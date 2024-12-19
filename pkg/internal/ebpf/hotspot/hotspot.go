package hotspot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/config"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/jvmtools/jvm"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 -type nmethod_event_t bpf ../../../../bpf/hotspot.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 -type nmethod_event_t bpf_debug ../../../../bpf/hotspot.c -- -I../../../../bpf/headers -DBPF_DEBUG

type BPFCompilationEvent bpfNmethodEventT

// Hold onto Linux inode numbers of files that are already instrumented, i.e libjvm.so
var instrumentedLibs = make(ebpfcommon.InstrumentedLibsT)
var libsMux sync.Mutex

type Tracer struct {
	cfg        *beyla.Config
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
}

func New(cfg *beyla.Config) *Tracer {
	log := slog.With("component", "hotspot.Tracer")
	return &Tracer{
		log: log,
		cfg: cfg,
	}
}

func (p *Tracer) AllowPID(pid uint32, _ uint32, _ *svc.Attrs) {
	out, err := jvm.Jattach(int(pid), []string{"jcmd", "VM.version"}, p.log)
	if err != nil {
		p.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		p.log.Error("error reading from scanner", "error", err)
	}
}

func (p *Tracer) BlockPID(uint32, uint32) {}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	if p.cfg.EBPF.BpfDebug {
		return loadBpf_debug()
	}

	return loadBpf()
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 2)

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	// This must match httpfltr.go, otherwise we get partial events in userspace.
	if !p.cfg.Discovery.SystemWide && !p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(1)
	} else {
		m["filter_pids"] = int32(0)
	}

	return m
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return map[string]map[string][]*ebpfcommon.ProbeDesc{
		"libjvm.so": {
			"_ZN9CodeCache6commitEP8CodeBlob": {{
				Required: false,
				Start:    p.bpfObjects.BeylaCodeCacheCommit,
			}},
		},
	}
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return nil
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return nil
}

func (p *Tracer) SetupTC() {}

func (p *Tracer) RecordInstrumentedLib(id uint64, closers []io.Closer) {
	libsMux.Lock()
	defer libsMux.Unlock()

	module := instrumentedLibs.AddRef(id)

	if len(closers) > 0 {
		module.AddClosers(closers)
	}

	p.log.Debug("Recorded instrumented Lib", "ino", id, "module", module)
}

func (p *Tracer) AddInstrumentedLibRef(id uint64) {
	p.RecordInstrumentedLib(id, nil)
}

func (p *Tracer) UnlinkInstrumentedLib(id uint64) {
	libsMux.Lock()
	defer libsMux.Unlock()

	module, err := instrumentedLibs.RemoveRef(id)

	p.log.Debug("Unlinking instrumented lib - before state", "ino", id, "module", module)

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "ino", id, "error", err)
	}
}

func (p *Tracer) AlreadyInstrumentedLib(id uint64) bool {
	libsMux.Lock()
	defer libsMux.Unlock()

	module := instrumentedLibs.Find(id)

	p.log.Debug("checking already instrumented Lib", "ino", id, "module", module)
	return module != nil
}

func (p *Tracer) Run(ctx context.Context, _ chan<- []request.Span) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.CompilationEvents,
		&ebpfcommon.IdentityPidsFilter{},
		p.processLogEvent,
		p.log,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)
}

func (p *Tracer) processLogEvent(_ *config.EPPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	var event BPFCompilationEvent

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)

	if err == nil {
		p.log.Info(
			readString(event.Klass[:])+"."+readString(event.Name[:])+readString(event.Signature[:]),
			"code address", event.CodeStart, "code size", event.Size,
			"pid", event.Pid.HostPid)
	}

	return request.Span{}, true, nil
}

func readString(data []int8) string {
	bytes := make([]byte, len(data))
	for i, v := range data {
		if v == 0 { // null-terminated string
			bytes = bytes[:i]
			break
		}
		bytes[i] = byte(v)
	}
	return string(bytes)
}
