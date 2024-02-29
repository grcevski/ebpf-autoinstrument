package httpfltr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/http_sock.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_TRACEPARENT
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_debug ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_DEBUG -DBPF_TRACEPARENT

type Tracer struct {
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *beyla.Config
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
	Service    *svc.ID
	qdiscs     []*netlink.GenericQdisc
	egress     []*netlink.BpfFilter
}

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "httpfltr.Tracer")
	return &Tracer{
		log:        log,
		cfg:        cfg,
		metrics:    metrics,
		pidsFilter: ebpfcommon.CommonPIDsFilter(cfg.Discovery.SystemWide),
	}
}

func (p *Tracer) AllowPID(pid uint32, svc svc.ID) {
	if p.bpfObjects.ValidPids != nil {
		nsid, err := ebpfcommon.FindNamespace(int32(pid))
		ebpfcommon.ActiveNamespaces[pid] = nsid
		if err == nil {
			err = p.bpfObjects.ValidPids.Put(bpfPidKeyT{Pid: pid, Ns: nsid}, uint8(1))
			if err != nil {
				p.log.Error("Error setting up pid in BPF space", "error", err)
			}
			// This is requied to ensure everything works when Beyla is running in pid=host mode.
			// In host mode, Beyla will find the host pid, while the bpf code matches the user pid.
			// Therefore we find all namespaced pids for the current pid we discovered and allow those too.
			otherPids, err := ebpfcommon.FindNamespacedPids(int32(pid))
			if err != nil {
				p.log.Error("Error finding namespaced pids", "error", err)
			}
			p.log.Debug("Found namespaced pids (will contain the existing pid too)", "pids", otherPids)
			for _, op := range otherPids {
				err = p.bpfObjects.ValidPids.Put(bpfPidKeyT{Pid: op, Ns: nsid}, uint8(1))
				if err != nil {
					p.log.Error("Error setting up pid in BPF space", "error", err)
				}
			}
		} else {
			p.log.Error("Error looking up namespace", "error", err)
		}
	}
	p.pidsFilter.AllowPID(pid, svc, ebpfcommon.PIDTypeKProbes)
}

func (p *Tracer) BlockPID(pid uint32) {
	if p.bpfObjects.ValidPids != nil {
		ns, ok := ebpfcommon.ActiveNamespaces[pid]
		if ok {
			err := p.bpfObjects.ValidPids.Delete(bpfPidKeyT{Pid: pid, Ns: ns})
			if err != nil {
				p.log.Error("Error removing pid in BPF space", "error", err)
			}
		} else {
			p.log.Warn("Couldn't find active namespace", "pid", pid)
		}
	}
	delete(ebpfcommon.ActiveNamespaces, pid)
	p.pidsFilter.BlockPID(pid)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	if p.cfg.EBPF.TrackRequestHeaders {
		if ebpfcommon.SupportsEBPFLoops() {
			p.log.Info("Found Linux kernel later than 5.17, enabling trace information parsing")
			loader = loadBpf_tp
			if p.cfg.EBPF.BpfDebug {
				loader = loadBpf_tp_debug
			}
		}
	}

	return loader()
}

func (p *Tracer) Constants(_ *exec.FileInfo, _ *goexec.Offsets) map[string]any {
	m := make(map[string]any, 2)

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	// This must match httpssl.go, otherwise we get partial events in userspace.
	if !p.cfg.Discovery.SystemWide && !p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(1)
	} else {
		m["filter_pids"] = int32(0)
	}

	if p.cfg.EBPF.TrackRequestHeaders {
		m["capture_header_buffer"] = int32(1)
	} else {
		m["capture_header_buffer"] = int32(0)
	}

	return m
}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.FunctionPrograms {
	return map[string]ebpfcommon.FunctionPrograms{
		// Both sys accept probes use the same kretprobe.
		// We could tap into __sys_accept4, but we might be more prone to
		// issues with the internal kernel code changing.
		"sys_accept": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysAccept4,
		},
		"sys_accept4": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysAccept4,
		},
		"sock_alloc": {
			Required: true,
			End:      p.bpfObjects.KretprobeSockAlloc,
		},
		"tcp_rcv_established": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpRcvEstablished,
		},
		// Tracking of HTTP client calls, by tapping into connect
		"sys_connect": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysConnect,
		},
		"tcp_connect": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpConnect,
		},
		"tcp_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpSendmsg,
		},
		// Reading more than 160 bytes
		"tcp_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpRecvmsg,
			End:      p.bpfObjects.KretprobeTcpRecvmsg,
		},
		"sys_clone": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysClone,
		},
		"sys_clone3": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysClone,
		},
		"sys_exit": {
			Required: true,
			Start:    p.bpfObjects.KprobeSysExit,
		},
	}
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return []*ebpf.Program{p.bpfObjects.SocketHttpFilter}
}

func (p *Tracer) EgressTCFilter() *ebpf.Program {
	return p.bpfObjects.EgressHttp
}

func (p *Tracer) RecordInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
	return false
}

func (p *Tracer) AddEgressToClose(filter *netlink.BpfFilter, qdisc *netlink.GenericQdisc) {
	p.egress = append(p.egress, filter)
	p.qdiscs = append(p.qdiscs, qdisc)
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span) {
	// At this point we now have loaded the bpf objects, which means we should insert any
	// pids that are allowed into the bpf map
	if p.bpfObjects.ValidPids != nil {
		p.log.Debug("Reallowing pids")
		for nsid, pids := range p.pidsFilter.CurrentPIDs(ebpfcommon.PIDTypeKProbes) {
			for pid := range pids {
				// skip any pids that might've been added, but are not tracked by the kprobes
				p.log.Debug("Reallowing pid", "pid", pid, "namespace", nsid)
				err := p.bpfObjects.ValidPids.Put(bpfPidKeyT{Pid: pid, Ns: nsid}, uint8(1))
				if err != nil {
					if err != nil {
						p.log.Error("Error setting up pid in BPF space", "pid", pid, "namespace", nsid, "error", err)
					}
				}
			}
		}
	} else {
		p.log.Error("BPF Pids map is not created yet, this is a bug.")
	}

	defer p.deleteEgress()

	ebpfcommon.SharedRingbuf(
		&p.cfg.EBPF,
		p.pidsFilter,
		p.bpfObjects.Events,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
	fmt.Printf("WTF?\n")
}

func (p *Tracer) deleteEgress() {
	p.log.Info("Deleting....", "egress", len(p.egress), "qdisc", len(p.qdiscs))

	for _, ef := range p.egress {
		doIgnoreNoDev(netlink.FilterDel, netlink.Filter(ef))
	}
	p.egress = []*netlink.BpfFilter{}
	for _, qd := range p.qdiscs {
		doIgnoreNoDev(netlink.QdiscDel, netlink.Qdisc(qd))
	}
	p.qdiscs = []*netlink.GenericQdisc{}
}

func doIgnoreNoDev[T any](sysCall func(T) error, dev T) error {
	if err := sysCall(dev); err != nil {
		if errors.Is(err, unix.ENODEV) {
			fmt.Printf("can't delete. Ignore this error if other pods or interfaces "+
				" are also being deleted at this moment. For example, if you are undeploying "+
				" a FlowCollector or Deployment where this agent is part of %v\n",
				err)
		} else {
			return err
		}
	}
	return nil
}
