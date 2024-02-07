// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package goinst

import (
	"context"
	"io"
	"log/slog"
	"unsafe"

	"github.com/cilium/ebpf"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/go.c -- -I../../../../bpf/headers -I../../../../bpf -I../../../../bpf/go -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/go.c -- -I../../../../bpf/headers -I../../../../bpf -I../../../../bpf/go -DBPF_DEBUG -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp ../../../../bpf/go.c -- -I../../../../bpf/headers -I../../../../bpf -I../../../../bpf/go
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_debug ../../../../bpf/go.c -- -I../../../../bpf/headers -I../../../../bpf -I../../../../bpf/go -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_noloop ../../../../bpf/go.c -- -I../../../../bpf/headers -I../../../../bpf -I../../../../bpf/go -DPRE_LOOP
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_noloop_debug ../../../../bpf/go.c -- -I../../../../bpf/headers -I../../../../bpf -I../../../../bpf/go -DBPF_DEBUG -DPRE_LOOP

type Tracer struct {
	log        *slog.Logger
	pidsFilter *ebpfcommon.PIDsFilter
	cfg        *ebpfcommon.TracerConfig
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
}

func New(cfg *ebpfcommon.TracerConfig, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "go.Tracer")
	return &Tracer{
		log:        log,
		pidsFilter: ebpfcommon.NewPIDsFilter(log),
		cfg:        cfg,
		metrics:    metrics,
	}
}

func (p *Tracer) AllowPID(pid uint32, _ svc.ID) {
	p.pidsFilter.AllowPID(pid)
}

func (p *Tracer) BlockPID(pid uint32) {
	p.pidsFilter.BlockPID(pid)
}

func (p *Tracer) supportsContextPropagation() bool {
	return !ebpfcommon.IntegrityModeOverride && ebpfcommon.SupportsContextPropagation(p.log)
}

func (p *Tracer) Optional() bool {
	return false
}

func (p *Tracer) UsesPinnedMaps() bool {
	return false
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.BpfDebug {
		loader = loadBpf_debug
	}

	if p.supportsContextPropagation() {
		if ebpfcommon.SupportsEBPFLoops() {
			loader = loadBpf_tp
			if p.cfg.BpfDebug {
				loader = loadBpf_tp_debug
			}
		} else {
			loader = loadBpf_tp_noloop
			if p.cfg.BpfDebug {
				loader = loadBpf_tp_noloop_debug
			}
		}
	} else {
		p.log.Info("Kernel in lockdown mode, trace info propagation in HTTP headers is disabled.")
	}
	return loader()
}

func (p *Tracer) Constants(_ *exec.FileInfo, offsets *goexec.Offsets) map[string]any {
	// Set the field offsets and the logLevel for nethttp BPF program,
	// as well as some other configuration constants
	constants := map[string]any{
		"wakeup_data_bytes": uint32(p.cfg.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{})),
	}
	for _, s := range []string{
		// http
		"url_ptr_pos",
		"path_ptr_pos",
		"method_ptr_pos",
		"status_ptr_pos",
		"status_code_ptr_pos",
		"remoteaddr_ptr_pos",
		"host_ptr_pos",
		"content_length_ptr_pos",
		"resp_req_pos",
		"req_header_ptr_pos",
		"io_writer_buf_ptr_pos",
		"io_writer_n_pos",
		"io_writer_buf_ptr_pos",
		"io_writer_n_pos",
		"tcp_addr_port_ptr_pos",
		"tcp_addr_ip_ptr_pos",
		"c_rwc_pos",
		"pc_conn_pos",
		"rwc_conn_pos",
		"conn_fd_pos",
		"fd_laddr_pos",
		"fd_raddr_pos",
		// http2
		"rws_req_pos",
		"cc_next_stream_id_pos",
		"framer_w_pos",
		// grpc
		"grpc_stream_st_ptr_pos",
		"grpc_stream_method_ptr_pos",
		"grpc_status_s_pos",
		"grpc_status_code_ptr_pos",
		"grpc_st_remoteaddr_ptr_pos",
		"grpc_st_localaddr_ptr_pos",
		"tcp_addr_port_ptr_pos",
		"tcp_addr_ip_ptr_pos",
		"grpc_client_target_ptr_pos",
		"grpc_stream_ctx_ptr_pos",
		"value_context_val_ptr_pos",
		"http2_client_next_id_pos",
		"hpack_encoder_w_pos",
		"grpc_peer_localaddr_pos",
		"grpc_peer_addr_pos",
		"grpc_st_peer_ptr_pos",
	} {
		constants[s] = offsets.Field[s]
		if constants[s] == nil {
			constants[s] = uint64(0xffffffffffffffff)
		}
	}

	return constants
}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string]ebpfcommon.FunctionPrograms {
	m := map[string]ebpfcommon.FunctionPrograms{
		// HTTP
		"net/http.serverHandler.ServeHTTP": {
			Start: p.bpfObjects.UprobeServeHTTP,
		},
		"net/http.(*conn).readRequest": {
			End: p.bpfObjects.UprobeReadRequestReturns,
		},
		"net/http.(*response).WriteHeader": {
			Start: p.bpfObjects.UprobeWriteHeader,
		},
		"net/http.(*Transport).roundTrip": { // HTTP client, works with Client.Do as well as using the RoundTripper directly
			Start: p.bpfObjects.UprobeRoundTrip,
			End:   p.bpfObjects.UprobeRoundTripReturn,
		},
		"github.com/gin-gonic/gin.(*Engine).ServeHTTP": {
			Required: true,
			Start:    p.bpfObjects.UprobeServeHTTP,
		},
		// HTTP 2.0
		"golang.org/x/net/http2.(*ClientConn).RoundTrip": { // http2 client
			Start: p.bpfObjects.UprobeHttp2RoundTrip,
			End:   p.bpfObjects.UprobeRoundTripReturn, // return is the same as for http 1.1
		},
		"golang.org/x/net/http2.(*responseWriterState).writeHeader": { // http2 server request done, capture the response code
			Start: p.bpfObjects.UprobeHttp2ResponseWriterStateWriteHeader,
		},
		// GRPC
		"google.golang.org/grpc.(*Server).handleStream": {
			Required: true,
			Start:    p.bpfObjects.UprobeServerHandleStream,
			End:      p.bpfObjects.UprobeServerHandleStreamReturn,
		},
		"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus": {
			Required: true,
			Start:    p.bpfObjects.UprobeTransportWriteStatus,
		},
		"google.golang.org/grpc.(*ClientConn).Invoke": {
			Required: true,
			Start:    p.bpfObjects.UprobeClientConnInvoke,
		},
		"google.golang.org/grpc.(*ClientConn).NewStream": {
			Required: true,
			Start:    p.bpfObjects.UprobeClientConnNewStream,
		},
		"google.golang.org/grpc.(*ClientConn).Close": {
			Required: true,
			Start:    p.bpfObjects.UprobeClientConnClose,
		},
		"google.golang.org/grpc.(*clientStream).RecvMsg": {
			End: p.bpfObjects.UprobeClientConnInvokeReturn,
		},
		"google.golang.org/grpc.(*clientStream).CloseSend": {
			End: p.bpfObjects.UprobeClientConnInvokeReturn,
		},
		// SQL
		"database/sql.(*DB).queryDC": {
			Start: p.bpfObjects.UprobeQueryDC,
			End:   p.bpfObjects.UprobeQueryDCReturn,
		},
		// Runtime
		"runtime.newproc1": {
			Start: p.bpfObjects.UprobeProcNewproc1,
			End:   p.bpfObjects.UprobeProcNewproc1Ret,
		},
		"runtime.goexit1": {
			Start: p.bpfObjects.UprobeProcGoexit1,
		},
	}

	if p.supportsContextPropagation() {
		m["net/http.Header.writeSubset"] = ebpfcommon.FunctionPrograms{
			Start: p.bpfObjects.UprobeWriteSubset, // http 1.x context propagation
		}
		m["golang.org/x/net/http2.(*Framer).WriteHeaders"] = ebpfcommon.FunctionPrograms{ // http2 context propagation
			Start: p.bpfObjects.UprobeHttp2FramerWriteHeaders,
			End:   p.bpfObjects.UprobeHttp2FramerWriteHeadersReturns,
		}

		if ebpfcommon.SupportsEBPFLoops() {
			m["golang.org/x/net/http2/hpack.(*Encoder).WriteField"] = ebpfcommon.FunctionPrograms{
				Required: true,
				Start:    p.bpfObjects.UprobeHpackEncoderWriteField,
			}
			m["google.golang.org/grpc/internal/transport.(*http2Client).NewStream"] = ebpfcommon.FunctionPrograms{
				Required: true,
				Start:    p.bpfObjects.UprobeTransportHttp2ClientNewStream,
			}
			m["google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader"] = ebpfcommon.FunctionPrograms{
				Required: true,
				Start:    p.bpfObjects.UprobeTransportLoopyWriterWriteHeader,
				End:      p.bpfObjects.UprobeTransportLoopyWriterWriteHeaderReturn,
			}
		}
	}

	return m
}

func (p *Tracer) KProbes() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span, service svc.ID) {
	ebpfcommon.ForwardRingbuf[ebpfcommon.HTTPRequestTrace](
		service,
		p.cfg, p.log, p.bpfObjects.Events,
		ebpfcommon.ReadHTTPRequestTraceAsSpan,
		p.pidsFilter.Filter,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}
