// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package nethttp

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpf_debugConnectionInfoT struct {
	S_addr [16]uint8
	D_addr [16]uint8
	S_port uint16
	D_port uint16
}

type bpf_debugGoroutineMetadata struct {
	Parent    uint64
	Timestamp uint64
}

type bpf_debugHttpConnectionMetadataT struct {
	Pid struct {
		HostPid   uint32
		UserPid   uint32
		Namespace uint32
	}
	Type uint8
}

type bpf_debugHttpFuncInvocationT struct {
	StartMonotimeNs uint64
	ReqPtr          uint64
	Tp              bpf_debugTpInfoT
}

type bpf_debugPidConnectionInfoT struct {
	Conn bpf_debugConnectionInfoT
	Pid  uint32
}

type bpf_debugPidKeyT struct {
	Pid       uint32
	Namespace uint32
}

type bpf_debugTpInfoPidT struct {
	Tp    bpf_debugTpInfoT
	Pid   uint32
	Valid uint8
	_     [3]byte
}

type bpf_debugTpInfoT struct {
	TraceId  [16]uint8
	SpanId   [8]uint8
	ParentId [8]uint8
	Ts       uint64
	Flags    uint8
	_        [7]byte
}

// loadBpf_debug returns the embedded CollectionSpec for bpf_debug.
func loadBpf_debug() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Bpf_debugBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf_debug: %w", err)
	}

	return spec, err
}

// loadBpf_debugObjects loads bpf_debug and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpf_debugObjects
//	*bpf_debugPrograms
//	*bpf_debugMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpf_debugObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf_debug()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpf_debugSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_debugSpecs struct {
	bpf_debugProgramSpecs
	bpf_debugMapSpecs
}

// bpf_debugSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_debugProgramSpecs struct {
	HttpServeHTTP_start                       *ebpf.ProgramSpec `ebpf:"http_ServeHTTP_start"`
	UprobeServeHTTP                           *ebpf.ProgramSpec `ebpf:"uprobe_ServeHTTP"`
	UprobeWriteHeader                         *ebpf.ProgramSpec `ebpf:"uprobe_WriteHeader"`
	UprobeConnServe                           *ebpf.ProgramSpec `ebpf:"uprobe_connServe"`
	UprobeConnServeRet                        *ebpf.ProgramSpec `ebpf:"uprobe_connServeRet"`
	UprobeHttp2FramerWriteHeaders             *ebpf.ProgramSpec `ebpf:"uprobe_http2FramerWriteHeaders"`
	UprobeHttp2FramerWriteHeadersReturns      *ebpf.ProgramSpec `ebpf:"uprobe_http2FramerWriteHeaders_returns"`
	UprobeHttp2ResponseWriterStateWriteHeader *ebpf.ProgramSpec `ebpf:"uprobe_http2ResponseWriterStateWriteHeader"`
	UprobeHttp2RoundTrip                      *ebpf.ProgramSpec `ebpf:"uprobe_http2RoundTrip"`
	UprobePersistConnRoundTrip                *ebpf.ProgramSpec `ebpf:"uprobe_persistConnRoundTrip"`
	UprobeReadRequestReturns                  *ebpf.ProgramSpec `ebpf:"uprobe_readRequestReturns"`
	UprobeRoundTrip                           *ebpf.ProgramSpec `ebpf:"uprobe_roundTrip"`
	UprobeRoundTripReturn                     *ebpf.ProgramSpec `ebpf:"uprobe_roundTripReturn"`
	UprobeWriteSubset                         *ebpf.ProgramSpec `ebpf:"uprobe_writeSubset"`
}

// bpf_debugMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_debugMapSpecs struct {
	Events                       *ebpf.MapSpec `ebpf:"events"`
	FilteredConnections          *ebpf.MapSpec `ebpf:"filtered_connections"`
	GoTraceMap                   *ebpf.MapSpec `ebpf:"go_trace_map"`
	GolangMapbucketStorageMap    *ebpf.MapSpec `ebpf:"golang_mapbucket_storage_map"`
	OngoingGoroutines            *ebpf.MapSpec `ebpf:"ongoing_goroutines"`
	OngoingHttpClientRequests    *ebpf.MapSpec `ebpf:"ongoing_http_client_requests"`
	OngoingHttpServerConnections *ebpf.MapSpec `ebpf:"ongoing_http_server_connections"`
	OngoingHttpServerRequests    *ebpf.MapSpec `ebpf:"ongoing_http_server_requests"`
	PidCache                     *ebpf.MapSpec `ebpf:"pid_cache"`
	TraceMap                     *ebpf.MapSpec `ebpf:"trace_map"`
	ValidPids                    *ebpf.MapSpec `ebpf:"valid_pids"`
}

// bpf_debugObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpf_debugObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_debugObjects struct {
	bpf_debugPrograms
	bpf_debugMaps
}

func (o *bpf_debugObjects) Close() error {
	return _Bpf_debugClose(
		&o.bpf_debugPrograms,
		&o.bpf_debugMaps,
	)
}

// bpf_debugMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpf_debugObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_debugMaps struct {
	Events                       *ebpf.Map `ebpf:"events"`
	FilteredConnections          *ebpf.Map `ebpf:"filtered_connections"`
	GoTraceMap                   *ebpf.Map `ebpf:"go_trace_map"`
	GolangMapbucketStorageMap    *ebpf.Map `ebpf:"golang_mapbucket_storage_map"`
	OngoingGoroutines            *ebpf.Map `ebpf:"ongoing_goroutines"`
	OngoingHttpClientRequests    *ebpf.Map `ebpf:"ongoing_http_client_requests"`
	OngoingHttpServerConnections *ebpf.Map `ebpf:"ongoing_http_server_connections"`
	OngoingHttpServerRequests    *ebpf.Map `ebpf:"ongoing_http_server_requests"`
	PidCache                     *ebpf.Map `ebpf:"pid_cache"`
	TraceMap                     *ebpf.Map `ebpf:"trace_map"`
	ValidPids                    *ebpf.Map `ebpf:"valid_pids"`
}

func (m *bpf_debugMaps) Close() error {
	return _Bpf_debugClose(
		m.Events,
		m.FilteredConnections,
		m.GoTraceMap,
		m.GolangMapbucketStorageMap,
		m.OngoingGoroutines,
		m.OngoingHttpClientRequests,
		m.OngoingHttpServerConnections,
		m.OngoingHttpServerRequests,
		m.PidCache,
		m.TraceMap,
		m.ValidPids,
	)
}

// bpf_debugPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpf_debugObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_debugPrograms struct {
	HttpServeHTTP_start                       *ebpf.Program `ebpf:"http_ServeHTTP_start"`
	UprobeServeHTTP                           *ebpf.Program `ebpf:"uprobe_ServeHTTP"`
	UprobeWriteHeader                         *ebpf.Program `ebpf:"uprobe_WriteHeader"`
	UprobeConnServe                           *ebpf.Program `ebpf:"uprobe_connServe"`
	UprobeConnServeRet                        *ebpf.Program `ebpf:"uprobe_connServeRet"`
	UprobeHttp2FramerWriteHeaders             *ebpf.Program `ebpf:"uprobe_http2FramerWriteHeaders"`
	UprobeHttp2FramerWriteHeadersReturns      *ebpf.Program `ebpf:"uprobe_http2FramerWriteHeaders_returns"`
	UprobeHttp2ResponseWriterStateWriteHeader *ebpf.Program `ebpf:"uprobe_http2ResponseWriterStateWriteHeader"`
	UprobeHttp2RoundTrip                      *ebpf.Program `ebpf:"uprobe_http2RoundTrip"`
	UprobePersistConnRoundTrip                *ebpf.Program `ebpf:"uprobe_persistConnRoundTrip"`
	UprobeReadRequestReturns                  *ebpf.Program `ebpf:"uprobe_readRequestReturns"`
	UprobeRoundTrip                           *ebpf.Program `ebpf:"uprobe_roundTrip"`
	UprobeRoundTripReturn                     *ebpf.Program `ebpf:"uprobe_roundTripReturn"`
	UprobeWriteSubset                         *ebpf.Program `ebpf:"uprobe_writeSubset"`
}

func (p *bpf_debugPrograms) Close() error {
	return _Bpf_debugClose(
		p.HttpServeHTTP_start,
		p.UprobeServeHTTP,
		p.UprobeWriteHeader,
		p.UprobeConnServe,
		p.UprobeConnServeRet,
		p.UprobeHttp2FramerWriteHeaders,
		p.UprobeHttp2FramerWriteHeadersReturns,
		p.UprobeHttp2ResponseWriterStateWriteHeader,
		p.UprobeHttp2RoundTrip,
		p.UprobePersistConnRoundTrip,
		p.UprobeReadRequestReturns,
		p.UprobeRoundTrip,
		p.UprobeRoundTripReturn,
		p.UprobeWriteSubset,
	)
}

func _Bpf_debugClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_debug_bpfel_x86.o
var _Bpf_debugBytes []byte
