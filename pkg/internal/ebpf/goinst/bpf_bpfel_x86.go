// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package goinst

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfConnectionInfoT struct {
	S_addr [16]uint8
	D_addr [16]uint8
	S_port uint16
	D_port uint16
}

type bpfGoroutineMetadata struct {
	Parent    uint64
	Timestamp uint64
}

type bpfGrpcClientFuncInvocationT struct {
	StartMonotimeNs uint64
	Cc              uint64
	Method          uint64
	MethodLen       uint64
	Tp              bpfTpInfoT
	Flags           uint64
}

type bpfGrpcSrvFuncInvocationT struct {
	StartMonotimeNs uint64
	Stream          uint64
	Tp              bpfTpInfoT
}

type bpfHttpFuncInvocationT struct {
	StartMonotimeNs uint64
	ReqPtr          uint64
	Tp              bpfTpInfoT
}

type bpfNewFuncInvocationT struct{ Parent uint64 }

type bpfSqlFuncInvocationT struct {
	StartMonotimeNs uint64
	SqlParam        uint64
	QueryLen        uint64
	Tp              bpfTpInfoT
}

type bpfTpInfoT struct {
	TraceId  [16]uint8
	SpanId   [8]uint8
	ParentId [8]uint8
	Ts       uint64
	Flags    uint8
	_        [7]byte
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	HttpServeHTTP_start                         *ebpf.ProgramSpec `ebpf:"http_ServeHTTP_start"`
	UprobeClientConnClose                       *ebpf.ProgramSpec `ebpf:"uprobe_ClientConn_Close"`
	UprobeClientConnInvoke                      *ebpf.ProgramSpec `ebpf:"uprobe_ClientConn_Invoke"`
	UprobeClientConnInvokeReturn                *ebpf.ProgramSpec `ebpf:"uprobe_ClientConn_Invoke_return"`
	UprobeClientConnNewStream                   *ebpf.ProgramSpec `ebpf:"uprobe_ClientConn_NewStream"`
	UprobeServeHTTP                             *ebpf.ProgramSpec `ebpf:"uprobe_ServeHTTP"`
	UprobeWriteHeader                           *ebpf.ProgramSpec `ebpf:"uprobe_WriteHeader"`
	UprobeHpackEncoderWriteField                *ebpf.ProgramSpec `ebpf:"uprobe_hpack_Encoder_WriteField"`
	UprobeHttp2FramerWriteHeaders               *ebpf.ProgramSpec `ebpf:"uprobe_http2FramerWriteHeaders"`
	UprobeHttp2FramerWriteHeadersReturns        *ebpf.ProgramSpec `ebpf:"uprobe_http2FramerWriteHeaders_returns"`
	UprobeHttp2ResponseWriterStateWriteHeader   *ebpf.ProgramSpec `ebpf:"uprobe_http2ResponseWriterStateWriteHeader"`
	UprobeHttp2RoundTrip                        *ebpf.ProgramSpec `ebpf:"uprobe_http2RoundTrip"`
	UprobeProcGoexit1                           *ebpf.ProgramSpec `ebpf:"uprobe_proc_goexit1"`
	UprobeProcNewproc1                          *ebpf.ProgramSpec `ebpf:"uprobe_proc_newproc1"`
	UprobeProcNewproc1Ret                       *ebpf.ProgramSpec `ebpf:"uprobe_proc_newproc1_ret"`
	UprobeQueryDC                               *ebpf.ProgramSpec `ebpf:"uprobe_queryDC"`
	UprobeQueryDCReturn                         *ebpf.ProgramSpec `ebpf:"uprobe_queryDCReturn"`
	UprobeReadRequestReturns                    *ebpf.ProgramSpec `ebpf:"uprobe_readRequestReturns"`
	UprobeRoundTrip                             *ebpf.ProgramSpec `ebpf:"uprobe_roundTrip"`
	UprobeRoundTripReturn                       *ebpf.ProgramSpec `ebpf:"uprobe_roundTripReturn"`
	UprobeServerHandleStream                    *ebpf.ProgramSpec `ebpf:"uprobe_server_handleStream"`
	UprobeServerHandleStreamReturn              *ebpf.ProgramSpec `ebpf:"uprobe_server_handleStream_return"`
	UprobeTransportHttp2ClientNewStream         *ebpf.ProgramSpec `ebpf:"uprobe_transport_http2Client_NewStream"`
	UprobeTransportLoopyWriterWriteHeader       *ebpf.ProgramSpec `ebpf:"uprobe_transport_loopyWriter_writeHeader"`
	UprobeTransportLoopyWriterWriteHeaderReturn *ebpf.ProgramSpec `ebpf:"uprobe_transport_loopyWriter_writeHeader_return"`
	UprobeTransportWriteStatus                  *ebpf.ProgramSpec `ebpf:"uprobe_transport_writeStatus"`
	UprobeWriteSubset                           *ebpf.ProgramSpec `ebpf:"uprobe_writeSubset"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Events                       *ebpf.MapSpec `ebpf:"events"`
	GoTraceMap                   *ebpf.MapSpec `ebpf:"go_trace_map"`
	GolangMapbucketStorageMap    *ebpf.MapSpec `ebpf:"golang_mapbucket_storage_map"`
	Newproc1                     *ebpf.MapSpec `ebpf:"newproc1"`
	OngoingGoroutines            *ebpf.MapSpec `ebpf:"ongoing_goroutines"`
	OngoingGrpcClientRequests    *ebpf.MapSpec `ebpf:"ongoing_grpc_client_requests"`
	OngoingGrpcHeaderWrites      *ebpf.MapSpec `ebpf:"ongoing_grpc_header_writes"`
	OngoingGrpcRequestStatus     *ebpf.MapSpec `ebpf:"ongoing_grpc_request_status"`
	OngoingGrpcServerRequests    *ebpf.MapSpec `ebpf:"ongoing_grpc_server_requests"`
	OngoingHttpClientRequests    *ebpf.MapSpec `ebpf:"ongoing_http_client_requests"`
	OngoingHttpServerConnections *ebpf.MapSpec `ebpf:"ongoing_http_server_connections"`
	OngoingHttpServerRequests    *ebpf.MapSpec `ebpf:"ongoing_http_server_requests"`
	OngoingSqlQueries            *ebpf.MapSpec `ebpf:"ongoing_sql_queries"`
	OngoingStreams               *ebpf.MapSpec `ebpf:"ongoing_streams"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Events                       *ebpf.Map `ebpf:"events"`
	GoTraceMap                   *ebpf.Map `ebpf:"go_trace_map"`
	GolangMapbucketStorageMap    *ebpf.Map `ebpf:"golang_mapbucket_storage_map"`
	Newproc1                     *ebpf.Map `ebpf:"newproc1"`
	OngoingGoroutines            *ebpf.Map `ebpf:"ongoing_goroutines"`
	OngoingGrpcClientRequests    *ebpf.Map `ebpf:"ongoing_grpc_client_requests"`
	OngoingGrpcHeaderWrites      *ebpf.Map `ebpf:"ongoing_grpc_header_writes"`
	OngoingGrpcRequestStatus     *ebpf.Map `ebpf:"ongoing_grpc_request_status"`
	OngoingGrpcServerRequests    *ebpf.Map `ebpf:"ongoing_grpc_server_requests"`
	OngoingHttpClientRequests    *ebpf.Map `ebpf:"ongoing_http_client_requests"`
	OngoingHttpServerConnections *ebpf.Map `ebpf:"ongoing_http_server_connections"`
	OngoingHttpServerRequests    *ebpf.Map `ebpf:"ongoing_http_server_requests"`
	OngoingSqlQueries            *ebpf.Map `ebpf:"ongoing_sql_queries"`
	OngoingStreams               *ebpf.Map `ebpf:"ongoing_streams"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Events,
		m.GoTraceMap,
		m.GolangMapbucketStorageMap,
		m.Newproc1,
		m.OngoingGoroutines,
		m.OngoingGrpcClientRequests,
		m.OngoingGrpcHeaderWrites,
		m.OngoingGrpcRequestStatus,
		m.OngoingGrpcServerRequests,
		m.OngoingHttpClientRequests,
		m.OngoingHttpServerConnections,
		m.OngoingHttpServerRequests,
		m.OngoingSqlQueries,
		m.OngoingStreams,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	HttpServeHTTP_start                         *ebpf.Program `ebpf:"http_ServeHTTP_start"`
	UprobeClientConnClose                       *ebpf.Program `ebpf:"uprobe_ClientConn_Close"`
	UprobeClientConnInvoke                      *ebpf.Program `ebpf:"uprobe_ClientConn_Invoke"`
	UprobeClientConnInvokeReturn                *ebpf.Program `ebpf:"uprobe_ClientConn_Invoke_return"`
	UprobeClientConnNewStream                   *ebpf.Program `ebpf:"uprobe_ClientConn_NewStream"`
	UprobeServeHTTP                             *ebpf.Program `ebpf:"uprobe_ServeHTTP"`
	UprobeWriteHeader                           *ebpf.Program `ebpf:"uprobe_WriteHeader"`
	UprobeHpackEncoderWriteField                *ebpf.Program `ebpf:"uprobe_hpack_Encoder_WriteField"`
	UprobeHttp2FramerWriteHeaders               *ebpf.Program `ebpf:"uprobe_http2FramerWriteHeaders"`
	UprobeHttp2FramerWriteHeadersReturns        *ebpf.Program `ebpf:"uprobe_http2FramerWriteHeaders_returns"`
	UprobeHttp2ResponseWriterStateWriteHeader   *ebpf.Program `ebpf:"uprobe_http2ResponseWriterStateWriteHeader"`
	UprobeHttp2RoundTrip                        *ebpf.Program `ebpf:"uprobe_http2RoundTrip"`
	UprobeProcGoexit1                           *ebpf.Program `ebpf:"uprobe_proc_goexit1"`
	UprobeProcNewproc1                          *ebpf.Program `ebpf:"uprobe_proc_newproc1"`
	UprobeProcNewproc1Ret                       *ebpf.Program `ebpf:"uprobe_proc_newproc1_ret"`
	UprobeQueryDC                               *ebpf.Program `ebpf:"uprobe_queryDC"`
	UprobeQueryDCReturn                         *ebpf.Program `ebpf:"uprobe_queryDCReturn"`
	UprobeReadRequestReturns                    *ebpf.Program `ebpf:"uprobe_readRequestReturns"`
	UprobeRoundTrip                             *ebpf.Program `ebpf:"uprobe_roundTrip"`
	UprobeRoundTripReturn                       *ebpf.Program `ebpf:"uprobe_roundTripReturn"`
	UprobeServerHandleStream                    *ebpf.Program `ebpf:"uprobe_server_handleStream"`
	UprobeServerHandleStreamReturn              *ebpf.Program `ebpf:"uprobe_server_handleStream_return"`
	UprobeTransportHttp2ClientNewStream         *ebpf.Program `ebpf:"uprobe_transport_http2Client_NewStream"`
	UprobeTransportLoopyWriterWriteHeader       *ebpf.Program `ebpf:"uprobe_transport_loopyWriter_writeHeader"`
	UprobeTransportLoopyWriterWriteHeaderReturn *ebpf.Program `ebpf:"uprobe_transport_loopyWriter_writeHeader_return"`
	UprobeTransportWriteStatus                  *ebpf.Program `ebpf:"uprobe_transport_writeStatus"`
	UprobeWriteSubset                           *ebpf.Program `ebpf:"uprobe_writeSubset"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.HttpServeHTTP_start,
		p.UprobeClientConnClose,
		p.UprobeClientConnInvoke,
		p.UprobeClientConnInvokeReturn,
		p.UprobeClientConnNewStream,
		p.UprobeServeHTTP,
		p.UprobeWriteHeader,
		p.UprobeHpackEncoderWriteField,
		p.UprobeHttp2FramerWriteHeaders,
		p.UprobeHttp2FramerWriteHeadersReturns,
		p.UprobeHttp2ResponseWriterStateWriteHeader,
		p.UprobeHttp2RoundTrip,
		p.UprobeProcGoexit1,
		p.UprobeProcNewproc1,
		p.UprobeProcNewproc1Ret,
		p.UprobeQueryDC,
		p.UprobeQueryDCReturn,
		p.UprobeReadRequestReturns,
		p.UprobeRoundTrip,
		p.UprobeRoundTripReturn,
		p.UprobeServerHandleStream,
		p.UprobeServerHandleStreamReturn,
		p.UprobeTransportHttp2ClientNewStream,
		p.UprobeTransportLoopyWriterWriteHeader,
		p.UprobeTransportLoopyWriterWriteHeaderReturn,
		p.UprobeTransportWriteStatus,
		p.UprobeWriteSubset,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel_x86.o
var _BpfBytes []byte
