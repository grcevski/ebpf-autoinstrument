// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package gotracer

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

type bpf_debugGoroutineKeyT struct {
	Pid  uint64
	Addr uint64
}

type bpf_debugGoroutineMetadata struct {
	Parent    bpf_debugGoroutineKeyT
	Timestamp uint64
}

type bpf_debugGrpcClientFuncInvocationT struct {
	StartMonotimeNs uint64
	Cc              uint64
	Method          uint64
	MethodLen       uint64
	Tp              bpf_debugTpInfoT
	Flags           uint64
}

type bpf_debugGrpcSrvFuncInvocationT struct {
	StartMonotimeNs uint64
	Stream          uint64
	Tp              bpf_debugTpInfoT
}

type bpf_debugGrpcTransportsT struct {
	Type uint8
	_    [1]byte
	Conn bpf_debugConnectionInfoT
}

type bpf_debugHttpClientDataT struct {
	Method        [7]uint8
	Path          [100]uint8
	_             [5]byte
	ContentLength int64
	Pid           struct {
		HostPid uint32
		UserPid uint32
		Ns      uint32
	}
	_ [4]byte
}

type bpf_debugHttpFuncInvocationT struct {
	StartMonotimeNs uint64
	Tp              bpf_debugTpInfoT
}

type bpf_debugKafkaClientReqT struct {
	Type            uint8
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Buf             [256]uint8
	_               [7]byte
	Conn            bpf_debugConnectionInfoT
	Pid             struct {
		HostPid uint32
		UserPid uint32
		Ns      uint32
	}
}

type bpf_debugKafkaGoReqT struct {
	Type            uint8
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Topic           [64]uint8
	_               [7]byte
	Conn            bpf_debugConnectionInfoT
	Tp              bpf_debugTpInfoT
	Pid             struct {
		HostPid uint32
		UserPid uint32
		Ns      uint32
	}
	Op uint8
	_  [7]byte
}

type bpf_debugNewFuncInvocationT struct{ Parent uint64 }

type bpf_debugOffTableT struct{ Table [43]uint64 }

type bpf_debugProduceReqT struct {
	MsgPtr          uint64
	ConnPtr         uint64
	StartMonotimeNs uint64
}

type bpf_debugRedisClientReqT struct {
	Type            uint8
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Buf             [256]uint8
	_               [7]byte
	Conn            bpf_debugConnectionInfoT
	_               [4]byte
	Tp              bpf_debugTpInfoT
	Pid             struct {
		HostPid uint32
		UserPid uint32
		Ns      uint32
	}
	Err uint8
	_   [3]byte
}

type bpf_debugServerHttpFuncInvocationT struct {
	StartMonotimeNs uint64
	Tp              bpf_debugTpInfoT
	Method          [7]uint8
	Path            [100]uint8
	_               [5]byte
	ContentLength   uint64
	Status          uint64
}

type bpf_debugSqlFuncInvocationT struct {
	StartMonotimeNs uint64
	SqlParam        uint64
	QueryLen        uint64
	Tp              bpf_debugTpInfoT
}

type bpf_debugTopicT struct {
	Name [64]int8
	Tp   bpf_debugTpInfoT
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
	UprobeClientConnClose                     *ebpf.ProgramSpec `ebpf:"uprobe_ClientConn_Close"`
	UprobeClientConnInvoke                    *ebpf.ProgramSpec `ebpf:"uprobe_ClientConn_Invoke"`
	UprobeClientConnInvokeReturn              *ebpf.ProgramSpec `ebpf:"uprobe_ClientConn_Invoke_return"`
	UprobeClientConnNewStream                 *ebpf.ProgramSpec `ebpf:"uprobe_ClientConn_NewStream"`
	UprobeClientConnNewStreamReturn           *ebpf.ProgramSpec `ebpf:"uprobe_ClientConn_NewStream_return"`
	UprobeServeHTTP                           *ebpf.ProgramSpec `ebpf:"uprobe_ServeHTTP"`
	UprobeServeHTTPReturns                    *ebpf.ProgramSpec `ebpf:"uprobe_ServeHTTPReturns"`
	UprobeClientStreamRecvMsgReturn           *ebpf.ProgramSpec `ebpf:"uprobe_clientStream_RecvMsg_return"`
	UprobeClientRoundTrip                     *ebpf.ProgramSpec `ebpf:"uprobe_client_roundTrip"`
	UprobeConnServe                           *ebpf.ProgramSpec `ebpf:"uprobe_connServe"`
	UprobeConnServeRet                        *ebpf.ProgramSpec `ebpf:"uprobe_connServeRet"`
	UprobeExecDC                              *ebpf.ProgramSpec `ebpf:"uprobe_execDC"`
	UprobeGrpcFramerWriteHeaders              *ebpf.ProgramSpec `ebpf:"uprobe_grpcFramerWriteHeaders"`
	UprobeGrpcFramerWriteHeadersReturns       *ebpf.ProgramSpec `ebpf:"uprobe_grpcFramerWriteHeaders_returns"`
	UprobeHttp2FramerWriteHeaders             *ebpf.ProgramSpec `ebpf:"uprobe_http2FramerWriteHeaders"`
	UprobeHttp2FramerWriteHeadersReturns      *ebpf.ProgramSpec `ebpf:"uprobe_http2FramerWriteHeaders_returns"`
	UprobeHttp2ResponseWriterStateWriteHeader *ebpf.ProgramSpec `ebpf:"uprobe_http2ResponseWriterStateWriteHeader"`
	UprobeHttp2RoundTrip                      *ebpf.ProgramSpec `ebpf:"uprobe_http2RoundTrip"`
	UprobeHttp2ServerOperateHeaders           *ebpf.ProgramSpec `ebpf:"uprobe_http2Server_operateHeaders"`
	UprobeHttp2serverConnRunHandler           *ebpf.ProgramSpec `ebpf:"uprobe_http2serverConn_runHandler"`
	UprobeNetFdRead                           *ebpf.ProgramSpec `ebpf:"uprobe_netFdRead"`
	UprobeNetFdReadGRPC                       *ebpf.ProgramSpec `ebpf:"uprobe_netFdReadGRPC"`
	UprobePersistConnRoundTrip                *ebpf.ProgramSpec `ebpf:"uprobe_persistConnRoundTrip"`
	UprobeProcGoexit1                         *ebpf.ProgramSpec `ebpf:"uprobe_proc_goexit1"`
	UprobeProcNewproc1                        *ebpf.ProgramSpec `ebpf:"uprobe_proc_newproc1"`
	UprobeProcNewproc1Ret                     *ebpf.ProgramSpec `ebpf:"uprobe_proc_newproc1_ret"`
	UprobeProtocolRoundtrip                   *ebpf.ProgramSpec `ebpf:"uprobe_protocol_roundtrip"`
	UprobeProtocolRoundtripRet                *ebpf.ProgramSpec `ebpf:"uprobe_protocol_roundtrip_ret"`
	UprobeQueryDC                             *ebpf.ProgramSpec `ebpf:"uprobe_queryDC"`
	UprobeQueryReturn                         *ebpf.ProgramSpec `ebpf:"uprobe_queryReturn"`
	UprobeReadRequestReturns                  *ebpf.ProgramSpec `ebpf:"uprobe_readRequestReturns"`
	UprobeReadRequestStart                    *ebpf.ProgramSpec `ebpf:"uprobe_readRequestStart"`
	UprobeReaderRead                          *ebpf.ProgramSpec `ebpf:"uprobe_reader_read"`
	UprobeReaderReadRet                       *ebpf.ProgramSpec `ebpf:"uprobe_reader_read_ret"`
	UprobeReaderSendMessage                   *ebpf.ProgramSpec `ebpf:"uprobe_reader_send_message"`
	UprobeRedisProcess                        *ebpf.ProgramSpec `ebpf:"uprobe_redis_process"`
	UprobeRedisProcessRet                     *ebpf.ProgramSpec `ebpf:"uprobe_redis_process_ret"`
	UprobeRedisWithWriter                     *ebpf.ProgramSpec `ebpf:"uprobe_redis_with_writer"`
	UprobeRedisWithWriterRet                  *ebpf.ProgramSpec `ebpf:"uprobe_redis_with_writer_ret"`
	UprobeRoundTrip                           *ebpf.ProgramSpec `ebpf:"uprobe_roundTrip"`
	UprobeRoundTripReturn                     *ebpf.ProgramSpec `ebpf:"uprobe_roundTripReturn"`
	UprobeSaramaBrokerWrite                   *ebpf.ProgramSpec `ebpf:"uprobe_sarama_broker_write"`
	UprobeSaramaResponsePromiseHandle         *ebpf.ProgramSpec `ebpf:"uprobe_sarama_response_promise_handle"`
	UprobeSaramaSendInternal                  *ebpf.ProgramSpec `ebpf:"uprobe_sarama_sendInternal"`
	UprobeServerHandleStream                  *ebpf.ProgramSpec `ebpf:"uprobe_server_handleStream"`
	UprobeServerHandleStreamReturn            *ebpf.ProgramSpec `ebpf:"uprobe_server_handleStream_return"`
	UprobeServerHandlerTransportHandleStreams *ebpf.ProgramSpec `ebpf:"uprobe_server_handler_transport_handle_streams"`
	UprobeTransportHttp2ClientNewStream       *ebpf.ProgramSpec `ebpf:"uprobe_transport_http2Client_NewStream"`
	UprobeTransportWriteStatus                *ebpf.ProgramSpec `ebpf:"uprobe_transport_writeStatus"`
	UprobeWriteSubset                         *ebpf.ProgramSpec `ebpf:"uprobe_writeSubset"`
	UprobeWriterProduce                       *ebpf.ProgramSpec `ebpf:"uprobe_writer_produce"`
	UprobeWriterWriteMessages                 *ebpf.ProgramSpec `ebpf:"uprobe_writer_write_messages"`
}

// bpf_debugMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_debugMapSpecs struct {
	DebugEvents                   *ebpf.MapSpec `ebpf:"debug_events"`
	Events                        *ebpf.MapSpec `ebpf:"events"`
	FetchRequests                 *ebpf.MapSpec `ebpf:"fetch_requests"`
	GoOffsetsMap                  *ebpf.MapSpec `ebpf:"go_offsets_map"`
	GoTraceMap                    *ebpf.MapSpec `ebpf:"go_trace_map"`
	GolangMapbucketStorageMap     *ebpf.MapSpec `ebpf:"golang_mapbucket_storage_map"`
	IncomingTraceMap              *ebpf.MapSpec `ebpf:"incoming_trace_map"`
	KafkaRequests                 *ebpf.MapSpec `ebpf:"kafka_requests"`
	Newproc1                      *ebpf.MapSpec `ebpf:"newproc1"`
	OngoingClientConnections      *ebpf.MapSpec `ebpf:"ongoing_client_connections"`
	OngoingGoroutines             *ebpf.MapSpec `ebpf:"ongoing_goroutines"`
	OngoingGrpcClientRequests     *ebpf.MapSpec `ebpf:"ongoing_grpc_client_requests"`
	OngoingGrpcHeaderWrites       *ebpf.MapSpec `ebpf:"ongoing_grpc_header_writes"`
	OngoingGrpcOperateHeaders     *ebpf.MapSpec `ebpf:"ongoing_grpc_operate_headers"`
	OngoingGrpcRequestStatus      *ebpf.MapSpec `ebpf:"ongoing_grpc_request_status"`
	OngoingGrpcServerRequests     *ebpf.MapSpec `ebpf:"ongoing_grpc_server_requests"`
	OngoingGrpcTransports         *ebpf.MapSpec `ebpf:"ongoing_grpc_transports"`
	OngoingHttpClientRequests     *ebpf.MapSpec `ebpf:"ongoing_http_client_requests"`
	OngoingHttpClientRequestsData *ebpf.MapSpec `ebpf:"ongoing_http_client_requests_data"`
	OngoingHttpServerRequests     *ebpf.MapSpec `ebpf:"ongoing_http_server_requests"`
	OngoingKafkaRequests          *ebpf.MapSpec `ebpf:"ongoing_kafka_requests"`
	OngoingProduceMessages        *ebpf.MapSpec `ebpf:"ongoing_produce_messages"`
	OngoingProduceTopics          *ebpf.MapSpec `ebpf:"ongoing_produce_topics"`
	OngoingRedisRequests          *ebpf.MapSpec `ebpf:"ongoing_redis_requests"`
	OngoingServerConnections      *ebpf.MapSpec `ebpf:"ongoing_server_connections"`
	OngoingSqlQueries             *ebpf.MapSpec `ebpf:"ongoing_sql_queries"`
	OngoingStreams                *ebpf.MapSpec `ebpf:"ongoing_streams"`
	OutgoingTraceMap              *ebpf.MapSpec `ebpf:"outgoing_trace_map"`
	ProduceRequests               *ebpf.MapSpec `ebpf:"produce_requests"`
	ProduceTraceparents           *ebpf.MapSpec `ebpf:"produce_traceparents"`
	RedisWrites                   *ebpf.MapSpec `ebpf:"redis_writes"`
	TraceMap                      *ebpf.MapSpec `ebpf:"trace_map"`
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
	DebugEvents                   *ebpf.Map `ebpf:"debug_events"`
	Events                        *ebpf.Map `ebpf:"events"`
	FetchRequests                 *ebpf.Map `ebpf:"fetch_requests"`
	GoOffsetsMap                  *ebpf.Map `ebpf:"go_offsets_map"`
	GoTraceMap                    *ebpf.Map `ebpf:"go_trace_map"`
	GolangMapbucketStorageMap     *ebpf.Map `ebpf:"golang_mapbucket_storage_map"`
	IncomingTraceMap              *ebpf.Map `ebpf:"incoming_trace_map"`
	KafkaRequests                 *ebpf.Map `ebpf:"kafka_requests"`
	Newproc1                      *ebpf.Map `ebpf:"newproc1"`
	OngoingClientConnections      *ebpf.Map `ebpf:"ongoing_client_connections"`
	OngoingGoroutines             *ebpf.Map `ebpf:"ongoing_goroutines"`
	OngoingGrpcClientRequests     *ebpf.Map `ebpf:"ongoing_grpc_client_requests"`
	OngoingGrpcHeaderWrites       *ebpf.Map `ebpf:"ongoing_grpc_header_writes"`
	OngoingGrpcOperateHeaders     *ebpf.Map `ebpf:"ongoing_grpc_operate_headers"`
	OngoingGrpcRequestStatus      *ebpf.Map `ebpf:"ongoing_grpc_request_status"`
	OngoingGrpcServerRequests     *ebpf.Map `ebpf:"ongoing_grpc_server_requests"`
	OngoingGrpcTransports         *ebpf.Map `ebpf:"ongoing_grpc_transports"`
	OngoingHttpClientRequests     *ebpf.Map `ebpf:"ongoing_http_client_requests"`
	OngoingHttpClientRequestsData *ebpf.Map `ebpf:"ongoing_http_client_requests_data"`
	OngoingHttpServerRequests     *ebpf.Map `ebpf:"ongoing_http_server_requests"`
	OngoingKafkaRequests          *ebpf.Map `ebpf:"ongoing_kafka_requests"`
	OngoingProduceMessages        *ebpf.Map `ebpf:"ongoing_produce_messages"`
	OngoingProduceTopics          *ebpf.Map `ebpf:"ongoing_produce_topics"`
	OngoingRedisRequests          *ebpf.Map `ebpf:"ongoing_redis_requests"`
	OngoingServerConnections      *ebpf.Map `ebpf:"ongoing_server_connections"`
	OngoingSqlQueries             *ebpf.Map `ebpf:"ongoing_sql_queries"`
	OngoingStreams                *ebpf.Map `ebpf:"ongoing_streams"`
	OutgoingTraceMap              *ebpf.Map `ebpf:"outgoing_trace_map"`
	ProduceRequests               *ebpf.Map `ebpf:"produce_requests"`
	ProduceTraceparents           *ebpf.Map `ebpf:"produce_traceparents"`
	RedisWrites                   *ebpf.Map `ebpf:"redis_writes"`
	TraceMap                      *ebpf.Map `ebpf:"trace_map"`
}

func (m *bpf_debugMaps) Close() error {
	return _Bpf_debugClose(
		m.DebugEvents,
		m.Events,
		m.FetchRequests,
		m.GoOffsetsMap,
		m.GoTraceMap,
		m.GolangMapbucketStorageMap,
		m.IncomingTraceMap,
		m.KafkaRequests,
		m.Newproc1,
		m.OngoingClientConnections,
		m.OngoingGoroutines,
		m.OngoingGrpcClientRequests,
		m.OngoingGrpcHeaderWrites,
		m.OngoingGrpcOperateHeaders,
		m.OngoingGrpcRequestStatus,
		m.OngoingGrpcServerRequests,
		m.OngoingGrpcTransports,
		m.OngoingHttpClientRequests,
		m.OngoingHttpClientRequestsData,
		m.OngoingHttpServerRequests,
		m.OngoingKafkaRequests,
		m.OngoingProduceMessages,
		m.OngoingProduceTopics,
		m.OngoingRedisRequests,
		m.OngoingServerConnections,
		m.OngoingSqlQueries,
		m.OngoingStreams,
		m.OutgoingTraceMap,
		m.ProduceRequests,
		m.ProduceTraceparents,
		m.RedisWrites,
		m.TraceMap,
	)
}

// bpf_debugPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpf_debugObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_debugPrograms struct {
	UprobeClientConnClose                     *ebpf.Program `ebpf:"uprobe_ClientConn_Close"`
	UprobeClientConnInvoke                    *ebpf.Program `ebpf:"uprobe_ClientConn_Invoke"`
	UprobeClientConnInvokeReturn              *ebpf.Program `ebpf:"uprobe_ClientConn_Invoke_return"`
	UprobeClientConnNewStream                 *ebpf.Program `ebpf:"uprobe_ClientConn_NewStream"`
	UprobeClientConnNewStreamReturn           *ebpf.Program `ebpf:"uprobe_ClientConn_NewStream_return"`
	UprobeServeHTTP                           *ebpf.Program `ebpf:"uprobe_ServeHTTP"`
	UprobeServeHTTPReturns                    *ebpf.Program `ebpf:"uprobe_ServeHTTPReturns"`
	UprobeClientStreamRecvMsgReturn           *ebpf.Program `ebpf:"uprobe_clientStream_RecvMsg_return"`
	UprobeClientRoundTrip                     *ebpf.Program `ebpf:"uprobe_client_roundTrip"`
	UprobeConnServe                           *ebpf.Program `ebpf:"uprobe_connServe"`
	UprobeConnServeRet                        *ebpf.Program `ebpf:"uprobe_connServeRet"`
	UprobeExecDC                              *ebpf.Program `ebpf:"uprobe_execDC"`
	UprobeGrpcFramerWriteHeaders              *ebpf.Program `ebpf:"uprobe_grpcFramerWriteHeaders"`
	UprobeGrpcFramerWriteHeadersReturns       *ebpf.Program `ebpf:"uprobe_grpcFramerWriteHeaders_returns"`
	UprobeHttp2FramerWriteHeaders             *ebpf.Program `ebpf:"uprobe_http2FramerWriteHeaders"`
	UprobeHttp2FramerWriteHeadersReturns      *ebpf.Program `ebpf:"uprobe_http2FramerWriteHeaders_returns"`
	UprobeHttp2ResponseWriterStateWriteHeader *ebpf.Program `ebpf:"uprobe_http2ResponseWriterStateWriteHeader"`
	UprobeHttp2RoundTrip                      *ebpf.Program `ebpf:"uprobe_http2RoundTrip"`
	UprobeHttp2ServerOperateHeaders           *ebpf.Program `ebpf:"uprobe_http2Server_operateHeaders"`
	UprobeHttp2serverConnRunHandler           *ebpf.Program `ebpf:"uprobe_http2serverConn_runHandler"`
	UprobeNetFdRead                           *ebpf.Program `ebpf:"uprobe_netFdRead"`
	UprobeNetFdReadGRPC                       *ebpf.Program `ebpf:"uprobe_netFdReadGRPC"`
	UprobePersistConnRoundTrip                *ebpf.Program `ebpf:"uprobe_persistConnRoundTrip"`
	UprobeProcGoexit1                         *ebpf.Program `ebpf:"uprobe_proc_goexit1"`
	UprobeProcNewproc1                        *ebpf.Program `ebpf:"uprobe_proc_newproc1"`
	UprobeProcNewproc1Ret                     *ebpf.Program `ebpf:"uprobe_proc_newproc1_ret"`
	UprobeProtocolRoundtrip                   *ebpf.Program `ebpf:"uprobe_protocol_roundtrip"`
	UprobeProtocolRoundtripRet                *ebpf.Program `ebpf:"uprobe_protocol_roundtrip_ret"`
	UprobeQueryDC                             *ebpf.Program `ebpf:"uprobe_queryDC"`
	UprobeQueryReturn                         *ebpf.Program `ebpf:"uprobe_queryReturn"`
	UprobeReadRequestReturns                  *ebpf.Program `ebpf:"uprobe_readRequestReturns"`
	UprobeReadRequestStart                    *ebpf.Program `ebpf:"uprobe_readRequestStart"`
	UprobeReaderRead                          *ebpf.Program `ebpf:"uprobe_reader_read"`
	UprobeReaderReadRet                       *ebpf.Program `ebpf:"uprobe_reader_read_ret"`
	UprobeReaderSendMessage                   *ebpf.Program `ebpf:"uprobe_reader_send_message"`
	UprobeRedisProcess                        *ebpf.Program `ebpf:"uprobe_redis_process"`
	UprobeRedisProcessRet                     *ebpf.Program `ebpf:"uprobe_redis_process_ret"`
	UprobeRedisWithWriter                     *ebpf.Program `ebpf:"uprobe_redis_with_writer"`
	UprobeRedisWithWriterRet                  *ebpf.Program `ebpf:"uprobe_redis_with_writer_ret"`
	UprobeRoundTrip                           *ebpf.Program `ebpf:"uprobe_roundTrip"`
	UprobeRoundTripReturn                     *ebpf.Program `ebpf:"uprobe_roundTripReturn"`
	UprobeSaramaBrokerWrite                   *ebpf.Program `ebpf:"uprobe_sarama_broker_write"`
	UprobeSaramaResponsePromiseHandle         *ebpf.Program `ebpf:"uprobe_sarama_response_promise_handle"`
	UprobeSaramaSendInternal                  *ebpf.Program `ebpf:"uprobe_sarama_sendInternal"`
	UprobeServerHandleStream                  *ebpf.Program `ebpf:"uprobe_server_handleStream"`
	UprobeServerHandleStreamReturn            *ebpf.Program `ebpf:"uprobe_server_handleStream_return"`
	UprobeServerHandlerTransportHandleStreams *ebpf.Program `ebpf:"uprobe_server_handler_transport_handle_streams"`
	UprobeTransportHttp2ClientNewStream       *ebpf.Program `ebpf:"uprobe_transport_http2Client_NewStream"`
	UprobeTransportWriteStatus                *ebpf.Program `ebpf:"uprobe_transport_writeStatus"`
	UprobeWriteSubset                         *ebpf.Program `ebpf:"uprobe_writeSubset"`
	UprobeWriterProduce                       *ebpf.Program `ebpf:"uprobe_writer_produce"`
	UprobeWriterWriteMessages                 *ebpf.Program `ebpf:"uprobe_writer_write_messages"`
}

func (p *bpf_debugPrograms) Close() error {
	return _Bpf_debugClose(
		p.UprobeClientConnClose,
		p.UprobeClientConnInvoke,
		p.UprobeClientConnInvokeReturn,
		p.UprobeClientConnNewStream,
		p.UprobeClientConnNewStreamReturn,
		p.UprobeServeHTTP,
		p.UprobeServeHTTPReturns,
		p.UprobeClientStreamRecvMsgReturn,
		p.UprobeClientRoundTrip,
		p.UprobeConnServe,
		p.UprobeConnServeRet,
		p.UprobeExecDC,
		p.UprobeGrpcFramerWriteHeaders,
		p.UprobeGrpcFramerWriteHeadersReturns,
		p.UprobeHttp2FramerWriteHeaders,
		p.UprobeHttp2FramerWriteHeadersReturns,
		p.UprobeHttp2ResponseWriterStateWriteHeader,
		p.UprobeHttp2RoundTrip,
		p.UprobeHttp2ServerOperateHeaders,
		p.UprobeHttp2serverConnRunHandler,
		p.UprobeNetFdRead,
		p.UprobeNetFdReadGRPC,
		p.UprobePersistConnRoundTrip,
		p.UprobeProcGoexit1,
		p.UprobeProcNewproc1,
		p.UprobeProcNewproc1Ret,
		p.UprobeProtocolRoundtrip,
		p.UprobeProtocolRoundtripRet,
		p.UprobeQueryDC,
		p.UprobeQueryReturn,
		p.UprobeReadRequestReturns,
		p.UprobeReadRequestStart,
		p.UprobeReaderRead,
		p.UprobeReaderReadRet,
		p.UprobeReaderSendMessage,
		p.UprobeRedisProcess,
		p.UprobeRedisProcessRet,
		p.UprobeRedisWithWriter,
		p.UprobeRedisWithWriterRet,
		p.UprobeRoundTrip,
		p.UprobeRoundTripReturn,
		p.UprobeSaramaBrokerWrite,
		p.UprobeSaramaResponsePromiseHandle,
		p.UprobeSaramaSendInternal,
		p.UprobeServerHandleStream,
		p.UprobeServerHandleStreamReturn,
		p.UprobeServerHandlerTransportHandleStreams,
		p.UprobeTransportHttp2ClientNewStream,
		p.UprobeTransportWriteStatus,
		p.UprobeWriteSubset,
		p.UprobeWriterProduce,
		p.UprobeWriterWriteMessages,
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
//go:embed bpf_debug_x86_bpfel.o
var _Bpf_debugBytes []byte
