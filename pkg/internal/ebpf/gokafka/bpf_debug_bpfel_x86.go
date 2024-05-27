// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package gokafka

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
	UprobeSaramaEncode                *ebpf.ProgramSpec `ebpf:"uprobe_sarama_encode"`
	UprobeSaramaEncodeRet             *ebpf.ProgramSpec `ebpf:"uprobe_sarama_encode_ret"`
	UprobeSaramaResponsePromiseHandle *ebpf.ProgramSpec `ebpf:"uprobe_sarama_response_promise_handle"`
	UprobeSaramaSendInternal          *ebpf.ProgramSpec `ebpf:"uprobe_sarama_sendInternal"`
}

// bpf_debugMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_debugMapSpecs struct {
	Events                    *ebpf.MapSpec `ebpf:"events"`
	GoTraceMap                *ebpf.MapSpec `ebpf:"go_trace_map"`
	GolangMapbucketStorageMap *ebpf.MapSpec `ebpf:"golang_mapbucket_storage_map"`
	OngoingClientConnections  *ebpf.MapSpec `ebpf:"ongoing_client_connections"`
	OngoingGoroutines         *ebpf.MapSpec `ebpf:"ongoing_goroutines"`
	OngoingServerConnections  *ebpf.MapSpec `ebpf:"ongoing_server_connections"`
	TraceMap                  *ebpf.MapSpec `ebpf:"trace_map"`
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
	Events                    *ebpf.Map `ebpf:"events"`
	GoTraceMap                *ebpf.Map `ebpf:"go_trace_map"`
	GolangMapbucketStorageMap *ebpf.Map `ebpf:"golang_mapbucket_storage_map"`
	OngoingClientConnections  *ebpf.Map `ebpf:"ongoing_client_connections"`
	OngoingGoroutines         *ebpf.Map `ebpf:"ongoing_goroutines"`
	OngoingServerConnections  *ebpf.Map `ebpf:"ongoing_server_connections"`
	TraceMap                  *ebpf.Map `ebpf:"trace_map"`
}

func (m *bpf_debugMaps) Close() error {
	return _Bpf_debugClose(
		m.Events,
		m.GoTraceMap,
		m.GolangMapbucketStorageMap,
		m.OngoingClientConnections,
		m.OngoingGoroutines,
		m.OngoingServerConnections,
		m.TraceMap,
	)
}

// bpf_debugPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpf_debugObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_debugPrograms struct {
	UprobeSaramaEncode                *ebpf.Program `ebpf:"uprobe_sarama_encode"`
	UprobeSaramaEncodeRet             *ebpf.Program `ebpf:"uprobe_sarama_encode_ret"`
	UprobeSaramaResponsePromiseHandle *ebpf.Program `ebpf:"uprobe_sarama_response_promise_handle"`
	UprobeSaramaSendInternal          *ebpf.Program `ebpf:"uprobe_sarama_sendInternal"`
}

func (p *bpf_debugPrograms) Close() error {
	return _Bpf_debugClose(
		p.UprobeSaramaEncode,
		p.UprobeSaramaEncodeRet,
		p.UprobeSaramaResponsePromiseHandle,
		p.UprobeSaramaSendInternal,
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
