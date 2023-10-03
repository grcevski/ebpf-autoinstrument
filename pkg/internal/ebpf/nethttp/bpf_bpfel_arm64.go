// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64
// +build arm64

package nethttp

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfFuncInvocation struct {
	StartMonotimeNs uint64
	Regs            struct {
		UserRegs struct {
			Regs   [31]uint64
			Sp     uint64
			Pc     uint64
			Pstate uint64
		}
		OrigX0          uint64
		Syscallno       int32
		Unused2         uint32
		OrigAddrLimit   uint64
		PmrSave         uint64
		Stackframe      [2]uint64
		LockdepHardirqs uint64
		ExitRcu         uint64
	}
}

type bpfGoroutineMetadata struct {
	Parent    uint64
	Timestamp uint64
}

type bpfTraceparentInfo struct {
	Traceparent [55]uint8
	Flags       uint8
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
	UprobeServeHTTP           *ebpf.ProgramSpec `ebpf:"uprobe_ServeHTTP"`
	UprobeWriteHeader         *ebpf.ProgramSpec `ebpf:"uprobe_WriteHeader"`
	UprobeRoundTrip           *ebpf.ProgramSpec `ebpf:"uprobe_roundTrip"`
	UprobeRoundTripReturn     *ebpf.ProgramSpec `ebpf:"uprobe_roundTripReturn"`
	UprobeStartBackgroundRead *ebpf.ProgramSpec `ebpf:"uprobe_startBackgroundRead"`
	UprobeWriteSubset         *ebpf.ProgramSpec `ebpf:"uprobe_writeSubset"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Events                    *ebpf.MapSpec `ebpf:"events"`
	GolangMapbucketStorageMap *ebpf.MapSpec `ebpf:"golang_mapbucket_storage_map"`
	HeaderReqMap              *ebpf.MapSpec `ebpf:"header_req_map"`
	Newproc1                  *ebpf.MapSpec `ebpf:"newproc1"`
	OngoingGoroutines         *ebpf.MapSpec `ebpf:"ongoing_goroutines"`
	OngoingHttpClientRequests *ebpf.MapSpec `ebpf:"ongoing_http_client_requests"`
	OngoingServerRequests     *ebpf.MapSpec `ebpf:"ongoing_server_requests"`
	TpInfos                   *ebpf.MapSpec `ebpf:"tp_infos"`
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
	Events                    *ebpf.Map `ebpf:"events"`
	GolangMapbucketStorageMap *ebpf.Map `ebpf:"golang_mapbucket_storage_map"`
	HeaderReqMap              *ebpf.Map `ebpf:"header_req_map"`
	Newproc1                  *ebpf.Map `ebpf:"newproc1"`
	OngoingGoroutines         *ebpf.Map `ebpf:"ongoing_goroutines"`
	OngoingHttpClientRequests *ebpf.Map `ebpf:"ongoing_http_client_requests"`
	OngoingServerRequests     *ebpf.Map `ebpf:"ongoing_server_requests"`
	TpInfos                   *ebpf.Map `ebpf:"tp_infos"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Events,
		m.GolangMapbucketStorageMap,
		m.HeaderReqMap,
		m.Newproc1,
		m.OngoingGoroutines,
		m.OngoingHttpClientRequests,
		m.OngoingServerRequests,
		m.TpInfos,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	UprobeServeHTTP           *ebpf.Program `ebpf:"uprobe_ServeHTTP"`
	UprobeWriteHeader         *ebpf.Program `ebpf:"uprobe_WriteHeader"`
	UprobeRoundTrip           *ebpf.Program `ebpf:"uprobe_roundTrip"`
	UprobeRoundTripReturn     *ebpf.Program `ebpf:"uprobe_roundTripReturn"`
	UprobeStartBackgroundRead *ebpf.Program `ebpf:"uprobe_startBackgroundRead"`
	UprobeWriteSubset         *ebpf.Program `ebpf:"uprobe_writeSubset"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.UprobeServeHTTP,
		p.UprobeWriteHeader,
		p.UprobeRoundTrip,
		p.UprobeRoundTripReturn,
		p.UprobeStartBackgroundRead,
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
//go:embed bpf_bpfel_arm64.o
var _BpfBytes []byte
