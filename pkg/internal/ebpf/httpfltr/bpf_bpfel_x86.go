// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package httpfltr

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

type bpfHttpBufT struct {
	Flags    uint64
	ConnInfo bpfConnectionInfoT
	Buf      [1024]uint8
	_        [4]byte
}

type bpfHttpConnectionMetadataT struct {
	Id   uint64
	Type uint8
	_    [7]byte
}

type bpfHttpInfoT struct {
	Flags           uint64
	ConnInfo        bpfConnectionInfoT
	_               [4]byte
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Buf             [160]uint8
	Pid             uint32
	Len             uint32
	RespLen         uint32
	Status          uint16
	Type            uint8
	Ssl             uint8
}

type bpfRecvArgsT struct {
	SockPtr  uint64
	IovecPtr uint64
}

type bpfSockArgsT struct {
	Addr       uint64
	AcceptTime uint64
}

type bpfSslArgsT struct {
	Ssl    uint64
	Buf    uint64
	LenPtr uint64
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
	KprobeSysExit           *ebpf.ProgramSpec `ebpf:"kprobe_sys_exit"`
	KprobeTcpConnect        *ebpf.ProgramSpec `ebpf:"kprobe_tcp_connect"`
	KprobeTcpRcvEstablished *ebpf.ProgramSpec `ebpf:"kprobe_tcp_rcv_established"`
	KprobeTcpRecvmsg        *ebpf.ProgramSpec `ebpf:"kprobe_tcp_recvmsg"`
	KprobeTcpSendmsg        *ebpf.ProgramSpec `ebpf:"kprobe_tcp_sendmsg"`
	KretprobeSockAlloc      *ebpf.ProgramSpec `ebpf:"kretprobe_sock_alloc"`
	KretprobeSysAccept4     *ebpf.ProgramSpec `ebpf:"kretprobe_sys_accept4"`
	KretprobeSysConnect     *ebpf.ProgramSpec `ebpf:"kretprobe_sys_connect"`
	KretprobeTcpRecvmsg     *ebpf.ProgramSpec `ebpf:"kretprobe_tcp_recvmsg"`
	UprobeSslDoHandshake    *ebpf.ProgramSpec `ebpf:"uprobe_ssl_do_handshake"`
	UprobeSslRead           *ebpf.ProgramSpec `ebpf:"uprobe_ssl_read"`
	UprobeSslReadEx         *ebpf.ProgramSpec `ebpf:"uprobe_ssl_read_ex"`
	UprobeSslShutdown       *ebpf.ProgramSpec `ebpf:"uprobe_ssl_shutdown"`
	UprobeSslWrite          *ebpf.ProgramSpec `ebpf:"uprobe_ssl_write"`
	UprobeSslWriteEx        *ebpf.ProgramSpec `ebpf:"uprobe_ssl_write_ex"`
	UretprobeSslDoHandshake *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_do_handshake"`
	UretprobeSslRead        *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_read"`
	UretprobeSslReadEx      *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_read_ex"`
	UretprobeSslWrite       *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_write"`
	UretprobeSslWriteEx     *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_write_ex"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	ActiveAcceptArgs    *ebpf.MapSpec `ebpf:"active_accept_args"`
	ActiveConnectArgs   *ebpf.MapSpec `ebpf:"active_connect_args"`
	ActiveRecvArgs      *ebpf.MapSpec `ebpf:"active_recv_args"`
	ActiveSslHandshakes *ebpf.MapSpec `ebpf:"active_ssl_handshakes"`
	ActiveSslReadArgs   *ebpf.MapSpec `ebpf:"active_ssl_read_args"`
	ActiveSslWriteArgs  *ebpf.MapSpec `ebpf:"active_ssl_write_args"`
	DeadPids            *ebpf.MapSpec `ebpf:"dead_pids"`
	Events              *ebpf.MapSpec `ebpf:"events"`
	FilteredConnections *ebpf.MapSpec `ebpf:"filtered_connections"`
	HttpTcpSeq          *ebpf.MapSpec `ebpf:"http_tcp_seq"`
	OngoingHttp         *ebpf.MapSpec `ebpf:"ongoing_http"`
	PidTidToConn        *ebpf.MapSpec `ebpf:"pid_tid_to_conn"`
	SslToConn           *ebpf.MapSpec `ebpf:"ssl_to_conn"`
	SslToPidTid         *ebpf.MapSpec `ebpf:"ssl_to_pid_tid"`
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
	ActiveAcceptArgs    *ebpf.Map `ebpf:"active_accept_args"`
	ActiveConnectArgs   *ebpf.Map `ebpf:"active_connect_args"`
	ActiveRecvArgs      *ebpf.Map `ebpf:"active_recv_args"`
	ActiveSslHandshakes *ebpf.Map `ebpf:"active_ssl_handshakes"`
	ActiveSslReadArgs   *ebpf.Map `ebpf:"active_ssl_read_args"`
	ActiveSslWriteArgs  *ebpf.Map `ebpf:"active_ssl_write_args"`
	DeadPids            *ebpf.Map `ebpf:"dead_pids"`
	Events              *ebpf.Map `ebpf:"events"`
	FilteredConnections *ebpf.Map `ebpf:"filtered_connections"`
	HttpTcpSeq          *ebpf.Map `ebpf:"http_tcp_seq"`
	OngoingHttp         *ebpf.Map `ebpf:"ongoing_http"`
	PidTidToConn        *ebpf.Map `ebpf:"pid_tid_to_conn"`
	SslToConn           *ebpf.Map `ebpf:"ssl_to_conn"`
	SslToPidTid         *ebpf.Map `ebpf:"ssl_to_pid_tid"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.ActiveAcceptArgs,
		m.ActiveConnectArgs,
		m.ActiveRecvArgs,
		m.ActiveSslHandshakes,
		m.ActiveSslReadArgs,
		m.ActiveSslWriteArgs,
		m.DeadPids,
		m.Events,
		m.FilteredConnections,
		m.HttpTcpSeq,
		m.OngoingHttp,
		m.PidTidToConn,
		m.SslToConn,
		m.SslToPidTid,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	KprobeSysExit           *ebpf.Program `ebpf:"kprobe_sys_exit"`
	KprobeTcpConnect        *ebpf.Program `ebpf:"kprobe_tcp_connect"`
	KprobeTcpRcvEstablished *ebpf.Program `ebpf:"kprobe_tcp_rcv_established"`
	KprobeTcpRecvmsg        *ebpf.Program `ebpf:"kprobe_tcp_recvmsg"`
	KprobeTcpSendmsg        *ebpf.Program `ebpf:"kprobe_tcp_sendmsg"`
	KretprobeSockAlloc      *ebpf.Program `ebpf:"kretprobe_sock_alloc"`
	KretprobeSysAccept4     *ebpf.Program `ebpf:"kretprobe_sys_accept4"`
	KretprobeSysConnect     *ebpf.Program `ebpf:"kretprobe_sys_connect"`
	KretprobeTcpRecvmsg     *ebpf.Program `ebpf:"kretprobe_tcp_recvmsg"`
	UprobeSslDoHandshake    *ebpf.Program `ebpf:"uprobe_ssl_do_handshake"`
	UprobeSslRead           *ebpf.Program `ebpf:"uprobe_ssl_read"`
	UprobeSslReadEx         *ebpf.Program `ebpf:"uprobe_ssl_read_ex"`
	UprobeSslShutdown       *ebpf.Program `ebpf:"uprobe_ssl_shutdown"`
	UprobeSslWrite          *ebpf.Program `ebpf:"uprobe_ssl_write"`
	UprobeSslWriteEx        *ebpf.Program `ebpf:"uprobe_ssl_write_ex"`
	UretprobeSslDoHandshake *ebpf.Program `ebpf:"uretprobe_ssl_do_handshake"`
	UretprobeSslRead        *ebpf.Program `ebpf:"uretprobe_ssl_read"`
	UretprobeSslReadEx      *ebpf.Program `ebpf:"uretprobe_ssl_read_ex"`
	UretprobeSslWrite       *ebpf.Program `ebpf:"uretprobe_ssl_write"`
	UretprobeSslWriteEx     *ebpf.Program `ebpf:"uretprobe_ssl_write_ex"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.KprobeSysExit,
		p.KprobeTcpConnect,
		p.KprobeTcpRcvEstablished,
		p.KprobeTcpRecvmsg,
		p.KprobeTcpSendmsg,
		p.KretprobeSockAlloc,
		p.KretprobeSysAccept4,
		p.KretprobeSysConnect,
		p.KretprobeTcpRecvmsg,
		p.UprobeSslDoHandshake,
		p.UprobeSslRead,
		p.UprobeSslReadEx,
		p.UprobeSslShutdown,
		p.UprobeSslWrite,
		p.UprobeSslWriteEx,
		p.UretprobeSslDoHandshake,
		p.UretprobeSslRead,
		p.UretprobeSslReadEx,
		p.UretprobeSslWrite,
		p.UretprobeSslWriteEx,
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
