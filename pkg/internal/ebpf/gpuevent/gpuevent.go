package gpuevent

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/ianlancetaylor/demangle"
	"github.com/prometheus/procfs"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/config"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	unwindsupport "go.opentelemetry.io/ebpf-profiler/support"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type gpu_kernel_launch_t -type gpu_malloc_t -type UnwindInfo -type StackDeltaPageKey -type StackDeltaPageInfo -target amd64,arm64 bpf ../../../../bpf/gpuevent.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type gpu_kernel_launch_t -type gpu_malloc_t -type UnwindInfo -type StackDeltaPageKey -type StackDeltaPageInfo -target amd64,arm64 bpf_debug ../../../../bpf/gpuevent.c -- -I../../../../bpf/headers -DBPF_DEBUG

const EventTypeKernelLaunch = 1 // EVENT_GPU_KERNEL_LAUNCH
const EventTypeMalloc = 2       // EVENT_GPU_MALLOC

type pidKey struct {
	Pid int32
	Ns  uint32
}

type modInfo struct {
	base uint64
	end  uint64
	ino  uint64
}

type moduleOffsets map[uint64]*SymbolTree

type GPUKernelLaunchInfo bpfGpuKernelLaunchT
type GPUMallocInfo bpfGpuMallocT

// TODO: We have a way to bring ELF file information to this Tracer struct
// via the newNonGoTracersGroup / newNonGoTracersGroupUProbes functions. Now,
// we need to figure out how to pass it to the SharedRingbuf.. not sure if thats
// possible
type Tracer struct {
	pidsFilter       ebpfcommon.ServiceFilter
	cfg              *beyla.Config
	metrics          imetrics.Reporter
	bpfObjects       bpfObjects
	closers          []io.Closer
	log              *slog.Logger
	instrumentedLibs ebpfcommon.InstrumentedLibsT
	libsMux          sync.Mutex
	pidMap           map[pidKey]uint64
	symbolsMap       map[uint64]moduleOffsets
	baseMap          map[pidKey][]modInfo

	// unwindInfoIndex maps each unique UnwindInfo to its array index within the corresponding
	// BPF map. This serves for de-duplication purposes. Elements are never removed. Entries are
	// synchronized with the unwind_info_array eBPF map.
	unwindInfoIndex map[sdtypes.UnwindInfo]uint16

	// numStackDeltaMapPages tracks the current size of the corresponding eBPF map.
	numStackDeltaMapPages uint64
}

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "gpuevent.Tracer")

	return &Tracer{
		log:              log,
		cfg:              cfg,
		metrics:          metrics,
		pidsFilter:       ebpfcommon.CommonPIDsFilter(&cfg.Discovery),
		instrumentedLibs: make(ebpfcommon.InstrumentedLibsT),
		libsMux:          sync.Mutex{},
		pidMap:           map[pidKey]uint64{},
		symbolsMap:       map[uint64]moduleOffsets{},
		baseMap:          map[pidKey][]modInfo{},
	}
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
	p.removeCudaPID(pid, ns)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	return loader()
}

func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 2)

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	if !p.cfg.Discovery.SystemWide && !p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(1)
	} else {
		m["filter_pids"] = int32(0)
	}

	return m
}

func (p *Tracer) RegisterOffsets(fileInfo *exec.FileInfo, _ *goexec.Offsets) {
	p.ProcessBinary(fileInfo)
}

func (p *Tracer) ProcessBinary(fileInfo *exec.FileInfo) {
	if fileInfo == nil || fileInfo.ELF == nil {
		p.log.Error("Empty fileinfo for Cuda")
	} else {
		var interval sdtypes.IntervalData
		ref := pfelf.NewReference(fileInfo.CmdExePath, pfelf.SystemOpener)
		err := elfunwindinfo.ExtractELF(ref, &interval)
		if err != nil {
			p.log.Error("error getting stack deltas", "err", err)
		} else {
			r, g, e := p.loadDeltas(fileInfo.Ino, interval.Deltas)
			p.log.Info("Load deltas", "ref", r, "gaps", g, "err", e)
		}

		p.processCudaFileInfo(fileInfo)
	}
}

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
		"libcudart.so": {
			"cudaLaunchKernel": {{
				Start: p.bpfObjects.HandleCudaLaunch,
			}},
			"cudaMalloc": {{
				Start: p.bpfObjects.HandleCudaMalloc,
			}},
		},
	}
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) RecordInstrumentedLib(id uint64, closers []io.Closer) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.AddRef(id)

	if len(closers) > 0 {
		module.Closers = append(module.Closers, closers...)
	}

	p.log.Debug("Recorded instrumented Lib", "ino", id, "module", module)
}

func (p *Tracer) AddInstrumentedLibRef(id uint64) {
	p.RecordInstrumentedLib(id, nil)
}

func (p *Tracer) UnlinkInstrumentedLib(id uint64) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	delete(p.symbolsMap, id)

	module, err := p.instrumentedLibs.RemoveRef(id)

	p.log.Debug("Unlinking instrumented lib - before state", "ino", id, "module", module)

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "ino", id, "error", err)
	}
}

func (p *Tracer) AlreadyInstrumentedLib(id uint64) bool {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.Find(id)

	p.log.Debug("checking already instrumented Lib", "ino", id, "module", module)
	return module != nil
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.Rb,
		&ebpfcommon.IdentityPidsFilter{},
		p.processCudaEvent,
		p.log,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func (p *Tracer) processCudaEvent(_ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	var eventType uint8

	// we read the type first, depending on the type we decide what kind of record we have
	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &eventType)
	if err != nil {
		return request.Span{}, true, err
	}

	switch eventType {
	case EventTypeKernelLaunch:
		return p.readGPUKernelLaunchIntoSpan(record)
	case EventTypeMalloc:
		return p.readGPUMallocIntoSpan(record)
	default:
		p.log.Error("unknown cuda event")
	}

	return request.Span{}, false, nil
}

func (p *Tracer) readGPUMallocIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GPUMallocInfo
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	p.log.Debug("GPU Malloc", "event", event)

	return request.Span{
		Type:          request.EventTypeGPUMalloc,
		ContentLength: int64(event.Size),
	}, false, nil
}

func (p *Tracer) readGPUKernelLaunchIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GPUKernelLaunchInfo
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	p.log.Info("GPU Kernel Launch", "event", event)

	// Find the symbol for the kernel launch
	symbol, ok := p.symForAddr(int32(event.PidInfo.UserPid), event.PidInfo.Ns, event.KernFuncOff)
	if !ok {
		return request.Span{}, true, fmt.Errorf("failed to find symbol for kernel launch at address %d, pid %d", event.KernFuncOff, event.PidInfo.UserPid)
	}

	return request.Span{
		Type:          request.EventTypeGPUKernelLaunch,
		Method:        p.symToName(symbol),
		Path:          p.callStack(&event),
		ContentLength: int64(event.GridX * event.GridY * event.GridZ),
		SubType:       int(event.BlockX * event.BlockY * event.BlockZ),
	}, false, nil
}

func (p *Tracer) callStack(event *GPUKernelLaunchInfo) string {
	if event.UstackSz > 1 {
		cs := []string{}

		for i := 0; i < int(event.UstackSz); i++ {
			addr := event.Ustack[i]
			if addr != 0 {
				symbol, ok := p.symForAddr(int32(event.PidInfo.UserPid), event.PidInfo.Ns, addr)
				if ok {
					symbol = p.symToName(symbol)
					cs = append(cs, symbol)
				}
			}
		}

		return strings.Join(cs, ";")
	}

	return ""
}

func (p *Tracer) processCudaLibFileInfo(info *exec.FileInfo, lib string, maps []*procfs.ProcMap, symMods moduleOffsets) (*SymbolTree, *procfs.ProcMap, bool) {
	cudaMap := exec.LibPathPlain(lib, maps)

	if cudaMap == nil {
		return nil, nil, false
	}

	if _, ok := symMods[cudaMap.Inode]; ok {
		return nil, cudaMap, false
	}

	instrPath := fmt.Sprintf("/proc/%d/map_files/%x-%x", info.Pid, cudaMap.StartAddr, cudaMap.EndAddr)

	var ELF *elf.File
	var err error

	if ELF, err = elf.Open(instrPath); err != nil {
		p.log.Error("can't open ELF file in", "file", instrPath, "error", err)
	}

	p.log.Debug("Processing symbols", "path", cudaMap.Pathname)

	symAddr, err := p.findSymbolAddresses(ELF)
	if err != nil {
		p.log.Error("failed to find symbol addresses", "error", err)
		return nil, nil, false
	}

	return symAddr, cudaMap, true
}

func (p *Tracer) discoverModule(info *exec.FileInfo, maps []*procfs.ProcMap, symModules moduleOffsets, path string) *procfs.ProcMap {
	symAddr, mod, ok := p.processCudaLibFileInfo(info, path, maps, symModules)
	if ok {
		symModules[mod.Inode] = symAddr
	}

	return mod
}

func (p *Tracer) processCudaFileInfo(info *exec.FileInfo) {
	maps, err := exec.FindLibMaps(int32(info.Pid))
	if err != nil {
		p.log.Error("failed to find pid maps", "error", err)
		return
	}

	p.log.Info("Processing CUDA symbols for", "pid", info.Pid, "ns", info.Ns)

	disovered := []*procfs.ProcMap{}
	symModules, ok := p.symbolsMap[info.Ino]
	if !ok {
		symModules = moduleOffsets{}
	}

	p.log.Debug("Sym modules have", "count", len(symModules))

	if mod := p.discoverModule(info, maps, symModules, info.CmdExePath); mod != nil {
		disovered = append(disovered, mod)
	}

	if mod := p.discoverModule(info, maps, symModules, "libtorch_cuda.so"); mod != nil {
		disovered = append(disovered, mod)
	}

	for _, m := range maps {
		if strings.Contains(m.Pathname, "/vllm") {
			if mod := p.discoverModule(info, maps, symModules, m.Pathname); mod != nil {
				disovered = append(disovered, mod)
			}
		}
		if strings.Contains(m.Pathname, "/ggml") {
			if mod := p.discoverModule(info, maps, symModules, m.Pathname); mod != nil {
				disovered = append(disovered, mod)
			}
		}
	}

	p.log.Debug("Processing cuda symbol map for", "inode", info.Ino)
	for k := range symModules {
		p.log.Debug("Found symbols for", "inode", k)
	}

	p.log.Debug("Sym modules have", "count", len(symModules))

	p.symbolsMap[info.Ino] = symModules
	if len(disovered) > 0 {
		p.establishCudaPID(uint32(info.Pid), info, disovered)
	}
}

func (p *Tracer) establishCudaPID(pid uint32, fi *exec.FileInfo, mods []*procfs.ProcMap) {
	bases, err := p.modulesAddressInfos(pid, mods)
	if err != nil {
		p.log.Error("Error finding base map image", "error", err)
		return
	}

	allPids, err := exec.FindNamespacedPids(int32(pid))

	if err != nil {
		p.log.Error("Error finding namespaced pids", "error", err)
		return
	}

	for _, nsPid := range allPids {
		k := pidKey{Pid: int32(nsPid), Ns: fi.Ns}
		p.baseMap[k] = bases
		p.pidMap[k] = fi.Ino
		p.log.Debug("Setting pid map", "pid", pid, "bases", bases)
	}
}

func (p *Tracer) removeCudaPID(pid uint32, ns uint32) {
	k := pidKey{Pid: int32(pid), Ns: ns}
	delete(p.baseMap, k)
	delete(p.pidMap, k)
}

func (p *Tracer) symToName(sym string) string {
	if cleanName, err := demangle.ToString(sym); err == nil {
		return cleanName
	}

	return sym
}

func (p *Tracer) modulesAddressInfos(pid uint32, mods []*procfs.ProcMap) ([]modInfo, error) {
	res := []modInfo{}

	for _, mod := range mods {
		res = append(res, modInfo{
			base: uint64(mod.StartAddr),
			end:  uint64(mod.EndAddr),
			ino:  mod.Inode,
		})
	}

	p.log.Debug("added", "mods", res, "pid", pid)

	if len(res) == 0 {
		return nil, errors.New("can't find any CUDA libraries in path")
	}

	return res, nil
}

func (p *Tracer) symForAddr(pid int32, ns uint32, off uint64) (string, bool) {
	k := pidKey{Pid: pid, Ns: ns}

	fInfo, ok := p.pidMap[k]
	if !ok {
		p.log.Warn("Can't find pid info for cuda", "pid", pid, "ns", ns)
		return "", false
	}
	syms, ok := p.symbolsMap[fInfo]
	if !ok {
		p.log.Warn("Can't find symbols for ino", "ino", fInfo)
		return "", false
	}

	base, ok := p.baseMap[k]
	if !ok {
		p.log.Warn("Can't find basemap")
		return "", false
	}

	for i := range base {
		m := &base[i]
		if off > m.base && off < m.end {
			modSyms, ok := syms[m.ino]
			if ok {
				res := modSyms.Search(off - m.base)
				if len(res) > 0 {
					return res[0].Symbol, true
				}
				return "", false
			} else {
				p.log.Warn("Can't find mod sym for", "ino", m.ino)
			}
		}
	}

	return "", false
}

func (p *Tracer) collectSymbols(f *elf.File, syms []elf.Symbol, tree *SymbolTree) {
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		address := s.Value
		// Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				address = s.Value - prog.Vaddr
				break
			}
		}
		if address != 0 {
			tree.Insert(Symbol{Low: address, High: address + s.Size, Symbol: s.Name})
		}
	}
}

// returns a map of symbol addresses to names
func (p *Tracer) findSymbolAddresses(f *elf.File) (*SymbolTree, error) {
	t := SymbolTree{}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	p.collectSymbols(f, syms, &t)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	p.collectSymbols(f, dynsyms, &t)

	return &t, nil
}

// stack unwinding

const (
	// minimumMemoizableGapSize is the minimum size for a gap for it to be
	// recorded. Currently reflects the V8 binary blob size, in which
	// the gap size is >= 512kB.
	minimumMemoizableGapSize = 512 * 1024
)

// Range describes a range with Start and End values.
type Range struct {
	Start uint64
	End   uint64
}

type StackDeltaEBPF struct {
	AddressLow uint16
	UnwindInfo uint16
}

type mapRef struct {
	StartPage uint64
	NumPages  uint32
	MapID     uint16
}

// loadDeltas converts the sdtypes.StackDelta to StackDeltaEBPF and passes that to
// the ebpf interface to be loaded to kernel maps. While converting the deltas, it
// also creates a list of all large gaps in the executable.
func (p *Tracer) loadDeltas(
	fileID uint64,
	deltas []sdtypes.StackDelta,
) (ref mapRef, gaps []Range, err error) {
	numDeltas := len(deltas)
	if numDeltas == 0 {
		// If no deltas are extracted, cache the result but don't reserve memory in BPF maps.
		return mapRef{MapID: 0}, []Range{}, nil
	}

	firstPage := deltas[0].Address >> unwindsupport.StackDeltaPageBits
	firstPageAddr := deltas[0].Address &^ unwindsupport.StackDeltaPageMask
	lastPage := deltas[numDeltas-1].Address >> unwindsupport.StackDeltaPageBits
	numPages := lastPage - firstPage + 1
	numDeltasPerPage := make([]uint16, numPages)

	// Index the unwind-info.
	var unwindInfo sdtypes.UnwindInfo
	ebpfDeltas := make([]StackDeltaEBPF, 0, numDeltas)
	for index, delta := range deltas {
		if unwindInfo.MergeOpcode != 0 {
			// This delta was merged in the previous iteration.
			unwindInfo.MergeOpcode = 0
			continue
		}
		unwindInfo = delta.Info
		if index+1 < len(deltas) {
			unwindInfo.MergeOpcode = p.calculateMergeOpcode(delta, deltas[index+1])
			nextDeltaAddr := deltas[index+1].Address
			if delta.Hints&sdtypes.UnwindHintGap != 0 &&
				nextDeltaAddr-delta.Address >= minimumMemoizableGapSize {
				// Remember large gaps so ProcessManager plugins can
				// later use them to find precompiled blobs without deltas.
				gaps = append(gaps, Range{
					Start: delta.Address,
					End:   nextDeltaAddr})
			}
		}
		// Uses the new 'unwindInfo' with potentially updated MergeOpcode
		// here. In the end, it's only the unwindInfoIndex being different for
		// merged deltas.
		var unwindInfoIndex uint16
		unwindInfoIndex, err = p.getUnwindInfoIndex(unwindInfo)
		if err != nil {
			return mapRef{}, nil, err
		}
		ebpfDeltas = append(ebpfDeltas, StackDeltaEBPF{
			AddressLow: uint16(delta.Address),
			UnwindInfo: unwindInfoIndex,
		})
		numDeltasPerPage[(delta.Address>>unwindsupport.StackDeltaPageBits)-firstPage]++
	}

	// Update data to eBPF
	mapID, err := p.UpdateExeIDToStackDeltas(fileID, ebpfDeltas)
	if err != nil {
		return mapRef{}, nil,
			fmt.Errorf("failed UpdateExeIDToStackDeltas for FileID %x: %v", fileID, err)
	}

	// Update stack delta pages
	if err = p.UpdateStackDeltaPages(fileID, numDeltasPerPage, mapID,
		firstPageAddr); err != nil {
		_ = p.DeleteExeIDToStackDeltas(fileID)
		return mapRef{}, nil,
			fmt.Errorf("failed UpdateStackDeltaPages for FileID %x: %v", fileID, err)
	}
	p.numStackDeltaMapPages += numPages

	return mapRef{
		MapID:     mapID,
		StartPage: firstPageAddr,
		NumPages:  uint32(numPages),
	}, gaps, nil
}

// calculateMergeOpcode calculates the merge opcode byte given two consecutive StackDeltas.
// Zero means no merging happened. Only small differences for address and the CFA delta
// are considered, in order to limit the amount of unique combinations generated.
func (p *Tracer) calculateMergeOpcode(delta, nextDelta sdtypes.StackDelta) uint8 {
	if delta.Info.Opcode == sdtypes.UnwindOpcodeCommand {
		return 0
	}
	addrDiff := nextDelta.Address - delta.Address
	if addrDiff < 1 || addrDiff > 2 {
		return 0
	}
	if nextDelta.Info.Opcode != delta.Info.Opcode ||
		nextDelta.Info.FPOpcode != delta.Info.FPOpcode ||
		nextDelta.Info.FPParam != delta.Info.FPParam {
		return 0
	}
	paramDiff := nextDelta.Info.Param - delta.Info.Param
	switch paramDiff {
	case 8:
		return uint8(addrDiff)
	case -8:
		return uint8(addrDiff) | unwindsupport.MergeOpcodeNegative
	}
	return 0
}

// getUnwindInfoIndex maps the given UnwindInfo to its eBPF array index. This can be direct
// encoding, or index to the unwind info array (new index is created if needed).
// See STACK_DELTA_COMMAND_FLAG for further explanation of the directly encoded unwind infos.
func (p *Tracer) getUnwindInfoIndex(
	info sdtypes.UnwindInfo,
) (uint16, error) {
	if info.Opcode == sdtypes.UnwindOpcodeCommand {
		return uint16(info.Param) | unwindsupport.DeltaCommandFlag, nil
	}

	if index, ok := p.unwindInfoIndex[info]; ok {
		return index, nil
	}
	index := uint16(len(p.unwindInfoIndex))
	if err := p.UpdateUnwindInfo(index, info); err != nil {
		return 0, fmt.Errorf("failed to insert unwind info #%d: %v", index, err)
	}
	p.unwindInfoIndex[info] = index
	return index, nil
}

func (p *Tracer) UpdateUnwindInfo(index uint16, info sdtypes.UnwindInfo) error {
	i := bpfUnwindInfo{}
	i.Opcode = info.Opcode
	i.FpOpcode = info.FPOpcode
	i.MergeOpcode = info.MergeOpcode
	i.Param = info.Param
	i.FpParam = info.FPParam

	return p.bpfObjects.UnwindInfoArray.Put(index, i)
}

func (p *Tracer) UpdateExeIDToStackDeltas(index uint64, deltaArrays []StackDeltaEBPF) (uint16, error) {
	for index, delta := range deltaArrays {
		d := bpfStackDelta{}
		d.AddrLow = delta.AddressLow
		d.UnwindInfo = delta.UnwindInfo
		if err := p.bpfObjects.StackDeltaArray.Put(index, d); err != nil {
			return 0, err
		}
	}

	return unwindsupport.StackDeltaBucketSmallest, nil
}

func (p *Tracer) UpdateStackDeltaPages(fileID uint64, numDeltasPerPage []uint16, mapID uint16, firstPageAddr uint64) error {
	firstDelta := uint32(0)

	for pageNumber, numDeltas := range numDeltasPerPage {
		k := bpfStackDeltaPageKey{}
		k.FileID = fileID
		k.Page = uint64(pageNumber)

		v := bpfStackDeltaPageInfo{}
		v.FirstDelta = firstDelta
		v.NumDeltas = numDeltas
		v.MapID = mapID

		if err := p.bpfObjects.StackDeltaPageToInfo.Put(k, v); err != nil {
			return err
		}

		firstDelta += uint32(numDeltas)
	}

	return nil
}

func (p *Tracer) DeleteExeIDToStackDeltas(fileID uint64) error {
	return p.bpfObjects.StackDeltaArray.Delete(fileID)
}
