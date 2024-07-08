package ebpfcommon

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/ianlancetaylor/demangle"
)

type pidKey struct {
	Pid int32
	Ns uint32
}

var pidMap = map[pidKey]uint64{}
var symbolsMap = map[uint64]map[int64]string{}
var baseMap = map[pidKey]uint64{}

func ProcessCudaFileInfo(info *exec.FileInfo) {
	if _, ok := symbolsMap[info.Ino]; ok {
		return
	}

	maps, err := exec.FindLibMaps(int32(info.Pid))
	if err != nil {
		slog.Error("failed to find pid maps", "error", err)
		return
	}

	var symAddr map[int64]string

	cudaMap := exec.LibExecPath("libtorch_cuda.so", maps)

	if cudaMap != nil {
		instrPath := fmt.Sprintf("/proc/%d/map_files/%x-%x", info.Pid, cudaMap.StartAddr, cudaMap.EndAddr)

		var ELF *elf.File

		if ELF, err = elf.Open(instrPath); err != nil {
			slog.Error("can't open ELF file in", "file", instrPath, "error", err)
		}
	
		symAddr, err = FindSymbolAddresses(ELF)
		if err != nil {
			slog.Error("failed to find symbol addresses", "error", err)
			return
		}
	} else {
		symAddr, err = FindSymbolAddresses(info.ELF)
		if err != nil {
			slog.Error("failed to find symbol addresses", "error", err)
			return
		}
	}

	slog.Info("Processing cuda symbol map for", "inode", info.Ino)

	symbolsMap[info.Ino] = symAddr
	EstablishCudaPID(uint32(info.Pid), info)
}

func EstablishCudaPID(pid uint32, fi *exec.FileInfo) {
	base, err := execBase(pid, fi)
	if err != nil {
		slog.Error("Error finding base map image", "error", err)
		return
	}

	allPids, err := exec.FindNamespacedPids(int32(pid))

	if err != nil {
		slog.Error("Error finding namespaced pids", "error", err)
		return
	}

	for _, p := range allPids {
		k := pidKey{Pid:int32(p), Ns: fi.Ns}
		baseMap[k] = base
		pidMap[k] = fi.Ino
		slog.Info("Setting pid map", "pid", pid, "base", base)
	}
}

func RemoveCudaPID(pid uint32, fi *exec.FileInfo) {
	k := pidKey{Pid:int32(pid), Ns: fi.Ns}
	delete(baseMap, k)
	delete(pidMap, k)
}

func symToName(sym string) string {
	if cleanName, err := demangle.ToString(sym); err == nil {
		return cleanName
	}

	return sym
}

func execBase(pid uint32, fi *exec.FileInfo) (uint64, error) {
	maps, err := exec.FindLibMaps(int32(pid))
	if err != nil {
		return 0, err
	}

	baseMap := exec.LibExecPath("libtorch_cuda.so", maps)
	if baseMap == nil {
		slog.Info("can't find libtorch_cuda.so in maps")
		baseMap = exec.LibExecPath(fi.CmdExePath, maps)
		if baseMap == nil {
			return 0, errors.New("Can't find executable in maps, this is a bug.")
		}
	}

	return uint64(baseMap.StartAddr), nil
}

func symForAddr(pid int32, ns uint32, off uint64) (string, bool) {
	k := pidKey{Pid:pid, Ns: ns}

	fInfo, ok := pidMap[k]
	if !ok {
		slog.Warn("Can't find pid info for cuda", "pid", pid, "ns", ns)
		return "", false
	}
	syms, ok := symbolsMap[fInfo]
	if !ok {
		slog.Warn("Can't find symbols for ino", "ino", fInfo)
		return "", false
	}

	base, ok := baseMap[k]
	if !ok {
		slog.Warn("Can't find basemap")
		return "", false
	}

	sym, ok := syms[int64(off)-int64(base)]
	return sym, ok
}

func ReadGPUKernelLaunchIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GPUKernelLaunchInfo
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	slog.Debug("GPU Kernel Launch", "event", event)

	// Find the symbol for the kernel launch
	symbol, ok := symForAddr(int32(event.PidInfo.UserPid), event.PidInfo.Ns, event.KernFuncOff)
	if !ok {
		return request.Span{}, true, fmt.Errorf("failed to find symbol for kernel launch at address %d", event.KernFuncOff)
	}

	slog.Info("GPU event", "cudaKernel", symToName(symbol))

	return request.Span{
		Type:   request.EventTypeGPUKernelLaunch,
		Method: symbol,
	}, false, nil
}

func collectSymbols(f *elf.File, syms []elf.Symbol, addressToName map[int64]string) {
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		address := int64(s.Value)
		//fmt.Printf("Name: %s, address: %d\n", s.Name, address)
		// Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				address = int64(s.Value) - int64(prog.Vaddr)
				//fmt.Printf("\t->Name: %s, address: %d, vaddr: %d\n", s.Name, address, prog.Vaddr)
				break
			}
		}
		addressToName[address] = s.Name
	}
}

// returns a map of symbol addresses to names
func FindSymbolAddresses(f *elf.File) (map[int64]string, error) {
	addressToName := map[int64]string{}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(f, syms, addressToName)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(f, dynsyms, addressToName)

	return addressToName, nil
}
