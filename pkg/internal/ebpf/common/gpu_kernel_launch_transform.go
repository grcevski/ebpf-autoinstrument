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
var symbolsMap = map[uint64]map[uint64]string{}

func ProcessCudaFileInfo(info *exec.FileInfo) {
	k := pidKey{Pid:info.Pid, Ns: info.Ns}
	if _, ok := pidMap[k]; ok {
		return
	}

	pidMap[k] = info.Ino
	if _, ok := symbolsMap[info.Ino]; ok {
		return
	}

	base, err := execBase(info)
	if err != nil {
		slog.Error("Error finding base map image", "error", err)
		return
	}

	symAddr, err := FindSymbolAddresses(base, info.ELF)
	if err != nil {
		slog.Error("failed to find symbol addresses", "error", err)
		return
	}


	symbolsMap[info.Ino] = symAddr
}

func symToName(sym string) string {
	if cleanName, err := demangle.ToString(sym); err == nil {
		return cleanName
	}

	return sym
}

func execBase(fileInfo *exec.FileInfo) (uint64, error) {
	maps, err := exec.FindLibMaps(fileInfo.Pid)
	if err != nil {
		return 0, err
	}

	baseMap := exec.LibExecPath(fileInfo.CmdExePath, maps)
	if baseMap == nil {
		return 0, errors.New("Can't find executable in maps, this is a bug.")
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

	sym, ok := syms[off]
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

func collectSymbols(base uint64, f *elf.File, syms []elf.Symbol, addressToName map[uint64]string) {
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		address := base + s.Value
		//fmt.Printf("Name: %s, address: %d\n", s.Name, address)
		// Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				address = base + s.Value - prog.Vaddr
				//fmt.Printf("\t->Name: %s, address: %d, vaddr: %d\n", s.Name, address, prog.Vaddr)
				break
			}
		}
		addressToName[address] = s.Name
	}
}

// returns a map of symbol addresses to names
func FindSymbolAddresses(base uint64, f *elf.File) (map[uint64]string, error) {
	addressToName := map[uint64]string{}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(base, f, syms, addressToName)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(base, f, dynsyms, addressToName)

	return addressToName, nil
}
