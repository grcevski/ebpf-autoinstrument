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

	symAddr, err := FindSymbolAddresses(info.ELF)
	if err != nil {
		slog.Error("failed to find symbol addresses", "error", err)
		return
	}

	symbolsMap[info.Ino] = symAddr
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

	return request.Span{
		Type:   request.EventTypeGPUKernelLaunch,
		Method: symbol,
	}, false, nil
}

func collectSymbols(f *elf.File, syms []elf.Symbol, addressToName map[uint64]string) {
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
				address = s.Value - prog.Vaddr + prog.Off
				break
			}
		}
		addressToName[address] = s.Name
	}
}

// returns a map of symbol addresses to names
func FindSymbolAddresses(f *elf.File) (map[uint64]string, error) {
	addressToName := map[uint64]string{}
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
