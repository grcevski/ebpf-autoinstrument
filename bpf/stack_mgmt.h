#ifndef OPTI_TRACEMGMT_H
#define OPTI_TRACEMGMT_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_dbg.h"
#include "frametypes.h"
#include "stack_types.h"

#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __constant_cpu_to_be32(x) __builtin_bswap32(x)
#define __constant_cpu_to_be64(x) __builtin_bswap64(x)
#elif defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __constant_cpu_to_be32(x) (x)
#define __constant_cpu_to_be64(x) (x)
#else
#error "Unknown endianness"
#endif

struct bpf_map_def SEC("maps") per_cpu_records = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(PerCPURecord),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") pid_page_to_mapping_info = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(PIDPage),
    .value_size = sizeof(PIDPageMappingInfo),
    .max_entries = 524288, // 2^19
    .map_flags = BPF_F_NO_PREALLOC,
};

// The decision whether to unwind native stacks or interpreter stacks is made by checking if a given
// PC address falls into the "interpreter loop" of an interpreter. This map helps identify such
// loops: The keys are those executable section IDs that contain interpreter loops, the values
// identify the offset range within this executable section that contains the interpreter loop.
struct bpf_map_def SEC("maps") interpreter_offsets = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(OffsetRange),
    .max_entries = 32,
};

static inline __attribute__((__always_inline__)) void increment_metric(u32 metricID) {
}

// Return the per-cpu record.
// As each per-cpu array only has 1 entry, we hard-code 0 as the key.
// The return value of get_per_cpu_record() can never be NULL and return value checks only exist
// to pass the verifier. If the implementation of get_per_cpu_record() is changed so that NULL can
// be returned, also add an error metric.
static inline PerCPURecord *get_per_cpu_record(void) {
    int key0 = 0;
    return (PerCPURecord *)bpf_map_lookup_elem(&per_cpu_records, &key0);
}

// Push the file ID, line number and frame type into FrameList with a user-defined
// maximum stack size.
//
// NOTE: The line argument is used for a lot of different purposes, depending on
//       the frame type. For example error frames use it to store the error number,
//       and hotspot puts a subtype and BCI indices, amongst other things (see
//       calc_line). This should probably be renamed to something like "frame type
//       specific data".
static inline __attribute__((__always_inline__)) ErrorCode _push_with_max_frames(
    Trace *trace, u64 file, u64 line, u8 frame_type, u8 return_address, u32 max_frames) {
    if (trace->stack_len >= max_frames) {
        bpf_d_printk("unable to push frame: stack is full");
        increment_metric(metricID_UnwindErrStackLengthExceeded);
        return ERR_STACK_LENGTH_EXCEEDED;
    }

#ifdef TESTING_COREDUMP
    // utils/coredump uses CGO to build the eBPF code. This dispatches
    // the frame information directly to helper implemented in ebpfhelpers.go.
    int __push_frame(u64, u64, u64, u8, u8);
    trace->stack_len++;
    return __push_frame(__cgo_ctx->id, file, line, frame_type, return_address);
#else
    trace->frames[trace->stack_len++] = (Frame){
        .file_id = file,
        .addr_or_line = line,
        .kind = frame_type,
        .return_address = return_address,
    };

    return ERR_OK;
#endif
}

// Push the file ID, line number and frame type into FrameList
static inline __attribute__((__always_inline__)) ErrorCode
_push_with_return_address(Trace *trace, u64 file, u64 line, u8 frame_type, bool return_address) {
    return _push_with_max_frames(
        trace, file, line, frame_type, return_address, MAX_NON_ERROR_FRAME_UNWINDS);
}

// Push the file ID, line number and frame type into FrameList
static inline __attribute__((__always_inline__)) ErrorCode _push(Trace *trace,
                                                                 u64 file,
                                                                 u64 line,
                                                                 u8 frame_type) {
    return _push_with_max_frames(trace, file, line, frame_type, 0, MAX_NON_ERROR_FRAME_UNWINDS);
}

// Push a critical error frame.
static inline __attribute__((__always_inline__)) ErrorCode push_error(Trace *trace,
                                                                      ErrorCode error) {
    return _push_with_max_frames(trace, 0, error, FRAME_MARKER_ABORT, 0, MAX_FRAME_UNWINDS);
}

// is_kernel_address checks if the given address looks like virtual address to kernel memory.
static bool is_kernel_address(u64 addr) {
    return addr & 0xFF00000000000000UL;
}

// unwinder_is_done checks if a given unwinder program is done for the trace
// extraction round.
static inline __attribute__((__always_inline__)) bool unwinder_is_done(const PerCPURecord *record,
                                                                       int unwinder) {
    return (record->unwindersDone & (1U << unwinder)) != 0;
}

// unwinder_mark_done will mask out a given unwinder program so that it will
// not be called again for the same trace. Used when interpreter unwinder has
// extracted all interpreter frames it can extract.
static inline __attribute__((__always_inline__)) void unwinder_mark_done(PerCPURecord *record,
                                                                         int unwinder) {
    record->unwindersDone |= 1U << unwinder;
}

// resolve_unwind_mapping decodes the current PC's mapping and prepares unwinding information.
// The state text_section_id and text_section_offset are updated accordingly. The unwinding program
// index that should be used is written to the given `unwinder` pointer.
static ErrorCode resolve_unwind_mapping(PerCPURecord *record, int *unwinder) {
    UnwindState *state = &record->state;
    pid_t pid = record->trace.pid;
    u64 pc = state->pc;

    if (is_kernel_address(pc)) {
        // This should not happen as we should only be unwinding usermode stacks.
        // Seeing PC point to a kernel address indicates a bad unwind.
        bpf_d_printk("PC value %lx is a kernel address", (unsigned long)pc);
        state->error_metric = metricID_UnwindNativeErrKernelAddress;
        return ERR_NATIVE_UNEXPECTED_KERNEL_ADDRESS;
    }

    if (pc < 0x1000) {
        // The kernel will always return a start address for user space memory mappings that is
        // above the value defined in /proc/sys/vm/mmap_min_addr.
        // As such small PC values happens regularly (e.g. by handling or extracting the
        // PC value incorrectly) we track them but don't proceed with unwinding.
        bpf_d_printk("small pc value %lx, ignoring", (unsigned long)pc);
        state->error_metric = metricID_UnwindNativeSmallPC;
        return ERR_NATIVE_SMALL_PC;
    }

    PIDPage key = {};
    key.prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE;
    key.pid = __constant_cpu_to_be32((u32)pid);
    key.page = __constant_cpu_to_be64(pc);

    // Check if we have the data for this virtual address
    PIDPageMappingInfo *val =
        (PIDPageMappingInfo *)bpf_map_lookup_elem(&pid_page_to_mapping_info, &key);
    if (!val) {
        bpf_d_printk("Failure to look up interval memory mapping for PC 0x%lx", (unsigned long)pc);
        state->error_metric = metricID_UnwindNativeErrWrongTextSection;
        return ERR_NATIVE_NO_PID_PAGE_MAPPING;
    }

    decode_bias_and_unwind_program(
        val->bias_and_unwind_program, &state->text_section_bias, unwinder);
    state->text_section_id = val->file_id;
    state->text_section_offset = pc - state->text_section_bias;
    bpf_d_printk("Text section id for PC %lx is %llx (unwinder %d)",
                 (unsigned long)pc,
                 state->text_section_id,
                 *unwinder);
    bpf_d_printk("Text section bias is %llx, and offset is %llx",
                 state->text_section_bias,
                 state->text_section_offset);

    return ERR_OK;
}

static inline int get_next_interpreter(PerCPURecord *record) {
    UnwindState *state = &record->state;
    u64 section_id = state->text_section_id;
    u64 section_offset = state->text_section_offset;
    // Check if the section id happens to be in the interpreter map.
    OffsetRange *range = (OffsetRange *)bpf_map_lookup_elem(&interpreter_offsets, &section_id);
    if (range != 0) {
        if ((section_offset >= range->lower_offset) && (section_offset <= range->upper_offset)) {
            bpf_d_printk("interpreter_offsets match %d", range->program_index);
            if (!unwinder_is_done(record, range->program_index)) {
                increment_metric(metricID_UnwindCallInterpreter);
                return range->program_index;
            }
            bpf_d_printk("interpreter unwinder done");
        }
    }
    return PROG_UNWIND_NATIVE;
}

// get_next_unwinder_after_native_frame determines the next unwinder program to run
// after a native stack frame has been unwound.
static inline __attribute__((__always_inline__)) ErrorCode
get_next_unwinder_after_native_frame(PerCPURecord *record, int *unwinder) {
    UnwindState *state = &record->state;
    *unwinder = PROG_UNWIND_STOP;

    if (state->pc == 0) {
        bpf_d_printk("Stopping unwind due to unwind failure (PC == 0)");
        state->error_metric = metricID_UnwindErrZeroPC;
        return ERR_NATIVE_ZERO_PC;
    }

    bpf_d_printk("==== Resolve next frame unwinder: frame %d ====", record->trace.stack_len);
    ErrorCode error = resolve_unwind_mapping(record, unwinder);
    if (error) {
        return error;
    }

    if (*unwinder == PROG_UNWIND_NATIVE) {
        *unwinder = get_next_interpreter(record);
    }

    return ERR_OK;
}
#endif