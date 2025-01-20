// References to the map definitions in the BPF C code.

#ifndef OPTI_EXTMAPS_H
#define OPTI_EXTMAPS_H

typedef struct _bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
} _bpf_map_def;

// References to map definitions in *.ebpf.c.
extern _bpf_map_def progs;
extern _bpf_map_def per_cpu_records;
extern _bpf_map_def pid_page_to_mapping_info;
extern _bpf_map_def metrics;
extern _bpf_map_def report_events;
extern _bpf_map_def reported_pids;
extern _bpf_map_def pid_events;
extern _bpf_map_def inhibit_events;
extern _bpf_map_def interpreter_offsets;
extern _bpf_map_def system_config;
extern _bpf_map_def trace_events;

#endif // OPTI_EXTMAPS_H
