// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#ifndef GO_RUNTIME_H
#define GO_RUNTIME_H

#include "utils.h"
#include "bpf_dbg.h"
#include "go_common.h"

typedef struct new_func_invocation {
    u64 parent;
} new_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, new_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} newproc1 SEC(".maps");

static __always_inline void runtime_proc_newproc1_start(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    new_func_invocation_t invocation = {
        .parent = (u64)GO_PARAM2(ctx) 
    };

    // Save the registers on invocation to be able to fetch the arguments at return of newproc1
    if (bpf_map_update_elem(&newproc1, &creator_goroutine, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }
}

static __always_inline int runtime_proc_newproc1_end(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 returns === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    // Lookup the newproc1 invocation metadata
    new_func_invocation_t *invocation = (new_func_invocation_t *)bpf_map_lookup_elem(&newproc1, &creator_goroutine);
    bpf_map_delete_elem(&newproc1, &creator_goroutine);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read newproc1 invocation metadata");
        return 0;
    }

    // The parent goroutine is the second argument of newproc1
    void *parent_goroutine = (void *)invocation->parent;
    bpf_dbg_printk("parent goroutine_addr %lx", parent_goroutine);

    // The result of newproc1 is the new goroutine
    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    goroutine_metadata metadata = {
        .timestamp = bpf_ktime_get_ns(),
        .parent = (u64)parent_goroutine,
    };

    if (bpf_map_update_elem(&ongoing_goroutines, &goroutine_addr, &metadata, BPF_ANY)) {
        bpf_dbg_printk("can't update active goroutine");
    }

    return 0;
}

static __always_inline void runtime_proc_goexit1_start(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc goexit1 === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    // We also clean-up the go routine based trace map, it's an LRU
    // but at this point we are sure we don't need the data.
    bpf_map_delete_elem(&go_trace_map, &goroutine_addr);
}

#endif // GO_RUNTIME_H