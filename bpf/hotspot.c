#include "vmlinux.h"
#include "utils.h"
#include "bpf_dbg.h"
#include "pid.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// CodeBlob/NMethod
volatile const s32 cb_kind = 0x34;
volatile const s32 cb_size = 0x18;
volatile const s32 nmethod_method = 0x58;
volatile const s32 cb_code_offset = 0x24;
volatile const s32 nmethod_verified_entry_offset = 0xa2;

// Symbol
volatile const s32 symbol_length = 0x4;
volatile const s32 symbol_body = 0x6;

// Method
volatile const s32 method_name = 0x48;
volatile const s32 method_const_method = 0x10;

// ConstMethod
volatile const s32 const_method_constants = 0x8;
volatile const s32 const_method_signature_index = 0x26;

// ConstantPool
volatile const s32 constants_pool_holder = 0x20;
volatile const s32 constants_size_of = 0x50;

// InstanceKlass
volatile const s32 instance_klass_name = 0x20;

enum {
    kCodeBlob_Nmethod = 0x1,
};

#define NM_MAX_BUF_SIZE 80

typedef struct nmethod_event {
    char name[NM_MAX_BUF_SIZE];
    char klass[NM_MAX_BUF_SIZE];
    char signature[NM_MAX_BUF_SIZE];
    u64 code_start;
    int size;
    pid_info pid;
} nmethod_event_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} compilation_events SEC(".maps");

const nmethod_event_t *unused_nmethod __attribute__((unused));

static __always_inline int read_symbol(void *name_ptr, char *buf, int max_len) {
    void *name = 0;
    bpf_probe_read(&name, sizeof(name), name_ptr);

    if (!name) {
        return 0;
    }

    u16 len = 0;
    bpf_probe_read(&len, sizeof(len), name + symbol_length);
    if (len) {
        bpf_clamp_umax(len, max_len);
        bpf_probe_read(buf, len, name + symbol_body);
    }

    if (len < max_len) {
        buf[len] = '\0';
    }

    return len;
}

static __always_inline void *start_address(void *nmethod) {
    int code_offset = 0;
    u16 verified_entry_offset = 0;

    bpf_probe_read(&code_offset, sizeof(code_offset), nmethod + cb_code_offset);
    bpf_probe_read(&verified_entry_offset,
                   sizeof(verified_entry_offset),
                   nmethod + nmethod_verified_entry_offset);

    return nmethod + code_offset + verified_entry_offset;
}

SEC("uprobe/libjvm.so:CodeCacheCommit")
int beyla_code_cache_commit(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    nmethod_event_t *event = bpf_ringbuf_reserve(&compilation_events, sizeof(nmethod_event_t), 0);

    if (!event) {
        return 0;
    }

    task_pid(&event->pid);
    event->size = -1;

    void *cb = (void *)PT_REGS_PARM1(ctx);

    bpf_dbg_printk("=== uprobe HotspotVM CodeCache::commit id=%d wrap=%llx ===", id, cb);

    u8 kind = 0;
    bpf_probe_read(&kind, sizeof(kind), cb + cb_kind);

    bpf_dbg_printk("kind: %d", kind);

    if (kind == kCodeBlob_Nmethod) {
        void *method = 0;
        void *code_start_address = start_address(cb);
        int code_size = 0;

        bpf_probe_read(&code_size, sizeof(code_size), cb + cb_size);
        bpf_probe_read(&method, sizeof(method), cb + nmethod_method);
        bpf_dbg_printk(
            "method: %llx, start: 0x%llx, size 0x%x", method, code_start_address, code_size);

        event->code_start = (u64)code_start_address;
        event->size = code_size;

        if (method) {
            int __attribute__((unused)) name_len =
                read_symbol(method + method_name, event->name, NM_MAX_BUF_SIZE);
            bpf_dbg_printk("[%d]name: %s", name_len, event->name);

            void *const_method = 0;
            bpf_probe_read(&const_method, sizeof(const_method), method + method_const_method);

            if (const_method) {
                void *constants = 0;
                bpf_probe_read(
                    &constants, sizeof(constants), const_method + const_method_constants);
                u16 signature_idx = 0;
                bpf_probe_read(&signature_idx,
                               sizeof(signature_idx),
                               const_method + const_method_signature_index);

                if (constants) {
                    void *pool_holder = 0;
                    bpf_probe_read(
                        &pool_holder, sizeof(pool_holder), constants + constants_pool_holder);

                    if (pool_holder) {
                        int __attribute__((unused)) klass_name_len =
                            read_symbol(pool_holder + instance_klass_name, event->klass, 80);
                        bpf_dbg_printk("[%d]klass name: %s", klass_name_len, event->klass);
                    }

                    int __attribute__((unused)) sig_len = read_symbol(
                        constants + constants_size_of + (signature_idx * sizeof(void *)),
                        event->signature,
                        80);
                    bpf_dbg_printk("[%d]signature: %s", sig_len, event->signature);
                }
            }
        }
    }

    bpf_ringbuf_submit(event, 0);

    return 0;
}
