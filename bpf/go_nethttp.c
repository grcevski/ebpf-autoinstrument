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
#include "go_nethttp.h"

/* HTTP Server */

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int uprobe_ServeHTTP(struct pt_regs *ctx) {
    http_ServeHTTP_start(ctx);
    return 0;
}

SEC("uprobe/readRequest")
int uprobe_readRequestReturns(struct pt_regs *ctx) {
    http_readRequest_end(ctx);
    return 0;
}

SEC("uprobe/WriteHeader")
int uprobe_WriteHeader(struct pt_regs *ctx) {
    return writeHeaderHelper(ctx, resp_req_pos);
}

SEC("uprobe/roundTrip")
int uprobe_roundTrip(struct pt_regs *ctx) {
    roundTripStartHelper(ctx);
    return 0;
}

SEC("uprobe/roundTrip_return")
int uprobe_roundTripReturn(struct pt_regs *ctx) {
    return http_roundTrip_end(ctx);
}

// Context propagation through HTTP headers
SEC("uprobe/header_writeSubset")
int uprobe_writeSubset(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    return http_writeSubset_start(ctx);
#else
    return 0;
#endif
}

// HTTP 2.0 server support
SEC("uprobe/http2ResponseWriterStateWriteHeader")
int uprobe_http2ResponseWriterStateWriteHeader(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 responseWriterState writeHeader === ");
    return writeHeaderHelper(ctx, rws_req_pos);
}

// HTTP 2.0 client support
SEC("uprobe/http2RoundTrip")
int uprobe_http2RoundTrip(struct pt_regs *ctx) {
    http2_http2RoundTrip_start(ctx);
    return 0;
}

SEC("uprobe/http2FramerWriteHeaders")
int uprobe_http2FramerWriteHeaders(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    http2_http2FramerWriteHeaders_start(ctx);
#endif
    return 0;
}

SEC("uprobe/http2FramerWriteHeaders_returns")
int uprobe_http2FramerWriteHeaders_returns(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    return http2_http2FramerWriteHeaders_end(ctx);
#else
    return 0;
#endif 
}

static __always_inline void read_ip_and_port(u8 *dst_ip, u16 *dst_port, void *src) {
    s64 addr_len = 0;
    void *addr_ip = 0;

    bpf_probe_read(dst_port, sizeof(u16), (void *)(src + tcp_addr_port_ptr_pos));
    bpf_probe_read(&addr_ip, sizeof(addr_ip), (void *)(src + tcp_addr_ip_ptr_pos));
    if (addr_ip) {
        bpf_probe_read(&addr_len, sizeof(addr_len), (void *)(src + tcp_addr_ip_ptr_pos + 8));
        if (addr_len == 4) {
            __builtin_memcpy(dst_ip, ip4ip6_prefix, sizeof(ip4ip6_prefix));
            bpf_probe_read(dst_ip + sizeof(ip4ip6_prefix), 4, addr_ip);
        } else if (addr_len == 16) {
            bpf_probe_read(dst_ip, 16, addr_ip);
        }
    }
}

// HTTP black-box context propagation
static __always_inline void get_conn_info(void *conn_ptr, connection_info_t *info) {
    if (conn_ptr) {
        void *fd_ptr = 0;
        bpf_probe_read(&fd_ptr, sizeof(fd_ptr), (void *)(conn_ptr + conn_fd_pos)); // find fd

        bpf_dbg_printk("Found fd ptr %llx", fd_ptr);

        if (fd_ptr) {
            void *laddr_ptr = 0;
            void *raddr_ptr = 0;

            bpf_probe_read(&laddr_ptr, sizeof(laddr_ptr), (void *)(fd_ptr + fd_laddr_pos + 8)); // find laddr
            bpf_probe_read(&raddr_ptr, sizeof(raddr_ptr), (void *)(fd_ptr + fd_raddr_pos + 8)); // find raddr

            if (laddr_ptr && raddr_ptr) {
                bpf_dbg_printk("laddr %llx, raddr %llx", laddr_ptr, raddr_ptr);

                // read local
                read_ip_and_port(info->s_addr, &info->s_port, laddr_ptr);

                // read remote
                read_ip_and_port(info->d_addr, &info->d_port, raddr_ptr);

                sort_connection_info(info);
                //dbg_print_http_connection_info(info);
            }
        }
    }
}

SEC("uprobe/connServe")
int uprobe_connServe(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http conn serve === ");

    void *c_ptr = GO_PARAM1(ctx);
    if (c_ptr) {
        void *rwc_ptr = c_ptr + 8 + c_rwc_pos; // embedded struct
        if (rwc_ptr) {
            void *conn_ptr = 0;
            bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(rwc_ptr + rwc_conn_pos)); // find conn
            if (conn_ptr) {
                void *goroutine_addr = GOROUTINE_PTR(ctx);
                connection_info_t conn = {0};
                get_conn_info(conn_ptr, &conn);

                bpf_map_update_elem(&ongoing_http_server_connections, &goroutine_addr, &conn, BPF_ANY);
            }
        }
    }

    return 0;
}

SEC("uprobe/connServeRet")
int uprobe_connServeRet(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http conn serve ret === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_map_delete_elem(&ongoing_http_server_connections, &goroutine_addr);

    return 0;
}

SEC("uprobe/persistConnRoundTrip")
int uprobe_persistConnRoundTrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http persistConn roundTrip === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    http_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_http_client_requests, &goroutine_addr);
    if (!invocation) {
        bpf_dbg_printk("can't find invocation info for client call, this might be a bug");
        return 0;
    }

    void *pc_ptr = GO_PARAM1(ctx);
    if (pc_ptr) {
        void *conn_conn_ptr = pc_ptr + 8 + pc_conn_pos; // embedded struct
        if (conn_conn_ptr) {
            void *conn_ptr = 0;
            bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(conn_conn_ptr + rwc_conn_pos)); // find conn
            if (conn_ptr) {
                connection_info_t conn = {0};
                get_conn_info(conn_ptr, &conn);
                u64 pid_tid = bpf_get_current_pid_tgid();
                u32 pid = pid_from_pid_tgid(pid_tid);
                tp_info_pid_t tp_p = {
                    .pid = pid,
                    .valid = 1,
                };

                tp_clone(&tp_p.tp, &invocation->tp);
                tp_p.tp.ts = bpf_ktime_get_ns();
                bpf_dbg_printk("storing trace_map info for black-box tracing");
                bpf_map_update_elem(&trace_map, &conn, &tp_p, BPF_ANY);
            }
        }
    }

    return 0;
}
