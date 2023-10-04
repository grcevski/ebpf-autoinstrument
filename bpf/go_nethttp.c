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

#include "utils.h"
#include "go_str.h"
#include "go_byte_arr.h"
#include "bpf_dbg.h"
#include "go_common.h"
#include "go_nethttp.h"
#include "go_traceparent.h"
#include "bpf_builtins.h"

#define CLIENT_FLAG_NEW 0x1

typedef struct traceparent_info_t {
    u8 traceparent[TRACEPARENT_LEN];
} traceparent_info;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, func_invocation);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request header map
    __type(value, u64); // the goroutine of the transport request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} header_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, traceparent_info); // the goroutine of the transport request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} tp_infos SEC(".maps");

struct bpf_map_def SEC("maps") temp_char_buf = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(char[256]),
    .max_entries = 256,
};

/* HTTP Server */

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int uprobe_ServeHTTP(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/ServeHTTP === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *resp_ptr = GO_PARAM3(ctx);

    bpf_dbg_printk("goroutine_addr %lx, response %llx, resp ptr %llx", goroutine_addr, resp_ptr);

    func_invocation invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .regs = *ctx,
    };

    void *req_ptr = 0;
    bpf_probe_read(&req_ptr, sizeof(req_ptr), (void *)(resp_ptr + resp_req_pos));

    if (req_ptr) {
        void *traceparent_ptr = extract_traceparent_from_req_headers((void*)(req_ptr + req_header_ptr_pos));
        if (traceparent_ptr) {
            int cpu = bpf_get_smp_processor_id();
            char *buf = bpf_map_lookup_elem(&temp_char_buf, &cpu);
            if (buf) {
                bpf_probe_read(buf, W3C_VAL_LENGTH, traceparent_ptr);
                w3c_string_to_span_context(buf, &invocation.sc);
                generate_random_bytes(invocation.sc.SpanID, SPAN_ID_SIZE);
            } else {
                bpf_printk("Error reading temp per CPU storage");
            }        
        } else {
            invocation.sc = generate_span_context();
        }
    } else {
        invocation.sc = generate_span_context();
    }

    int cpu = bpf_get_smp_processor_id();
    unsigned char *buf = bpf_map_lookup_elem(&temp_char_buf, &cpu);

    if (buf) {
        span_context_to_w3c_string(&invocation.sc, buf);
        bpf_dbg_printk("sc %s", buf);
    }
    // Write event
    if (bpf_map_update_elem(&ongoing_server_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/startBackgroundRead")
int uprobe_startBackgroundRead(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc startBackgroundRead === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    // This code is here for keepalive support on HTTP requests. Since the connection is not
    // established every time, we set the initial goroutine start on the new read initiation.
    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (!g_metadata) {
        goroutine_metadata metadata = {
            .timestamp = bpf_ktime_get_ns(),
            .parent = (u64)goroutine_addr,
        };

        if (bpf_map_update_elem(&ongoing_goroutines, &goroutine_addr, &metadata, BPF_ANY)) {
            bpf_dbg_printk("can't update active goroutine");
        }
    }

    return 0;
}

SEC("uprobe/WriteHeader")
int uprobe_WriteHeader(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/WriteHeader === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    func_invocation *invocation =
        bpf_map_lookup_elem(&ongoing_server_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_server_requests, &goroutine_addr);
    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(goroutine_addr);
        if (parent_go) {
            bpf_dbg_printk("found parent goroutine for header [%llx]", parent_go);
            invocation = bpf_map_lookup_elem(&ongoing_server_requests, &parent_go);
            bpf_map_delete_elem(&ongoing_server_requests, &parent_go);
        }
        if (!invocation) {
            bpf_dbg_printk("can't read http invocation metadata");
            return 0;
        }
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return 0;
    }
    trace->type = EVENT_HTTP_REQUEST;
    trace->id = (u64)goroutine_addr;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (g_metadata) {
        trace->go_start_monotime_ns = g_metadata->timestamp;
        bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    // Read the response argument
    void *resp_ptr = GO_PARAM1(ctx);
    // Get request struct
    void *req_ptr = 0;
    bpf_probe_read(&req_ptr, sizeof(req_ptr), (void *)(resp_ptr + resp_req_pos));

    bpf_dbg_printk("response %llx, request %llx", resp_ptr, req_ptr);

    if (!req_ptr) {
        bpf_printk("can't find req inside the response value");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get method from Request.Method
    if (!read_go_str("method", req_ptr, method_ptr_pos, &trace->method, sizeof(trace->method))) {
        bpf_printk("can't read http Request.Method");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get the remote peer information from Request.RemoteAddr
    if (!read_go_str("remote_addr", req_ptr, remoteaddr_ptr_pos, &trace->remote_addr, sizeof(trace->remote_addr))) {
        bpf_printk("can't read http Request.RemoteAddr");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get the host information the remote supplied
    if (!read_go_str("host", req_ptr, host_ptr_pos, &trace->host, sizeof(trace->host))) {
        bpf_printk("can't read http Request.Host");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));

    if (!url_ptr || !read_go_str("path", url_ptr, path_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_printk("can't read http Request.URL.Path");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    bpf_probe_read(&trace->content_length, sizeof(trace->content_length), (void *)(req_ptr + content_length_ptr_pos));

    // Get traceparent from the Request.Header
    void *traceparent_ptr = extract_traceparent_from_req_headers((void*)(req_ptr + req_header_ptr_pos));
    if (traceparent_ptr != NULL) {
        long res = bpf_probe_read(trace->traceparent, sizeof(trace->traceparent), traceparent_ptr);
        if (res < 0) {
            bpf_printk("can't copy traceparent header");
            bpf_ringbuf_discard(trace, 0);
            return 0;
        }
    }

    bpf_memcpy(&trace->sc, &invocation->sc, sizeof(struct span_context));

    trace->status = (u16)(((u64)GO_PARAM2(ctx)) & 0x0ffff);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

    return 0;
}

/* HTTP Client. We expect to see HTTP client in both HTTP server and gRPC server calls.*/

SEC("uprobe/roundTrip")
int uprobe_roundTrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http roundTrip === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *req_ptr = GO_PARAM2(ctx);
    bpf_dbg_printk("goroutine_addr %lx, req ptr %llx", goroutine_addr, req_ptr);

    void *headers_ptr = 0;
    bpf_probe_read(&headers_ptr, sizeof(headers_ptr), (void*)(req_ptr + req_header_ptr_pos));
    bpf_dbg_printk("goroutine_addr %lx, req ptr %llx, headers_ptr %llx", goroutine_addr, req_ptr, headers_ptr);

    func_invocation invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .regs = *ctx
    };

    // Write event
    if (bpf_map_update_elem(&ongoing_http_client_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update http client map element");
    }

    if (headers_ptr) {
        void *traceparent_ptr = extract_traceparent_from_req_headers((void*)(req_ptr + req_header_ptr_pos));

        if (traceparent_ptr) {
            bpf_dbg_printk("Traceparent %s found in headers, skipping generation", traceparent_ptr);
            return 0;
        }

        bpf_map_update_elem(&header_req_map, &headers_ptr, &goroutine_addr, BPF_ANY);
    }

    return 0;
}

SEC("uprobe/roundTrip_return")
int uprobe_roundTripReturn(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http roundTrip return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    func_invocation *invocation =
        bpf_map_lookup_elem(&ongoing_http_client_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_http_client_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read http invocation metadata");
        return 0;
    }

    traceparent_info *tp = bpf_map_lookup_elem(&tp_infos, &goroutine_addr);
    bpf_map_delete_elem(&tp_infos, &goroutine_addr);

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return 0;
    }

    trace->id = find_parent_goroutine(goroutine_addr);

    trace->type = EVENT_HTTP_CLIENT;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    // Read arguments from the original set of registers

    // Get request/response struct
    void *req_ptr = GO_PARAM2(&(invocation->regs));
    void *resp_ptr = (void *)GO_PARAM1(ctx);

    void *headers_ptr = NULL;
    bpf_probe_read(&headers_ptr, sizeof(headers_ptr), (void*)(req_ptr + req_header_ptr_pos));
    if (headers_ptr) {
        bpf_map_delete_elem(&header_req_map, &headers_ptr);
    }

    // Get method from Request.Method
    if (!read_go_str("method", req_ptr, method_ptr_pos, &trace->method, sizeof(trace->method))) {
        bpf_printk("can't read http Request.Method");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get the host information of the remote
    if (!read_go_str("host", req_ptr, host_ptr_pos, &trace->host, sizeof(trace->host))) {
        bpf_printk("can't read http Request.Host");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));

    if (!url_ptr || !read_go_str("path", url_ptr, path_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_printk("can't read http Request.URL.Path");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    if (tp) {
        bpf_dbg_printk("found traceparent info %s", tp->traceparent);
        bpf_probe_read(trace->traceparent, sizeof(tp->traceparent), tp->traceparent);
    } else {
        // Get traceparent from the Request.Header
        void *traceparent_ptr = extract_traceparent_from_req_headers((void*)(req_ptr + req_header_ptr_pos));
        if (traceparent_ptr != NULL) {
            long res = bpf_probe_read(trace->traceparent, sizeof(trace->traceparent), traceparent_ptr);
            if (res < 0) {
                bpf_printk("can't copy traceparent header");
                bpf_ringbuf_discard(trace, 0);
                return 0;
            }
        }
    }

    bpf_printk("url: %s, req %llx", trace->path, (u64)req_ptr);

    bpf_probe_read(&trace->content_length, sizeof(trace->content_length), (void *)(req_ptr + content_length_ptr_pos));

    bpf_probe_read(&trace->status, sizeof(trace->status), (void *)(resp_ptr + status_code_ptr_pos));

    bpf_dbg_printk("status %d, offset %d, resp_ptr %lx", trace->status, status_code_ptr_pos, (u64)resp_ptr);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

    return 0;
}

SEC("uprobe/header_writeSubset")
int uprobe_writeSubset(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc header writeSubset === ");

    void *header_addr = GO_PARAM1(ctx);
    void *io_writer_addr = GO_PARAM3(ctx);

    bpf_dbg_printk("goroutine_addr %lx, header ptr %llx", GOROUTINE_PTR(ctx), header_addr);

    u64 *request_goaddr = bpf_map_lookup_elem(&header_req_map, &header_addr);

    if (!request_goaddr) {
        bpf_dbg_printk("Can't find parent go routine for header %llx", header_addr);
        return 0;
    }

    u64 parent_goaddr = *request_goaddr;

    traceparent_info *tp_info = bpf_map_lookup_elem(&tp_infos, &parent_goaddr);
    if (tp_info) {
        return 0;
    }

    bpf_dbg_printk("request goaddr %llx", (void*)parent_goaddr);
    u64 request_parent = find_parent_goroutine((void *)parent_goaddr);

    struct span_context sc = generate_span_context();
    if (request_parent) {
        func_invocation *parent_inv = bpf_map_lookup_elem(&ongoing_server_requests, &request_parent);
        bpf_printk("found request parent %llx, parent invocation %llx", request_parent, parent_inv);

        if (parent_inv) {
            bpf_probe_read(sc.TraceID, sizeof(sc.TraceID), parent_inv->sc.TraceID);
        }
    }

    traceparent_info info = {};

    span_context_to_w3c_string(&sc, info.traceparent);
    bpf_map_update_elem(&tp_infos, &parent_goaddr, &info, BPF_ANY);

    void *buf_ptr = 0;
    bpf_probe_read(&buf_ptr, sizeof(buf_ptr), (void *)(io_writer_addr + io_writer_buf_ptr_pos));
    if (!buf_ptr) {
        return 0;
    }
    
    s64 size = 0;
    bpf_probe_read(&size, sizeof(s64), (void *)(io_writer_addr + io_writer_buf_ptr_pos + 8)); // grab size

    s64 len = 0;
    bpf_probe_read(&len, sizeof(s64), (void *)(io_writer_addr + io_writer_n_pos)); // grab len

    bpf_dbg_printk("buf_ptr %llx, len=%d, size=%d", (void*)buf_ptr, len, size);

    if (len < (size - W3C_VAL_LENGTH - W3C_KEY_LENGTH - 4)) { // 4 = :<space>\r\n
        char key[W3C_KEY_LENGTH + 2] = "Traceparent: ";
        char end[2] = "\r\n";
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), key, sizeof(key));
        len += W3C_KEY_LENGTH + 2;
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), info.traceparent, sizeof(info.traceparent));
        len += W3C_VAL_LENGTH;
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), end, sizeof(end));
        len += 2;
        bpf_probe_write_user((void *)(io_writer_addr + io_writer_n_pos), &len, sizeof(len));
    }

    return 0;
}