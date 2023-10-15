#ifndef HTTP_SOCK_HELPERS
#define HTTP_SOCK_HELPERS

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "ringbuf.h"
#include "pid.h"

#define MIN_HTTP_SIZE 12 // HTTP/1.1 CCC is the smallest valid request we can have
#define RESPONSE_STATUS_POS 9 // HTTP/1.1 <--

#define PACKET_TYPE_REQUEST 1
#define PACKET_TYPE_RESPONSE 2

// Keeps track of the tcp sequences we've seen for a connection
// With multiple network interfaces the same sequence can be seen again
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, u32); // the TCP sequence
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} http_tcp_seq SEC(".maps");

// Keeps track of active accept or connect connection infos
// From this table we extract the PID of the process and filter
// HTTP calls we are not interested in
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, http_connection_metadata_t); // PID_TID group and connection type
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} filtered_connections SEC(".maps");

// Keeps track of the ongoing http connections we match for request/response
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, http_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http SEC(".maps");

static __always_inline bool tcp_dup(connection_info_t *http, protocol_info_t *tcp) {
    u32 *prev_seq = bpf_map_lookup_elem(&http_tcp_seq, http);

    if (prev_seq && (*prev_seq == tcp->seq)) {
        return true;
    }

    bpf_map_update_elem(&http_tcp_seq, http, &tcp->seq, BPF_ANY);
    return false;
}

static __always_inline bool is_http(unsigned char *p, u32 len, u8 *packet_type) {
    if (len < MIN_HTTP_SIZE) {
        return false;
    }
    //HTTP
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
       *packet_type = PACKET_TYPE_RESPONSE;
    } else if (
        ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) ||                                                      // GET
        ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') && (p[4] == ' ') && (p[5] == '/')) ||                                     // POST
        ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) ||                                                      // PUT
        ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H') && (p[5] == ' ') && (p[6] == '/')) ||                    // PATCH
        ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E') && (p[6] == ' ') && (p[7] == '/')) ||   // DELETE
        ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D') && (p[4] == ' ') && (p[5] == '/')) ||                                     // HEAD
        ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') && (p[5] == 'N') && (p[6] == 'S') && (p[7] == ' ') && (p[8] == '/'))   // OPTIONS
    ) {
        *packet_type = PACKET_TYPE_REQUEST;
    }

    return true;
}

static __always_inline void read_msghdr_buf(void *target, int buf_len, struct msghdr *msg) {
    unsigned int m_flags;
    u8 i_type;
    size_t iov_offset;
    size_t count;

    bpf_probe_read_kernel(&m_flags, sizeof(unsigned int), &(msg->msg_flags));
    bpf_probe_read_kernel(&i_type, sizeof(u8), &(msg->msg_iter.iter_type));
    bpf_probe_read_kernel(&iov_offset, sizeof(size_t), &(msg->msg_iter.iov_offset));
    bpf_probe_read_kernel(&count, sizeof(size_t), &(msg->msg_iter.count));

    bpf_dbg_printk("msg flags %x, iter type %d, iov_offset %d, count %d", m_flags, i_type, iov_offset, count);

    struct iovec *iovec;
    bpf_probe_read_kernel(&iovec, sizeof(struct iovec *), &(msg->msg_iter.iov));        
    if (i_type == 0) { // IOVEC
        struct iovec vec;
        long success = bpf_probe_read_kernel(&vec, sizeof(vec), iovec);
        bpf_printk("iovec %llx, len %d, success=%d", vec.iov_base, vec.iov_len, success);
        if (vec.iov_len > 0) {
            success = bpf_probe_read_user(target, buf_len, (void *)vec.iov_base);
            bpf_printk("target %llx, success=%d", vec.iov_base, success);
        } else {            
            bpf_probe_read(target, buf_len, (void *)iovec);
            bpf_printk("%llx %llx %llx %llx", target, target + 8, target + 16, target + 24);
        }
    } else { // we assume UBUF
        bpf_probe_read(target, buf_len, (void *)iovec);
    }    
}

static __always_inline void* find_msghdr_buf(struct msghdr *msg) {
    u8 i_type;

    bpf_probe_read_kernel(&i_type, sizeof(u8), &(msg->msg_iter.iter_type));

    struct iovec *iovec;
    bpf_probe_read_kernel(&iovec, sizeof(struct iovec *), &(msg->msg_iter.iov));        
    if (i_type == 0) { // IOVEC
        struct iovec vec;
        bpf_probe_read_kernel(&vec, sizeof(vec), iovec);
        return (void *)vec.iov_base;
    } else { // we assume UBUF
        return (void *)iovec;
    }    
}

// Copying 16 bytes at a time from the skb buffer is the only way to keep the verifier happy.
static __always_inline void read_skb_bytes(const void *skb, u32 offset, unsigned char *buf, const u32 len) {
    u32 max = offset + len;
    int b = 0;
    for (; b < (FULL_BUF_SIZE/BUF_COPY_BLOCK_SIZE); b++) {
        if ((offset + (BUF_COPY_BLOCK_SIZE - 1)) >= max) {
            break;
        }
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), BUF_COPY_BLOCK_SIZE);
        offset += BUF_COPY_BLOCK_SIZE;
    }

    if ((b * BUF_COPY_BLOCK_SIZE) >= len) {
        return;
    }

    // This code is messy to make sure the eBPF verifier is happy. I had to cast to signed 64bit.
    s64 remainder = (s64)max - (s64)offset;

    if (remainder <= 0) {
        return;
    }

    int remaining_to_copy = (remainder < (BUF_COPY_BLOCK_SIZE - 1)) ? remainder : (BUF_COPY_BLOCK_SIZE - 1);
    int space_in_buffer = (len < (b * BUF_COPY_BLOCK_SIZE)) ? 0 : len - (b * BUF_COPY_BLOCK_SIZE);

    if (remaining_to_copy <= space_in_buffer) {
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), remaining_to_copy);
    }
}

static __always_inline void finish_http(http_info_t *info) {
    if (info->start_monotime_ns != 0 && info->status != 0 && info->pid != 0) {
        http_info_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_info_t), 0);
        if (trace) {
            bpf_dbg_printk("Sending trace %lx", info);

            bpf_memcpy(trace, info, sizeof(http_info_t));
            bpf_ringbuf_submit(trace, get_flags());
        }

        bpf_map_delete_elem(&http_tcp_seq, &info->conn_info);
        bpf_map_delete_elem(&ongoing_http, &info->conn_info);
        // bpf_map_delete_elem(&filtered_connections, &info->conn_info); // don't clean this up, doesn't work with keepalive
        // we don't explicitly clean-up the http_tcp_seq, we need to still monitor for dups
    }        
}

static __always_inline http_info_t *get_or_set_http_info(http_info_t *info, u8 packet_type) {
    if (packet_type == PACKET_TYPE_REQUEST) {
        http_info_t *old_info = bpf_map_lookup_elem(&ongoing_http, &info->conn_info);
        if (old_info) {
            finish_http(old_info); // this will delete ongoing_http for this connection info if there's full stale request
        }

        bpf_map_update_elem(&ongoing_http, &info->conn_info, info, BPF_ANY);
    }

    return bpf_map_lookup_elem(&ongoing_http, &info->conn_info);
}

static __always_inline bool still_responding(http_info_t *info) {
    return info->status != 0;
}

static __always_inline bool still_reading(http_info_t *info) {
    return info->status == 0 && info->start_monotime_ns != 0;
}

static __always_inline void process_http_request(http_info_t *info, int len) {
    info->start_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->len = len;
}

static __always_inline void process_http_response(http_info_t *info, unsigned char *buf, http_connection_metadata_t *meta, int len) {
    info->pid = pid_from_pid_tgid(meta->id);
    info->type = meta->type;
    info->resp_len = len;
    info->status = 0;
    info->end_monotime_ns = bpf_ktime_get_ns();
    info->status += (buf[RESPONSE_STATUS_POS]     - '0') * 100;
    info->status += (buf[RESPONSE_STATUS_POS + 1] - '0') * 10;
    info->status += (buf[RESPONSE_STATUS_POS + 2] - '0');
}

static __always_inline void handle_http_response(unsigned char *small_buf, connection_info_t *conn, http_info_t *info, int orig_len) {
    http_connection_metadata_t *meta = bpf_map_lookup_elem(&filtered_connections, conn);
    http_connection_metadata_t dummy_meta = {
        .id = bpf_get_current_pid_tgid(),
        .type = EVENT_HTTP_REQUEST
    };

    if (!meta) {
        meta = &dummy_meta;
    }

    process_http_response(info, small_buf, meta, orig_len);
    finish_http(info);
}

static __always_inline http_buf_t *make_http_trace_buf(void *u_buf, int size, connection_info_t *conn) {
    if (size <= 0) {
        return NULL;
    }

    http_buf_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_buf_t), 0);
    if (trace) {
        trace->conn_info = *conn;
        trace->flags |= CONN_INFO_FLAG_TRACE;

        s64 buf_len = (s64)size;
        if (buf_len >= TRACE_BUF_SIZE) {
            buf_len = TRACE_BUF_SIZE - 1;
        }
        buf_len &= (TRACE_BUF_SIZE - 1);
        bpf_probe_read(trace->buf, buf_len, u_buf);

        if (buf_len < TRACE_BUF_SIZE) {
            trace->buf[buf_len] = '\0';
        }
    }
    return trace;
}

static __always_inline void handle_msghdr_with_connection(connection_info_t *conn, void *u_buf, int bytes_len) {
    unsigned char small_buf[MIN_HTTP_SIZE] = {0};
    bpf_probe_read(small_buf, MIN_HTTP_SIZE, u_buf);

    bpf_dbg_printk("buf=[%s]", small_buf);

    u8 packet_type = 0;
    if (is_http(small_buf, MIN_HTTP_SIZE, &packet_type)) {
        http_info_t in = {0};
        in.conn_info = *conn;

        http_info_t *info = get_or_set_http_info(&in, packet_type);
        if (!info) {
            return;
        }

        bpf_dbg_printk("=== http_buffer_event len=%d pid=%d still_reading=%d ===", bytes_len, pid_from_pid_tgid(bpf_get_current_pid_tgid()), still_reading(info));

        if (packet_type == PACKET_TYPE_REQUEST && (info->status == 0)) {
            http_buf_t *trace = make_http_trace_buf(u_buf, bytes_len, conn);
            if (trace) {
                // we copy some small part of the buffer to the info trace event, so that we can process an event even with
                // incomplete trace info in user space.
                bpf_probe_read(info->buf, FULL_BUF_SIZE, u_buf);
                bpf_dbg_printk("Sending http buffer %s", trace->buf);
                bpf_ringbuf_submit(trace, get_flags());
            } else {
                bpf_probe_read(info->buf, FULL_BUF_SIZE, u_buf);
            }

            process_http_request(info, bytes_len);
        } else if (packet_type == PACKET_TYPE_RESPONSE) {
            handle_http_response(small_buf, conn, info, bytes_len);
        }        
    }
}

#endif