#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_dbg.h"
#include "pid.h"
#include "sockaddr.h"
#include "tcp_info.h"
#include "http_sock.h"
#include "http_ssl.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Temporary tracking of accept arguments
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, sock_args_t);
} active_accept_args SEC(".maps");

// Temporary tracking of connect arguments
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, sock_args_t);
} active_connect_args SEC(".maps");

// Temporary tracking of tcp_recvmsg arguments
typedef struct recv_args {
    u64 sock_ptr; // linux sock or socket address
    u64 iovec_ptr;
} recv_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, recv_args_t);
} active_recv_args SEC(".maps");

// Used by accept to grab the sock details
SEC("kretprobe/sock_alloc")
int BPF_KRETPROBE(kretprobe_sock_alloc, struct socket *sock) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== sock alloc %llx ===", id);

    u64 addr = (u64)sock;

    sock_args_t args = {};

    args.addr = addr;
    args.accept_time = bpf_ktime_get_ns();

    // The socket->sock is not valid until accept finishes, therefore
    // we don't extract ->sock here, we remember the address of socket
    // and parse in sys_accept
    bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);

    return 0;
}

// We tap into accept and connect to figure out if a request is inbound or
// outbound. However, in some cases servers can optimise the accept path if
// the same request is sent over and over. For that reason, in case we miss the
// initial accept, we establish an active filtered connection here. By default
// sets the type to be server HTTP, in client mode we'll overwrite the 
// data in the map, since those cannot be optimised.
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    pid_connection_info_t info = {};

    if (parse_sock_info(sk, &info.conn)) {
        sort_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);        
        //dbg_print_http_connection_info(&info.conn);

        http_connection_metadata_t meta = {};
        task_pid(&meta.pid);
        meta.type = EVENT_HTTP_REQUEST;
        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_NOEXIST); // On purpose BPF_NOEXIST, we don't want to overwrite data by accept or connect
        bpf_map_update_elem(&pid_tid_to_conn, &id, &info, BPF_ANY); // to support SSL on missing handshake
    }

    return 0;
}

// We tap into both sys_accept and sys_accept4.
// We don't care about the accept entry arguments, since we get only peer information
// we don't have the full picture for the socket.
// 
// Note: A current limitation is that likely we won't capture the first accept request. The
// process may have already reached accept, before the instrumenter has launched.
SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(kretprobe_sys_accept4, uint fd)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    //bpf_dbg_printk("=== accept 4 ret id=%d ===", id);

    // The file descriptor is the value returned from the accept4 syscall.
    // If we got a negative file descriptor we don't have a connection
    if ((int)fd < 0) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
    if (!args) {
        //bpf_dbg_printk("No sock info %d", id);
        goto cleanup;
    }

    bpf_dbg_printk("=== accept 4 ret id=%d, sock=%llx, fd=%d ===", id, args->addr, fd);

    pid_connection_info_t info = {};

    if (parse_accept_socket_info(args, &info.conn)) {
        sort_connection_info(&info.conn);
        //dbg_print_http_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);

        http_connection_metadata_t meta = {};
        task_pid(&meta.pid);
        meta.type = EVENT_HTTP_REQUEST;
        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale
        bpf_map_update_elem(&pid_tid_to_conn, &id, &info, BPF_ANY); // to support SSL on missing handshake
    }

cleanup:
    bpf_map_delete_elem(&active_accept_args, &id);
    return 0;
}

// Used by connect so that we can grab the sock details
SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== tcp connect %llx ===", id);

    u64 addr = (u64)sk;

    sock_args_t args = {};

    args.addr = addr;
    args.accept_time = bpf_ktime_get_ns();

    bpf_map_update_elem(&active_connect_args, &id, &args, BPF_ANY);

    return 0;
}

// We tap into sys_connect so we can track properly the processes doing
// HTTP client calls
SEC("kretprobe/sys_connect")
int BPF_KRETPROBE(kretprobe_sys_connect, int fd)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== connect ret id=%d, pid=%d ===", id, pid_from_pid_tgid(id));

    // The file descriptor is the value returned from the connect syscall.
    // If we got a negative file descriptor we don't have a connection, unless we are in progress
    if (fd < 0 && (fd != -EINPROGRESS)) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);
    if (!args) {
        bpf_dbg_printk("No sock info %d", id);
        goto cleanup;
    }

    pid_connection_info_t info = {};

    if (parse_connect_sock_info(args, &info.conn)) {
        bpf_dbg_printk("=== connect ret id=%d, pid=%d ===", id, pid_from_pid_tgid(id));
        sort_connection_info(&info.conn);
        //dbg_print_http_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);

        http_connection_metadata_t meta = {};
        task_pid(&meta.pid);
        meta.type = EVENT_HTTP_CLIENT;
        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale
        bpf_map_update_elem(&pid_tid_to_conn, &id, &info, BPF_ANY); // to support SSL 
    }

cleanup:
    bpf_map_delete_elem(&active_connect_args, &id);
    return 0;
}

// Main HTTP read and write operations are handled with tcp_sendmsg and tcp_recvmsg 
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe tcp_sendmsg=%d sock=%llx size %d===", id, sk, size);

    pid_connection_info_t info = {};

    if (parse_sock_info(sk, &info.conn)) {
        //dbg_print_http_connection_info(&info.conn); // commented out since GitHub CI doesn't like this call
        sort_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);

        if (size > 0) {
            void *iovec_ptr = find_msghdr_buf(msg);
            if (iovec_ptr) {
                handle_buf_with_connection(&info, iovec_ptr, size, 0);
            } else {
                bpf_dbg_printk("can't find iovec ptr in msghdr, not tracking sendmsg");
            }
        }

        void *ssl = 0;
        // Checks if it's sandwitched between active SSL handshake, read or write uprobe/uretprobe
        void **s = bpf_map_lookup_elem(&active_ssl_handshakes, &id);
        if (s) {
            ssl = *s;
        } else {
            ssl_args_t *ssl_args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
            if (!ssl_args) {
                ssl_args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
            }
            if (ssl_args) {
                ssl = (void *)ssl_args->ssl;
            }
        }

        if (!ssl) {
            return 0;
        }
        bpf_dbg_printk("=== kprobe SSL tcp_sendmsg=%d sock=%llx ssl=%llx ===", id, sk, ssl);
        bpf_map_update_elem(&ssl_to_conn, &ssl, &info, BPF_ANY);
    }

    return 0;
}

//int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== tcp_recvmsg id=%d sock=%llx ===", id, sk);

    // Important: We must work here to remember the iovec pointer, since the msghdr structure
    // can get modified in non-reversible way if the incoming packet is large and broken down in parts. 
    recv_args_t args = {
        .sock_ptr = (u64)sk,
        .iovec_ptr = (u64)find_msghdr_buf(msg)
    };

    bpf_map_update_elem(&active_recv_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kretprobe_tcp_recvmsg, int copied_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    recv_args_t *args = bpf_map_lookup_elem(&active_recv_args, &id);

    if (!args || (copied_len <= 0)) {
        goto done;
    }

    bpf_dbg_printk("=== tcp_recvmsg ret id=%d sock=%llx copied_len %d ===", id, args->sock_ptr, copied_len);

    if (!args->iovec_ptr) {
        bpf_dbg_printk("iovec_ptr found in kprobe is NULL, ignoring this tcp_recvmsg");
    }

    pid_connection_info_t info = {};

    if (parse_sock_info((struct sock *)args->sock_ptr, &info.conn)) {
        sort_connection_info(&info.conn);
        //dbg_print_http_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);
        handle_buf_with_connection(&info, (void *)args->iovec_ptr, copied_len, 0);
    }

done:
    bpf_map_delete_elem(&active_recv_args, &id);

    return 0;
}

// Fall-back in case we don't see kretprobe on tcp_recvmsg in high network volume situations
SEC("socket/http_filter")
int socket__http_filter(struct __sk_buff *skb) {
    protocol_info_t tcp = {};
    connection_info_t conn = {};

    http_info_t info = {0};

    u8 hlen = 0;
    u8 tcp_opt_type = 0;
    u8 read_off = 0;
    u16 tot_len = 0;
    u16 h_proto = 0;

    if (!read_sk_buff_opt(skb, &tcp, &conn, &hlen, &tcp_opt_type, &read_off, &tot_len, &h_proto)) {
        return 0;
    }

    if (0 && !tcp.flags) {
        bpf_dbg_printk("SYN packed len = %d", skb->len);

        bpf_skb_load_bytes(skb, tcp.hdr_len, &info.buf, sizeof(info.buf));

        s32 len = skb->len-2;
        bpf_clamp_umax(len, FULL_BUF_SIZE);

        if (len > 2 && len < (FULL_BUF_SIZE-2)) {
            bpf_printk("AAA: %x", info.buf[len]);
            bpf_printk("BBB: %x", info.buf[len+1]);
        }
    }

    // ignore ACK packets
    if (tcp_ack(&tcp)) {
        return 0;
    }

    // ignore empty packets, unless it's TCP FIN or TCP RST
    if (!tcp_close(&tcp) && tcp_empty(&tcp, skb)) {
        return 0;
    }

    // sorting must happen here, before we check or set dups
    sort_connection_info(&conn);
    
    // we don't want to read the whole buffer for every packed that passes our checks, we read only a bit and check if it's trully HTTP request/response.
    unsigned char buf[MIN_HTTP_SIZE] = {0};
    bpf_skb_load_bytes(skb, tcp.hdr_len, (void *)buf, sizeof(buf));
    // technically the read should be reversed, but eBPF verifier complains on read with variable length
    u32 len = skb->len - tcp.hdr_len;
    if (len > MIN_HTTP_SIZE) {
        len = MIN_HTTP_SIZE;
    }

    u8 packet_type = 0;
    if (is_http(buf, len, &packet_type)) { // we must check tcp_close second, a packet can be a close and a response
        info.conn_info = conn;

        if (packet_type == PACKET_TYPE_REQUEST) {
            u32 full_len = skb->len - tcp.hdr_len;
            bpf_clamp_umax(full_len, FULL_BUF_SIZE-4);

            read_skb_bytes(skb, tcp.hdr_len, info.buf, FULL_BUF_SIZE);
            bpf_printk("seq = %d ack = %d | %s", tcp.seq, tcp.ack, info.buf);

            u32 data = 0;
            bpf_skb_load_bytes(skb, read_off, &data, sizeof(data));
            bpf_printk("options %llx", data);

            u32 t_id = 0;
            u32 s_id = 0;
            if (hlen >= 32 && tcp_opt_type == 1) {
                bpf_skb_load_bytes(skb, read_off, &t_id, sizeof(t_id));
                bpf_skb_load_bytes(skb, read_off + 4, &s_id, sizeof(s_id));
            }

            bpf_dbg_printk("=== http_filter len=%d t_id:%x s_id:%x %s ===", len, t_id, s_id, buf);
            //dbg_print_http_connection_info(&conn);
            set_fallback_http_info(&info, &conn, skb->len - tcp.hdr_len);
        } else if (packet_type) {
            bpf_printk("RESP seq = %d ack = %d", tcp.seq, tcp.ack);
        }
    }

    return 0;
}

/*
    The tracking of the clones is complicated by the fact that in container environments
    the tid returned by the sys_clone call is the namespaced tid, not the host tid which 
    bpf sees normally. To mitigate this we work exclusively with namespaces. Only the clone_map
    and server_traces are keyed off the namespace:pid.
*/
SEC("kretprobe/sys_clone")
int BPF_KRETPROBE(kretprobe_sys_clone, int tid) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || tid < 0) {
        return 0;
    }

    pid_key_t parent = {0};
    task_tid(&parent);

    pid_key_t child = {
        .pid = (u32)tid,
        .ns = parent.ns,
    };

    bpf_dbg_printk("sys_clone_ret %d -> %d", id, tid);
    bpf_map_update_elem(&clone_map, &child, &parent, BPF_ANY);
    
    return 0;
}

SEC("kprobe/sys_exit")
int BPF_KPROBE(kprobe_sys_exit, int status) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    pid_key_t task = {0};
    task_tid(&task);

    bpf_dbg_printk("sys_exit %d, pid=%d, valid_pid(id)=%d", id, pid_from_pid_tgid(id), valid_pid(id));
    bpf_map_delete_elem(&clone_map, &task);
    bpf_map_delete_elem(&server_traces, &task);
    
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, u8);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} existing_requests SEC(".maps");

SEC("tc_egress")
int egress_http(struct __sk_buff *skb) {
    protocol_info_t tcp = {};
    connection_info_t conn = {};
    u8 hlen = 0;
    u8 tcp_opt_type = 0;
    u8 write_off = 0;
    u16 tot_len = 0;
    u16 h_proto = 0;

    if (!read_sk_buff_opt(skb, &tcp, &conn, &hlen, &tcp_opt_type, &write_off, &tot_len, &h_proto)) {
        return 0;
    }

    //bpf_dbg_printk("TCP flags %x, seq %d, skb->len %d", tcp.flags, tcp.seq, skb->len);
    
    // sorting must happen here, before we check or set dups
    sort_connection_info(&conn);
    //dbg_print_http_connection_info(&conn);

    if (0 && !tcp.flags) {
        bpf_dbg_printk("SYN packed len = %d", skb->len);

        u8* exists = bpf_map_lookup_elem(&existing_requests, &conn);
        if (!exists) {
            u8 set=1;
            u8 val=0xba;

            uint16_t pkt_end = skb->data_end - skb->data;
            bpf_printk("Changing tail and setting data on syn, end=%d", pkt_end);
            bpf_skb_change_tail(skb, pkt_end + 1, 0);
            bpf_skb_store_bytes(skb, pkt_end, &val, sizeof(u8), 0);

            u32 offset_ip_tot_len = 0;
            u32 offset_ip_checksum = 0;
            if (h_proto == ETH_P_IP) {
                offset_ip_tot_len = ETH_HLEN + offsetof(struct iphdr, tot_len);
                offset_ip_checksum = ETH_HLEN + offsetof(struct iphdr, check);
            } else {
                offset_ip_tot_len = ETH_HLEN + offsetof(struct ipv6hdr, payload_len);
            }            

            u16 new_tot_len = bpf_htons(bpf_ntohs(tot_len) + 1);

            bpf_printk("tot_len = %d, tot_len_alt = %d, new_tot_len = %d, new_tot_len_alt = %d, h_proto = %d, skb->len = %d", tot_len, bpf_ntohs(tot_len), new_tot_len, bpf_ntohs(new_tot_len), h_proto, skb->len);

            if (offset_ip_checksum) {
                bpf_l3_csum_replace(skb, offset_ip_checksum, tot_len, new_tot_len, sizeof(u16));
            }

            bpf_skb_store_bytes(skb, offset_ip_tot_len, &new_tot_len, sizeof(u16), 0);

            bpf_map_update_elem(&existing_requests, &conn, &set, BPF_ANY);
        } else {
            bpf_dbg_printk("already seen");
        }
    }

    // ignore ACK packets
    if (tcp_ack(&tcp)) {
        return 0;
    }

    if (tcp_close(&tcp)) {
        bpf_map_delete_elem(&existing_requests, &conn);
    }

    // ignore empty packets, unless it's TCP FIN or TCP RST
    if (!tcp_close(&tcp) && tcp_empty(&tcp, skb)) {
        return 0;
    }

    // we don't want to read the whole buffer for every packed that passes our checks, we read only a bit and check if it's trully HTTP request/response.
    unsigned char buf[MIN_HTTP_SIZE] = {0};
    bpf_skb_load_bytes(skb, tcp.hdr_len, (void *)buf, sizeof(buf));
    // technically the read should be reversed, but eBPF verifier complains on read with variable length
    u32 len = skb->len - tcp.hdr_len;
    if (len > MIN_HTTP_SIZE) {
        len = MIN_HTTP_SIZE;
    }

    u8 packet_type = 0;
    if (is_http(buf, len, &packet_type)) { // we must check tcp_close second, a packet can be a close and a response
        if (packet_type == PACKET_TYPE_REQUEST) {
            bpf_dbg_printk("tc_egress http TCP packet seq = %d ack = %d options_len = %d", tcp.seq, tcp.ack, tcp.hdr_len - write_off);
            //u8 data = 'P';

            s32 options_len = tcp.hdr_len - write_off;
            if (options_len > 0) {
                u8 data = 0;
                bpf_skb_load_bytes(skb, write_off, &data, sizeof(data));
                bpf_printk("options %llx", data);

                if (data == 0x01) { // nop
                    u32 new_data = 0x00aa010f;
                    bpf_skb_store_bytes(skb, write_off, &new_data, sizeof(u32), 0);
                }
            }

            //uint16_t pkt_end = skb->data_end - skb->data;
            //bpf_printk("Changing tail and setting data on syn, end=%d", pkt_end);
            //bpf_skb_change_tail(skb, pkt_end + 1, 0);
            //bpf_skb_store_bytes(skb, pkt_end, &data, sizeof(u8), 0);

            //u32 offset_ip_tot_len = 0;
            //u32 offset_ip_checksum = 0;
            //if (h_proto == ETH_P_IP) {
            //    offset_ip_tot_len = ETH_HLEN + offsetof(struct iphdr, tot_len);
            //    offset_ip_checksum = ETH_HLEN + offsetof(struct iphdr, check);
            //} else {
            //    offset_ip_tot_len = ETH_HLEN + offsetof(struct ipv6hdr, payload_len);
            //}            

            u16 new_tot_len = bpf_htons(bpf_ntohs(tot_len) + 1);

            bpf_printk("tot_len = %d, tot_len_alt = %d, new_tot_len = %d, new_tot_len_alt = %d, h_proto = %d, skb->len = %d", tot_len, bpf_ntohs(tot_len), new_tot_len, bpf_ntohs(new_tot_len), h_proto, skb->len);

            //if (offset_ip_checksum) {
            //    bpf_l3_csum_replace(skb, offset_ip_checksum, tot_len, new_tot_len, sizeof(u16));
            //}

            //bpf_skb_store_bytes(skb, offset_ip_tot_len, &new_tot_len, sizeof(u16), 0);

            //bpf_map_update_elem(&existing_requests, &conn, &set, BPF_ANY);

            //bpf_skb_store_bytes(skb, tcp.hdr_len, &data, sizeof(u8), 0);       

            if (hlen >= 32 && tcp_opt_type == 1) {
                // u32 t_id = bpf_get_prandom_u32();
                // u32 s_id = bpf_get_prandom_u32();

                // bpf_skb_change_tail(skb, skb->len + 1, 0);
                // bpf_skb_pull_data(skb, 0);

                // u32 offset_ip_tot_len = 0;
                // u32 offset_ip_checksum = 0;
                // if (h_proto == ETH_P_IP) {
                //     offset_ip_tot_len = ETH_HLEN + offsetof(struct iphdr, tot_len);
                //     offset_ip_checksum = ETH_HLEN + offsetof(struct iphdr, check);
                // } else {
                //     offset_ip_tot_len = ETH_HLEN + offsetof(struct ipv6hdr, payload_len);
                // }            

                // u16 new_tot_len = bpf_htons(bpf_ntohs(tot_len) + 1);

                // bpf_printk("tot_len = %d, tot_len_alt = %d, new_tot_len = %d, new_tot_len_alt = %d, h_proto = %d, skb->len = %d", tot_len, bpf_ntohs(tot_len), new_tot_len, bpf_ntohs(new_tot_len), h_proto, skb->len);

                // if (offset_ip_checksum) {
                //     bpf_l3_csum_replace(skb, offset_ip_checksum, tot_len, new_tot_len, sizeof(u16));
                // }

                // bpf_skb_store_bytes(skb, offset_ip_tot_len, &new_tot_len, sizeof(u16), 0);
                // u8 val = 0x20;
                // bpf_skb_store_bytes(skb, skb->len-1, &val, sizeof(u8), 0);

                //u32 flags = 0xff;

                //bpf_skb_store_bytes(skb, write_off-1, &flags, sizeof(u8), 0);
                //u16 flags = 0xbaba;
                //bpf_skb_store_bytes(skb, write_off, &flags, sizeof(u32), 0);
                //bpf_l4_csum_replace(skb, write_off, tcp.ack, flags, sizeof(u32));
                //bpf_skb_store_bytes(skb, write_off+4, &s_id, sizeof(u32), 0);
                //bpf_printk("Storing t_id=%x, s_id=%x", t_id, s_id);
            }
        }
    }

    return 0;
}