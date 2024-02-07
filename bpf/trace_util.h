#ifndef TRACE_UTIL_H
#define TRACE_UTIL_H

// 55+13
#define TRACE_PARENT_HEADER_LEN 68
#define TRACE_ID_CHAR_LEN   32
#define SPAN_ID_CHAR_LEN    16
#define TRACE_ID_SIZE_BYTES 16
#define SPAN_ID_SIZE_BYTES   8
#define FLAGS_SIZE_BYTES     1
#define FLAGS_CHAR_LEN       2
#define TP_MAX_VAL_LENGTH   55
#define TP_MAX_KEY_LENGTH   11

typedef struct tp_info {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    unsigned char parent_id[SPAN_ID_SIZE_BYTES];
    u64 ts;
    u8  flags;
} tp_info_t;

static unsigned char *hex = (unsigned char *)"0123456789abcdef";
static unsigned char *reverse_hex = (unsigned char *)
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff" 
		"\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

static __always_inline void urand_bytes(unsigned char *buf, u32 size) {
    for (int i = 0; i < size; i += sizeof(u32)) {
        *((u32 *)&buf[i]) = bpf_get_prandom_u32();
    }
}

static __always_inline void decode_hex(unsigned char *dst, unsigned char *src, int src_len) {
    for (int i = 1, j = 0; i < src_len; i +=2) {
        unsigned char p = src[i-1];
        unsigned char q = src[i];

        unsigned char a = reverse_hex[p & 0xff];
        unsigned char b = reverse_hex[q & 0xff];

        a = a & 0x0f;
        b = b & 0x0f;

        dst[j++] = ((a << 4) | b) & 0xff;
    }
}

static __always_inline void encode_hex(unsigned char *dst, unsigned char *src, int src_len) {
    for (int i = 0, j = 0; i < src_len; i++) {
        unsigned char p = src[i];
        dst[j++] = hex[(p >> 4) & 0xff];
        dst[j++] = hex[p & 0x0f];
    }
}


static __always_inline bool is_traceparent(unsigned char *p) {
    if (((p[0] == 'T') || (p[0] == 't')) && (p[1] == 'r') && (p[2] == 'a') && (p[3] == 'c') && 
        (p[4] == 'e') && ((p[5] == 'p') || (p[5] == 'P')) && (p[6] == 'a') && (p[7] == 'r') &&
        (p[8] == 'e') && (p[9] == 'n') && (p[10] == 't') && (p[11] == ':') && (p[12] == ' ')
    ) {
        return true;
    }

    return false;
}

static __always_inline void make_tp_string(unsigned char *buf, tp_info_t *tp) {
    // Version
    *buf++ = '0'; *buf++ = '0'; *buf++ = '-';

    // TraceID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;
    *buf++ = '-';

    // SpanID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;
    *buf++ = '-';

    // Flags
    *buf++ = '0'; *buf = (tp->flags == 0) ? '0' : '1';
}

#endif