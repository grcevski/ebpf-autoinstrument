// Copyright The OpenTelemetry Authors
//
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
#include "stdbool.h"
#include "bpf_dbg.h"
#include "bpf_helpers.h"
#include "http_trace.h"

#define MAX_BUCKETS 8
#define W3C_KEY_LENGTH 11
#define W3C_VAL_LENGTH 55

#define MAX_REALLOCATION 400
#define MAX_DATA_SIZE 400

#define OFFSET_OF_GO_RUNTIME_HMAP_FIELD_B 9
#define OFFSET_OF_GO_RUNTIME_HMAP_FIELD_BUCKETS 16

#define TRACE_ID_STRING_SIZE 32
#define SPAN_ID_STRING_SIZE 16

struct go_string
{
    char *str;
    s64 len;
};

struct go_slice
{
    void *array;
    s64 len;
    s64 cap;
};

struct go_slice_user_ptr
{
    void *array;
    void *len;
    void *cap;
};

struct go_iface
{
    void *tab;
    void *data;
};

struct map_bucket {
    char tophash[8];
    struct go_string keys[8];
    struct go_slice values[8];
    void *overflow;
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct map_bucket));
    __uint(max_entries, 1);
} golang_mapbucket_storage_map SEC(".maps");

// assumes s2 is all lowercase
static __always_inline int bpf_memicmp(char *s1, char *s2, s32 size)
{
    for (int i = 0; i < size; i++)
    {
        if (s1[i] != s2[i] && s1[i] != (s2[i] - 32)) // compare with each uppercase character
        {
            return i+1;
        }
    }

    return 0;
}

static __always_inline void *extract_traceparent_from_req_headers(void *headers_ptr_ptr)
{
    void *headers_ptr;
    long res;
    res = bpf_probe_read(&headers_ptr, sizeof(headers_ptr), headers_ptr_ptr);
    if (res < 0)
    {
        return NULL;
    }
    u64 headers_count = 0;
    res = bpf_probe_read(&headers_count, sizeof(headers_count), headers_ptr);
    if (res < 0)
    {
        return NULL;
    }
    if (headers_count == 0)
    {
        return NULL;
    }
    unsigned char log_2_bucket_count;
    res = bpf_probe_read(&log_2_bucket_count, sizeof(log_2_bucket_count), headers_ptr + OFFSET_OF_GO_RUNTIME_HMAP_FIELD_B);
    if (res < 0)
    {
        return NULL;
    }
    u64 bucket_count = 1 << log_2_bucket_count;
    void *header_buckets;
    res = bpf_probe_read(&header_buckets, sizeof(header_buckets), headers_ptr + OFFSET_OF_GO_RUNTIME_HMAP_FIELD_BUCKETS);
    if (res < 0)
    {
        return NULL;
    }
    u32 map_id = 0;
    struct map_bucket *map_value = bpf_map_lookup_elem(&golang_mapbucket_storage_map, &map_id);
    if (!map_value)
    {
        return NULL;
    }

    for (u64 j = 0; j < MAX_BUCKETS; j++)
    {
        if (j >= bucket_count)
        {
            break;
        }
        res = bpf_probe_read(map_value, sizeof(struct map_bucket), header_buckets + (j * sizeof(struct map_bucket)));
        if (res < 0)
        {
            continue;
        }
        for (u64 i = 0; i < 8; i++)
        {
            if (map_value->tophash[i] == 0)
            {
                continue;
            }
            if (map_value->keys[i].len != W3C_KEY_LENGTH)
            {
                continue;
            }
            char current_header_key[W3C_KEY_LENGTH];
            bpf_probe_read(current_header_key, sizeof(current_header_key), map_value->keys[i].str);        
            if (bpf_memicmp(current_header_key, "traceparent", W3C_KEY_LENGTH)) // grpc headers don't get normalized
            {
                continue;
            }
            void *traceparent_header_value_ptr = map_value->values[i].array;
            struct go_string traceparent_header_value_go_str;
            res = bpf_probe_read(&traceparent_header_value_go_str, sizeof(traceparent_header_value_go_str), traceparent_header_value_ptr);
            if (res < 0)
            {
                return NULL;
            }
            if (traceparent_header_value_go_str.len != W3C_VAL_LENGTH)
            {
                continue;
            }
            return traceparent_header_value_go_str.str;
        }
    }
    return NULL;
}

static __always_inline void generate_random_bytes(unsigned char *buff, u32 size)
{
    for (int i = 0; i < (size / 4); i++)
    {
        u32 random = bpf_get_prandom_u32();
        buff[(4 * i)] = (random >> 24) & 0xFF;
        buff[(4 * i) + 1] = (random >> 16) & 0xFF;
        buff[(4 * i) + 2] = (random >> 8) & 0xFF;
        buff[(4 * i) + 3] = random & 0xFF;
    }
}

char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static __always_inline void bytes_to_hex_string(unsigned char *pin, u32 size, unsigned char *out)
{
    unsigned char *pout = out;
    for (u32 i = 0; i < size; i++)
    {
        *pout++ = hex[(*pin >> 4) & 0xF];
        *pout++ = hex[(*pin++) & 0xF];
    }
}

static __always_inline void hex_string_to_bytes(char *str, u32 size, unsigned char *out)
{
    for (int i = 0; i < (size / 2); i++)
    {
        char ch0 = str[2 * i];
        char ch1 = str[2 * i + 1];
        u8 nib0 = (ch0 & 0xF) + (ch0 >> 6) | ((ch0 >> 3) & 0x8);
        u8 nib1 = (ch1 & 0xF) + (ch1 >> 6) | ((ch1 >> 3) & 0x8);
        out[i] = (nib0 << 4) | nib1;
    }
}

static __always_inline struct span_context generate_span_context()
{
    struct span_context context = {};
    generate_random_bytes(context.TraceID, TRACE_ID_SIZE);
    generate_random_bytes(context.SpanID, SPAN_ID_SIZE);
    return context;
}

static __always_inline void span_context_to_w3c_string(struct span_context *ctx, unsigned char *buff)
{
    // W3C format: version (2 chars) - trace id (32 chars) - span id (16 chars) - sampled (2 chars)
    unsigned char *out = buff;

    // Write version
    *out++ = '0';
    *out++ = '0';
    *out++ = '-';

    // Write trace id
    bytes_to_hex_string(ctx->TraceID, TRACE_ID_SIZE, out);
    out += TRACE_ID_STRING_SIZE;
    *out++ = '-';

    // Write span id
    bytes_to_hex_string(ctx->SpanID, SPAN_ID_SIZE, out);
    out += SPAN_ID_STRING_SIZE;
    *out++ = '-';

    // Write sampled
    *out++ = '0';
    *out = '1';
}

static __always_inline void w3c_string_to_span_context(char *str, struct span_context *ctx)
{
    u32 trace_id_start_pos = 3;
    u32 span_id_start_pod = 36;
    hex_string_to_bytes(str + trace_id_start_pos, TRACE_ID_STRING_SIZE, ctx->TraceID);
    hex_string_to_bytes(str + span_id_start_pod, SPAN_ID_STRING_SIZE, ctx->SpanID);
}

static __always_inline void copy_byte_arrays(unsigned char *dst, unsigned char *src, u32 size)
{
    for (int i = 0; i < size; i++)
    {
        dst[i] = src[i];
    }
}