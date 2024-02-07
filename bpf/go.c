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
#include "go_grpc.h"

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

/* HTTP Client */

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

/* HTTP 2.0 Server */
SEC("uprobe/http2ResponseWriterStateWriteHeader")
int uprobe_http2ResponseWriterStateWriteHeader(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 responseWriterState writeHeader === ");
    return writeHeaderHelper(ctx, rws_req_pos);
}

/* HTTP 2.0 client support */
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

/* GRPC */

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream(struct pt_regs *ctx) {
    grpc_server_handleStream_start(ctx);
    return 0;
}

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream_return(struct pt_regs *ctx) {
    return grpc_server_handleStream_end(ctx);
}

SEC("uprobe/transport_writeStatus")
int uprobe_transport_writeStatus(struct pt_regs *ctx) {
    grpc_transport_writeStatus_start(ctx);
    return 0;
}

SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke(struct pt_regs *ctx) {
    grpc_ClientConn_Invoke_start(ctx);
    return 0;
}

// Same as ClientConn_Invoke, registers for the method are offset by one
SEC("uprobe/ClientConn_NewStream")
int uprobe_ClientConn_NewStream(struct pt_regs *ctx) {
    grpc_ClientConn_NewStream_start(ctx);
    return 0;
}

SEC("uprobe/ClientConn_Close")
int uprobe_ClientConn_Close(struct pt_regs *ctx) {
    grpc_ClientConn_Close_start(ctx);
    return 0;
}

SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke_return(struct pt_regs *ctx) {
    return grpc_ClientConn_Invoke_end(ctx);
}

// The gRPC client stream is written on another goroutine in transport loopyWriter (controlbuf.go).
// We extract the stream ID when it's just created and make a mapping of it to our goroutine that's executing ClientConn.Invoke.
SEC("uprobe/transport_http2Client_NewStream")
int uprobe_transport_http2Client_NewStream(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    grpc_transport_http2Client_NewStream_start(ctx);
#endif    
    return 0;
}

// LoopyWriter is about to write the headers, we lookup to see if this StreamID (first argument after the receiver)
// to see if it has a ClientConn.Invoke mapping. If we find one, we duplicate the invocation metadata on the loopyWriter
// goroutine.
SEC("uprobe/transport_loopyWriter_writeHeader")
int uprobe_transport_loopyWriter_writeHeader(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    grpc_transport_loopyWriter_writeHeader_start(ctx);
#endif
    return 0;
}

SEC("uprobe/transport_loopyWriter_writeHeader_return")
int uprobe_transport_loopyWriter_writeHeader_return(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    grpc_transport_loopyWriter_writeHeader_end(ctx);
#endif
    return 0;
}

SEC("uprobe/hpack_Encoder_WriteField")
int uprobe_hpack_Encoder_WriteField(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    return grpc_hpack_Encoder_WriteField_start(ctx);
#endif
    return 0;
}



