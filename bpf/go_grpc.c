#include "go_grpc.h"

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
    grpc_server_handleStream_start(ctx);
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
