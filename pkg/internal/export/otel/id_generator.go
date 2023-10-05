package otel

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/grafana/beyla/pkg/internal/request"
	"go.opentelemetry.io/otel/trace"
)

type SpanContextIDGenerator struct{}
type RequestSpanKey struct{}
type RequestTraceKey struct{}

func ContextFromTraceSpan(parent context.Context, span *request.Span) context.Context {
	return context.WithValue(parent, RequestSpanKey{}, *span)
}

func ContextWithTraceID(parent context.Context, traceID trace.TraceID) context.Context {
	return context.WithValue(parent, RequestTraceKey{}, traceID)
}

func requestSpan(ctx context.Context) *request.Span {
	val := ctx.Value(RequestSpanKey{})
	if val == nil {
		return nil
	}

	holder, ok := val.(request.Span)
	if !ok {
		return nil
	}

	return &holder
}

func currentTraceID(ctx context.Context) *trace.TraceID {
	val := ctx.Value(RequestTraceKey{})
	if val == nil {
		return nil
	}

	holder, ok := val.(trace.TraceID)
	if !ok {
		return nil
	}

	return &holder
}

func randomTraceID() trace.TraceID {
	t := trace.TraceID{}

	for i := 0; i < len(t); i += 4 {
		binary.LittleEndian.PutUint32(t[i:], rand.Uint32())
	}

	return t
}

func randomSpanID() trace.SpanID {
	t := trace.SpanID{}

	for i := 0; i < len(t); i += 4 {
		binary.LittleEndian.PutUint32(t[i:], rand.Uint32())
	}

	return t
}

func (e *SpanContextIDGenerator) NewIDs(ctx context.Context) (trace.TraceID, trace.SpanID) {
	span := requestSpan(ctx)
	if span == nil || !trace.TraceID(span.TraceID).IsValid() || !trace.SpanID(span.SpanID).IsValid() {
		traceID := currentTraceID(ctx)
		if traceID != nil {
			return *traceID, randomSpanID()
		}
		fmt.Println("BAD BAD BAD")
		return randomTraceID(), randomSpanID()
	}

	return trace.TraceID(span.TraceID), trace.SpanID(span.SpanID)
}

func (e *SpanContextIDGenerator) NewSpanID(ctx context.Context, traceID trace.TraceID) trace.SpanID {
	span := requestSpan(ctx)
	if span == nil || !trace.SpanID(span.SpanID).IsValid() {
		fmt.Printf("I'm getting new random SpanID, this is OK\n")
		return randomSpanID()
	}

	return trace.SpanID(span.SpanID)
}
