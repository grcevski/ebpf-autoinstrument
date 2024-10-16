package pipe

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/goexec"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/grafana/ebpf-autoinstrument/test/collector"
)

const testTimeout = 5 * time.Second

func TestBasicPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{Metrics: otel.MetricsConfig{MetricsEndpoint: tc.ServerHostPort, ReportTarget: true, ReportPeerInfo: true}})
	gb.inspector = func(_ string, _ []string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- nethttp.HTTPRequestTrace) {
			out <- newRequest("GET", "/foo/bar", "1.1.1.1:3456", 404)
		}
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := getEvent(t, tc)
	assert.Equal(t, collector.MetricRecord{
		Name: "duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):      "GET",
			string(semconv.HTTPStatusCodeKey):  "404",
			string(semconv.HTTPTargetKey):      "/foo/bar",
			string(semconv.NetSockPeerAddrKey): "1.1.1.1",
		},
		Type: pmetric.MetricTypeHistogram,
	}, event)
}

func TestTracerPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{Traces: otel.TracesConfig{TracesEndpoint: tc.ServerHostPort, ServiceName: "test"}})
	gb.inspector = func(_ string, _ []string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- nethttp.HTTPRequestTrace) {
			out <- newRequest("GET", "/foo/bar", "1.1.1.1:3456", 404)
		}
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := getTraceEvent(t, tc)
	assert.Equal(t, collector.TraceRecord{
		Name: "session",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):      "GET",
			string(semconv.HTTPStatusCodeKey):  "404",
			string(semconv.HTTPTargetKey):      "/foo/bar",
			string(semconv.NetSockPeerAddrKey): "1.1.1.1",
			string(semconv.NetHostNameKey):     getHostname(),
			string(semconv.NetHostPortKey):     "8080",
		},
		Kind: ptrace.SpanKindInternal,
	}, event)
}

func TestRouteConsolidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{
		Metrics: otel.MetricsConfig{MetricsEndpoint: tc.ServerHostPort}, // ReportPeerInfo = false, no peer info
		Routes:  &transform.RoutesConfig{Patterns: []string{"/user/{id}", "/products/{id}/push"}},
	})
	gb.inspector = func(_ string, _ []string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- nethttp.HTTPRequestTrace) {
			out <- newRequest("GET", "/user/1234", "1.1.1.1:3456", 200)
			out <- newRequest("GET", "/products/3210/push", "1.1.1.1:3456", 200)
			out <- newRequest("GET", "/attach", "1.1.1.1:3456", 200) // undefined route: won't report as route
		}
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	// expect to receive 3 events without any guaranteed order
	events := map[string]collector.MetricRecord{}
	for i := 0; i < 3; i++ {
		ev := getEvent(t, tc)
		events[ev.Attributes[string(semconv.HTTPRouteKey)]] = ev
	}

	assert.Equal(t, collector.MetricRecord{
		Name: "duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "/user/{id}",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/user/{id}"])

	assert.Equal(t, collector.MetricRecord{
		Name: "duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "/products/{id}/push",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/products/{id}/push"])

	assert.Equal(t, collector.MetricRecord{
		Name: "duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "*",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["*"])
}

func newRequest(method, path, peer string, status int) nethttp.HTTPRequestTrace {
	rt := nethttp.HTTPRequestTrace{}
	copy(rt.Path[:], path)
	copy(rt.Method[:], method)
	copy(rt.RemoteAddr[:], peer)
	copy(rt.Host[:], getHostname()+":8080")
	rt.Status = uint16(status)
	return rt
}

func getEvent(t *testing.T, coll *collector.TestCollector) collector.MetricRecord {
	t.Helper()
	select {
	case ev := <-coll.Records:
		return ev
	case <-time.After(testTimeout):
		t.Fatal("timeout while waiting for message")
	}
	return collector.MetricRecord{}
}

func getTraceEvent(t *testing.T, coll *collector.TestCollector) collector.TraceRecord {
	t.Helper()
	select {
	case ev := <-coll.TraceRecords:
		return ev
	case <-time.After(testTimeout):
		t.Fatal("timeout while waiting for message")
	}
	return collector.TraceRecord{}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}
