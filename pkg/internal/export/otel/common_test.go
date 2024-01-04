package otel

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/svc"
)

func TestOtlpOptions_AsMetricHTTP(t *testing.T) {
	type testCase struct {
		in  otlpOptions
		len int
	}
	testCases := []testCase{
		{in: otlpOptions{Endpoint: "foo"}, len: 1},
		{in: otlpOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo"}, len: 2},
		{in: otlpOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo", SkipTLSVerify: true}, len: 3},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo", Insecure: true, SkipTLSVerify: true}, len: 4},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Equal(t, tc.len, len(tc.in.AsMetricHTTP()))
		})
	}
}

func TestOtlpOptions_AsMetricGRPC(t *testing.T) {
	type testCase struct {
		in  otlpOptions
		len int
	}
	testCases := []testCase{
		{in: otlpOptions{Endpoint: "foo"}, len: 1},
		{in: otlpOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Equal(t, tc.len, len(tc.in.AsMetricGRPC()))
		})
	}
}

func TestOtlpOptions_AsTraceHTTP(t *testing.T) {
	type testCase struct {
		in  otlpOptions
		len int
	}
	testCases := []testCase{
		{in: otlpOptions{Endpoint: "foo"}, len: 1},
		{in: otlpOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo"}, len: 2},
		{in: otlpOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo", SkipTLSVerify: true}, len: 3},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo", Insecure: true, SkipTLSVerify: true}, len: 4},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Equal(t, tc.len, len(tc.in.AsTraceHTTP()))
		})
	}
}

func TestOtlpOptions_AsTraceGRPC(t *testing.T) {
	type testCase struct {
		in  otlpOptions
		len int
	}
	testCases := []testCase{
		{in: otlpOptions{Endpoint: "foo"}, len: 1},
		{in: otlpOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Equal(t, tc.len, len(tc.in.AsTraceGRPC()))
		})
	}
}

func TestReporterPoolEviction(t *testing.T) {
	type fakeReporter struct {
		serviceID svc.ID
		evicted   bool
	}
	preconstructedReporters := map[svc.ID]*fakeReporter{
		svc.ID{Name: "r1"}: {serviceID: svc.ID{Name: "r1"}},
		svc.ID{Name: "r2"}: {serviceID: svc.ID{Name: "r2"}},
		svc.ID{Name: "r3"}: {serviceID: svc.ID{Name: "r3"}},
		svc.ID{Name: "r4"}: {serviceID: svc.ID{Name: "r4"}},
		svc.ID{Name: "r5"}: {serviceID: svc.ID{Name: "r5"}},
	}
	rp := NewReporterPool[*fakeReporter](
		3,
		func(key svc.ID, value *fakeReporter) {
			value.evicted = true
		},
		func(id svc.ID) (*fakeReporter, error) {
			return preconstructedReporters[id], nil
		},
	)
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		r, err := rp.For(svc.ID{Name: id})
		require.NoError(t, err)
		require.Equal(t, svc.ID{Name: id}, r.serviceID)
		require.False(t, r.evicted)
	}
	// r1 and r2 should be evicted. r3, r4, and r5 should haven't been evicted
	require.True(t, preconstructedReporters[svc.ID{Name: "r1"}].evicted)
	require.True(t, preconstructedReporters[svc.ID{Name: "r2"}].evicted)
	require.False(t, preconstructedReporters[svc.ID{Name: "r3"}].evicted)
	require.False(t, preconstructedReporters[svc.ID{Name: "r4"}].evicted)
	require.False(t, preconstructedReporters[svc.ID{Name: "r5"}].evicted)
	// after purging the reporter pool, all the components should have been evicted
	rp.Purge()
	for k, v := range preconstructedReporters {
		require.Truef(t, v.evicted, "reporter %s should have been evicted", k.Name)
	}
}
