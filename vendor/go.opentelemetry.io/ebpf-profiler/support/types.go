// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// support maps the definitions from headers in the C world into a nice go way
package support // import "go.opentelemetry.io/ebpf-profiler/support"

import "fmt"

const (
	FrameMarkerUnknown  = 0
	FrameMarkerErrorBit = 0x80
	FrameMarkerPython   = 1
	FrameMarkerNative   = 3
	FrameMarkerPHP      = 2
	FrameMarkerPHPJIT   = 9
	FrameMarkerKernel   = 4
	FrameMarkerHotSpot  = 5
	FrameMarkerRuby     = 6
	FrameMarkerPerl     = 7
	FrameMarkerV8       = 8
	FrameMarkerDotnet   = 10
	FrameMarkerAbort    = (0x7F | 0x80)
)

const (
	ProgUnwindStop    = 1
	ProgUnwindNative  = 2
	ProgUnwindHotspot = 3
	ProgUnwindPython  = 4
	ProgUnwindPHP     = 5
	ProgUnwindRuby    = 6
	ProgUnwindPerl    = 7
	ProgUnwindV8      = 8
	ProgUnwindDotnet  = 9
)

const (
	DeltaCommandFlag = 0x8000

	MergeOpcodeNegative = 0x80
)

const (
	EventTypeGenericPID = 1
)

const MaxFrameUnwinds = 128

const (
	MetricIDBeginCumulative = 1
)

const (
	BitWidthPID  = 32
	BitWidthPage = 64
)

// EncodeBiasAndUnwindProgram encodes a bias_and_unwind_program value (for C.PIDPageMappingInfo)
// from a bias and unwind program values.
// This currently assumes a non-negative bias: this encoding may have to be changed if bias can be
// negative.
func EncodeBiasAndUnwindProgram(bias uint64,
	unwindProgram uint8) (uint64, error) {
	if (bias >> 56) > 0 {
		return 0, fmt.Errorf("unsupported bias value (too large): 0x%x", bias)
	}
	return bias | (uint64(unwindProgram) << 56), nil
}

// DecodeBiasAndUnwindProgram decodes the contents of the `bias_and_unwind_program` field in
// C.PIDPageMappingInfo and returns the corresponding bias and unwind program.
func DecodeBiasAndUnwindProgram(biasAndUnwindProgram uint64) (bias uint64, unwindProgram uint8) {
	bias = biasAndUnwindProgram & 0x00FFFFFFFFFFFFFF
	unwindProgram = uint8(biasAndUnwindProgram >> 56)
	return bias, unwindProgram
}

const (
	// StackDeltaBucket[Smallest|Largest] define the boundaries of the bucket sizes of the various
	// nested stack delta maps.
	StackDeltaBucketSmallest = 8
	StackDeltaBucketLargest  = 21

	// StackDeltaPage[Bits|Mask] determine the paging size of stack delta map information
	StackDeltaPageBits = 16
	StackDeltaPageMask = (1 << 16) - 1
)

const (
	HSTSIDIsStubBit       = 63
	HSTSIDHasFrameBit     = 62
	HSTSIDStackDeltaBit   = 56
	HSTSIDStackDeltaMask  = ((1 << 6) - 1)
	HSTSIDStackDeltaScale = 8
	HSTSIDSegMapBit       = 0
	HSTSIDSegMapMask      = ((1 << 56) - 1)
)

const (
	// PerfMaxStackDepth is the bpf map data array length for BPF_MAP_TYPE_STACK_TRACE traces
	PerfMaxStackDepth = 127
)

const (
	TraceOriginUnknown  = 0
	TraceOriginSampling = 1
	TraceOriginOffCPU   = 2
)

const OffCPUThresholdMax = 20
