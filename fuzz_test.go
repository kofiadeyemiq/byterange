package byterange

import (
	"errors"
	"testing"
)

// FuzzParse checks that Parse never panics and, whenever it returns a
// result, that result actually satisfies Parse's documented contract:
// every range is within [0, size), ascending, and every returned error is
// one of the package's declared sentinels.
func FuzzParse(f *testing.F) {
	seeds := []struct {
		header string
		size   int64
	}{
		{"bytes=0-499", 10000},
		{"bytes=500-999", 10000},
		{"bytes=-500", 10000},
		{"bytes=9500-", 10000},
		{"bytes=0-0,-1", 10000},
		{"bytes= 0-999, 4500-5499, -1000", 10000},
		{"bytes=500-600,601-999", 10000},
		{"items=0-5", 100},
		{"BYTES=0-5", 100},
		{"bytes=", 100},
		{"bytes=5-4", 100},
		{"bytes=abc-def", 100},
		{"bytes=-0", 100},
		{"bytes=0-0", 0},
		{"bytes=-1", 0},
		{"", 100},
		{"bytes", 100},
		{"bytes=99999999999999999999999999999999999999-", 100},
		{"bytes=0-99999999999999999999999999999999999999", 100},
		{"bytes=-99999999999999999999999999999999999999", 100},
		{"bytes=0-99,50-149,200-299", 1000},
		{"bytes=0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0", 1000},
		{"bytes=0-1, ,2-3", 1000},
		{"bytes=,0-4", 1000},
		{"bytes=0-4,", 1000},
		{"bytes=,", 1000},
		{"bytes=,,,", 1000},
		{"bytes=,   ,", 1000},
	}
	for _, s := range seeds {
		f.Add(s.header, s.size)
	}

	f.Fuzz(func(t *testing.T, header string, size int64) {
		if size < -1<<32 || size > 1<<32 {
			// Keep sizes in a range where int64 arithmetic inside Parse
			// cannot itself overflow, so any overflow the fuzzer finds is
			// attributable to Parse rather than to an unrealistic size
			// this package makes no claims about.
			t.Skip()
		}

		ranges, err := Parse(header, size)
		if size < 0 {
			if err == nil {
				t.Fatalf("Parse(%q, %d): want error for negative size", header, size)
			}
			return
		}

		if err != nil {
			switch {
			case errors.Is(err, ErrUnsupportedUnit),
				errors.Is(err, ErrMalformed),
				errors.Is(err, ErrTooManyRanges),
				errors.Is(err, ErrRangesTooLarge),
				errors.Is(err, ErrUnsatisfiable):
				// documented outcome
			default:
				t.Fatalf("Parse(%q, %d) returned an undocumented error: %v", header, size, err)
			}
			if ranges != nil {
				t.Fatalf("Parse(%q, %d) returned a non-nil Ranges alongside an error", header, size)
			}
			return
		}

		if len(ranges) == 0 {
			t.Fatalf("Parse(%q, %d) returned no error and no ranges", header, size)
		}
		for i, r := range ranges {
			if r.Start < 0 || r.End < r.Start-1 {
				t.Fatalf("Parse(%q, %d)[%d] = %v: malformed range", header, size, i, r)
			}
			if size > 0 && r.End >= size {
				t.Fatalf("Parse(%q, %d)[%d] = %v: End >= size", header, size, i, r)
			}
			if i > 0 && r.Start <= ranges[i-1].End {
				t.Fatalf("Parse(%q, %d) not strictly ascending/non-overlapping after coalescing at index %d: %v", header, size, i, ranges)
			}
		}
	})
}
