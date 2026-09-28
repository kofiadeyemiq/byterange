package byterange

import (
	"errors"
	"testing"
)

// TestParse_RFC9110Examples exercises the examples given verbatim in
// RFC 9110 §14.1.2 ("Byte Ranges"), for a representation of length 10000 as
// that section specifies.
func TestParse_RFC9110Examples(t *testing.T) {
	const size = 10000

	tests := []struct {
		name   string
		header string
		want   Ranges
	}{
		// "The first 500 bytes (byte offsets 0-499, inclusive): bytes=0-499"
		{"first 500 bytes", "bytes=0-499", Ranges{{0, 499}}},
		// "The second 500 bytes (byte offsets 500-999, inclusive): bytes=500-999"
		{"second 500 bytes", "bytes=500-999", Ranges{{500, 999}}},
		// "The final 500 bytes (byte offsets 9500-9999, inclusive): bytes=-500"
		{"final 500 bytes, suffix form", "bytes=-500", Ranges{{9500, 9999}}},
		// "Or: bytes=9500-"
		{"final 500 bytes, open form", "bytes=9500-", Ranges{{9500, 9999}}},
		// "The first and last bytes only (bytes 0 and 9999): bytes=0-0,-1"
		{"first and last byte", "bytes=0-0,-1", Ranges{{0, 0}, {9999, 9999}}},
		// "The first, middle, and last 1000 bytes: bytes= 0-999, 4500-5499, -1000"
		{"first, middle, last 1000 bytes", "bytes= 0-999, 4500-5499, -1000", Ranges{{0, 999}, {4500, 5499}, {9000, 9999}}},
		// "Other valid (but not canonical) specifications of the second 500
		// bytes (byte offsets 500-999, inclusive): bytes=500-600,601-999"
		// These two ranges are adjacent, so this package's default
		// coalescing merges them into the single range the RFC says they
		// specify.
		{"second 500 bytes, split and coalesced", "bytes=500-600,601-999", Ranges{{500, 999}}},
		// "bytes=500-700,601-999" — overlapping, also coalesced.
		{"second 500 bytes, overlapping and coalesced", "bytes=500-700,601-999", Ranges{{500, 999}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.header, size)
			if err != nil {
				t.Fatalf("Parse(%q, %d) error = %v, want nil", tt.header, size, err)
			}
			assertRangesEqual(t, got, tt.want)
		})
	}
}

func assertRangesEqual(t *testing.T, got, want Ranges) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d ranges %v, want %d ranges %v", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("range %d: got %v, want %v (full: got %v want %v)", i, got[i], want[i], got, want)
		}
	}
}

func TestParse_UnknownUnit(t *testing.T) {
	// RFC 9110 §14.2: "An origin server MUST ignore a Range header field
	// that contains a range unit it does not understand." Verified against
	// net/http.ServeContent's current (pre-fix) behavior for this same
	// input in TestStdlibComparison_UnknownUnit.
	for _, header := range []string{"items=0-5", "ITEMS=0-5", "pages=1-2"} {
		_, err := Parse(header, 100)
		if !errors.Is(err, ErrUnsupportedUnit) {
			t.Errorf("Parse(%q, 100) error = %v, want ErrUnsupportedUnit", header, err)
		}
	}
}

func TestParse_UnitCaseInsensitive(t *testing.T) {
	// RFC 9110 §14.1: "All range unit names are case-insensitive."
	for _, header := range []string{"bytes=0-4", "BYTES=0-4", "Bytes=0-4", "bYtEs=0-4"} {
		got, err := Parse(header, 100)
		if err != nil {
			t.Fatalf("Parse(%q, 100) error = %v", header, err)
		}
		assertRangesEqual(t, got, Ranges{{0, 4}})
	}
}

func TestParse_Malformed(t *testing.T) {
	// RFC 9110 §14.1.1: "An int-range is invalid if the last-pos value is
	// present and less than the first-pos" and "A ranges-specifier is
	// invalid if it contains any range-spec that is invalid ..." — so one
	// bad spec invalidates the whole set, not just that spec.
	headers := []string{
		"",
		"foo",
		"bytes",
		"bytes=",
		"bytes=,",
		"bytes=abc-500",
		"bytes=500-abc",
		"bytes=5-4",           // last < first
		"bytes=0-499,5-4",     // one good, one invalid: whole thing invalid
		"bytes=-",             // suffix with no digits
		"bytes=- 500",         // whitespace inside a number is not a digit sequence
		"bytes=0 -499",        // whitespace inside first-pos
		"bytes=0-499 500-999", // missing comma
		"bytes=1--5",          // double dash
	}
	for _, header := range headers {
		_, err := Parse(header, 1000)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%q, 1000) error = %v, want ErrMalformed", header, err)
		}
	}
}

func TestParse_Unsatisfiable(t *testing.T) {
	tests := []struct {
		name   string
		header string
		size   int64
	}{
		{"first-pos beyond size", "bytes=500-600", 100},
		{"first-pos equals size", "bytes=100-200", 100},
		{"suffix zero", "bytes=-0", 100},
		{"all specs beyond size", "bytes=500-600,700-800", 100},
		{"zero length representation, int-range", "bytes=0-0", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.header, tt.size)
			if !errors.Is(err, ErrUnsatisfiable) {
				t.Errorf("Parse(%q, %d) error = %v, want ErrUnsatisfiable", tt.header, tt.size, err)
			}
		})
	}
}

func TestParse_ZeroLengthSuffixIsSatisfiable(t *testing.T) {
	// RFC 9110 §14.1.2: "When a selected representation has zero length,
	// the only satisfiable form of range-spec in a GET request is a
	// suffix-range with a non-zero suffix-length."
	got, err := Parse("bytes=-1", 0)
	if err != nil {
		t.Fatalf("Parse(bytes=-1, 0) error = %v, want nil", err)
	}
	if len(got) != 1 || got[0].Length() != 0 {
		t.Fatalf("Parse(bytes=-1, 0) = %v, want a single empty range", got)
	}
}

func TestParse_ClampsOpenEndedAndOversizedLast(t *testing.T) {
	got, err := Parse("bytes=50-9999999", 100)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	assertRangesEqual(t, got, Ranges{{50, 99}})

	got, err = Parse("bytes=50-", 100)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	assertRangesEqual(t, got, Ranges{{50, 99}})
}

func TestParse_SuffixLargerThanSize(t *testing.T) {
	// "If the selected representation is shorter than the specified
	// suffix-length, the entire representation is used."
	got, err := Parse("bytes=-1000000", 100)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	assertRangesEqual(t, got, Ranges{{0, 99}})
}

func TestParse_HugeNumeralsDoNotPanicOrError(t *testing.T) {
	// RFC 9110 §14.1.2: "Since there is no predefined limit to the length
	// of content, recipients MUST anticipate potentially large decimal
	// numerals and prevent parsing errors due to integer conversion
	// overflows."
	huge := "99999999999999999999999999999999999999"

	// Huge first-pos: always beyond any real size, so unsatisfiable, but
	// must not error or panic.
	_, err := Parse("bytes="+huge+"-", 100)
	if !errors.Is(err, ErrUnsatisfiable) {
		t.Fatalf("Parse with huge first-pos: error = %v, want ErrUnsatisfiable", err)
	}

	// Huge last-pos clamps to size-1, same as an absent last-pos.
	got, err := Parse("bytes=0-"+huge, 100)
	if err != nil {
		t.Fatalf("Parse with huge last-pos: error = %v", err)
	}
	assertRangesEqual(t, got, Ranges{{0, 99}})

	// Huge suffix-length clamps to the whole representation.
	got, err = Parse("bytes=-"+huge, 100)
	if err != nil {
		t.Fatalf("Parse with huge suffix-length: error = %v", err)
	}
	assertRangesEqual(t, got, Ranges{{0, 99}})
}

func TestParse_MaxRangesDefault(t *testing.T) {
	// See defaultMaxRanges: the default is 16.
	header := manySmallRangesHeader(16)
	if _, err := Parse(header, 100000); err != nil {
		t.Fatalf("16 ranges: error = %v, want nil", err)
	}

	header = manySmallRangesHeader(17)
	_, err := Parse(header, 100000)
	if !errors.Is(err, ErrTooManyRanges) {
		t.Fatalf("17 ranges: error = %v, want ErrTooManyRanges", err)
	}
}

func TestParse_MaxRangesOption(t *testing.T) {
	header := manySmallRangesHeader(3)
	if _, err := Parse(header, 100000, WithMaxRanges(3)); err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	_, err := Parse(header, 100000, WithMaxRanges(2))
	if !errors.Is(err, ErrTooManyRanges) {
		t.Fatalf("error = %v, want ErrTooManyRanges", err)
	}
	// n <= 0 disables the check.
	header = manySmallRangesHeader(100)
	if _, err := Parse(header, 100000, WithMaxRanges(0)); err != nil {
		t.Fatalf("disabled cap: error = %v, want nil", err)
	}
}

func TestParse_MaxTotalBytesOption(t *testing.T) {
	// Two 100-byte, non-adjacent ranges: 200 bytes total.
	header := "bytes=0-99,200-299"
	if _, err := Parse(header, 1000, WithMaxTotalBytes(200)); err != nil {
		t.Fatalf("at the limit: error = %v, want nil", err)
	}
	_, err := Parse(header, 1000, WithMaxTotalBytes(199))
	if !errors.Is(err, ErrRangesTooLarge) {
		t.Fatalf("over the limit: error = %v, want ErrRangesTooLarge", err)
	}
	// Disabled by default.
	if _, err := Parse(header, 1000); err != nil {
		t.Fatalf("default (disabled): error = %v, want nil", err)
	}
}

func TestParse_CoalesceOption(t *testing.T) {
	header := "bytes=0-99,50-149"
	got, err := Parse(header, 1000)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	assertRangesEqual(t, got, Ranges{{0, 149}})

	got, err = Parse(header, 1000, WithCoalesce(false))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	assertRangesEqual(t, got, Ranges{{0, 99}, {50, 149}})
}

func TestParse_CoalesceOutOfOrder(t *testing.T) {
	// Coalescing sorts first, so overlapping ranges given out of order
	// still merge, per RFC 9110 §15.3.7.2: "regardless of the order in
	// which the corresponding range-spec appeared in the received Range
	// header field."
	got, err := Parse("bytes=50-149,0-99", 1000)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	assertRangesEqual(t, got, Ranges{{0, 149}})
}

func TestParse_NegativeSizeRejected(t *testing.T) {
	if _, err := Parse("bytes=0-1", -1); err == nil {
		t.Fatal("want error for negative size")
	}
}

// TestParse_1300SmallRanges measures this package's default behavior on the
// exact request shape described in the CVE-2011-3192-class amplification
// case: many small, non-overlapping (so coalescing cannot help) ranges
// against a 10000-byte body. See bench/amplify for the same request driven
// through net/http.ServeContent for comparison.
func TestParse_1300SmallRanges(t *testing.T) {
	header := manySmallRangesHeader(1300)
	_, err := Parse(header, 10000)
	if !errors.Is(err, ErrTooManyRanges) {
		t.Fatalf("1300 ranges against defaultMaxRanges=%d: error = %v, want ErrTooManyRanges", defaultMaxRanges, err)
	}
}

// manySmallRangesHeader builds a Range header requesting n single-byte,
// non-overlapping, ascending ranges: "bytes=0-0,2-2,4-4,...".
func manySmallRangesHeader(n int) string {
	header := "bytes="
	for i := 0; i < n; i++ {
		if i > 0 {
			header += ","
		}
		pos := i * 2
		header += itoa(pos) + "-" + itoa(pos)
	}
	return header
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
