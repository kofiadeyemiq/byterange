package byterange

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// config holds the tunable defenses applied by Parse. See Option.
type config struct {
	maxRanges     int
	maxTotalBytes int64
	coalesce      bool
}

// defaultMaxRanges bounds how many range-specs a single Range header may
// contain. 16 comfortably covers every legitimate use this package's author
// could find (a video player seeking a handful of times, a download manager
// resuming a handful of chunks, a PDF viewer fetching a few pages) while
// keeping the worst case cheap: parsing work is O(defaultMaxRanges), and a
// multipart response carries at most defaultMaxRanges part boundaries
// (RFC 9110 §15.3.7.2 puts the per-part overhead around 80 bytes, so the
// fixed overhead this allows is on the order of 1-2 KB). It is far below the
// hundreds or thousands of ranges seen in the CVE-2011-3192-class attack this
// package defends against.
const defaultMaxRanges = 16

// defaultMaxTotalBytes is 0 (disabled) because the total-bytes cap defends a
// different case than defaultMaxRanges: a client assembling many large,
// non-overlapping ranges that together approach the full representation size.
// That is already bounded by size itself and is no more expensive than one
// full-file response, so this package does not restrict it unless the caller
// opts in with WithMaxTotalBytes.
const defaultMaxTotalBytes = 0

// emptyElementSlack is how many extra raw list elements (see
// rawListElementsCap) Parse tolerates per real range a caller's configured
// WithMaxRanges allows, to accommodate "a reasonable number of empty list
// elements" (RFC 9110 §5.6.1.2) without that tolerance itself becoming an
// unbounded cost.
const emptyElementSlack = 64

// rawListElementsHardCeiling is the absolute cap rawListElementsCap returns
// when WithMaxRanges is disabled (n <= 0), so a caller who opts out of a
// range-count limit doesn't also opt out of a bound on parsing cost. It is
// generous enough that no realistic legitimate request reaches it.
const rawListElementsHardCeiling = 1 << 16

// rawListElementsCap returns the maximum number of comma-separated elements
// (empty or not) Parse will scan for a given configured maxRanges. It is a
// parsing-cost hygiene bound, not a policy choice — see where it is used in
// Parse.
func rawListElementsCap(maxRanges int) int {
	if maxRanges <= 0 {
		return rawListElementsHardCeiling
	}
	if scaled := maxRanges * emptyElementSlack; scaled < rawListElementsHardCeiling {
		return scaled
	}
	return rawListElementsHardCeiling
}

func defaultConfig() config {
	return config{
		maxRanges:     defaultMaxRanges,
		maxTotalBytes: defaultMaxTotalBytes,
		coalesce:      true,
	}
}

// Option configures the defenses Parse applies. The zero value of Parse's
// opts (no options) uses safe defaults: see WithMaxRanges, WithMaxTotalBytes,
// and WithCoalesce.
type Option func(*config)

// WithMaxRanges sets the maximum number of range-specs a Range header may
// contain before Parse returns ErrTooManyRanges. n <= 0 disables the check.
// The default is 16; see the doc comment on defaultMaxRanges for why.
func WithMaxRanges(n int) Option {
	return func(c *config) { c.maxRanges = n }
}

// WithMaxTotalBytes sets the maximum total length, summed across all ranges
// after coalescing, that a Range header may request before Parse returns
// ErrRangesTooLarge. n <= 0 disables the check, which is the default.
func WithMaxTotalBytes(n int64) Option {
	return func(c *config) { c.maxTotalBytes = n }
}

// WithCoalesce controls whether Parse merges overlapping or adjacent ranges
// into a single range, as permitted by RFC 9110 §15.3.7.2. It is enabled by
// default: coalescing only ever reduces the number of ranges and the number
// of times the same bytes would otherwise be sent twice, so disabling it is
// rarely useful outside of tests that want to see the raw request shape.
func WithCoalesce(enabled bool) Option {
	return func(c *config) { c.coalesce = enabled }
}

// Parse parses the value of an HTTP Range header field (RFC 9110 §14.1.2)
// against a representation of the given size and returns the satisfiable,
// size-clamped ranges it names, in ascending order.
//
// header is the raw field value, e.g. "bytes=0-499,500-999" — not including
// the "Range:" field name. size is the total length in bytes of the
// representation the ranges are resolved against; size must be >= 0.
//
// Parse returns one of the sentinel errors declared in this package's
// var block when it cannot return a range set: see their doc comments for
// what each means and how a caller (Serve does this automatically) should
// respond. All wrapped errors satisfy errors.Is against their sentinel.
func Parse(header string, size int64, opts ...Option) (Ranges, error) {
	if size < 0 {
		return nil, fmt.Errorf("byterange: negative size %d", size)
	}

	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	header = strings.TrimSpace(header)
	unit, rangeSet, ok := strings.Cut(header, "=")
	if !ok {
		return nil, ErrMalformed
	}
	// RFC 9110 §14.1: "All range unit names are case-insensitive."
	if !strings.EqualFold(strings.TrimSpace(unit), "bytes") {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedUnit, strings.TrimSpace(unit))
	}

	fields := strings.Split(rangeSet, ",")

	// Empty elements (after OWS) don't contribute to the element count and
	// are skipped rather than parsed: RFC 9110 §5.6.1.2's recipient grammar
	// for a #rule list (which range-set is: "range-set = 1#range-spec") is
	// "#element => [ element ] *( OWS "," OWS [ element ] )", so
	// "bytes=0-1, ,2-3" and "bytes=0-1,2-3," are both valid range-sets
	// naming the same two specs a strict "1#range-spec" reading would
	// reject. "Empty elements do not contribute to the count of elements
	// present" (same section), so this filtering happens before the
	// WithMaxRanges check below.
	specs := fields[:0]
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			specs = append(specs, f)
		}
	}
	if len(specs) == 0 {
		// range-set = 1#range-spec requires at least one non-empty
		// element; per RFC 9110 §5.6.1.2's own examples, "," and ",   ,"
		// are invalid for exactly this reason.
		return nil, ErrMalformed
	}

	if cfg.maxRanges > 0 && len(specs) > cfg.maxRanges {
		return nil, fmt.Errorf("%w: %d ranges requested, max %d", ErrTooManyRanges, len(specs), cfg.maxRanges)
	}

	// RFC 9110 §5.6.1.2: "A recipient MUST parse and ignore a reasonable
	// number of empty list elements: enough to handle common mistakes by
	// senders that merge values, but not so much that they could be used
	// as a denial-of-service mechanism." The check above already rejects a
	// header naming too many actual ranges; this second check catches the
	// case that one alone would miss — few real ranges padded with a huge
	// number of empty elements, e.g. "bytes=0-1,2-3" followed by thousands
	// of commas — which would otherwise cost this package O(len(fields))
	// work for no bound at all. rawListElementsCap (see its doc comment)
	// scales with WithMaxRanges so a caller who raises that cap isn't
	// second-guessed by this one.
	if rawCap := rawListElementsCap(cfg.maxRanges); len(fields) > rawCap {
		return nil, fmt.Errorf("%w: %d list elements (including empty), max %d", ErrMalformed, len(fields), rawCap)
	}

	raw := make([]Range, 0, len(specs))
	for _, spec := range specs {
		r, satisfiable, ok := parseSpec(spec, size)
		if !ok {
			// RFC 9110 §14.1.1: "A ranges-specifier is invalid if it
			// contains any range-spec that is invalid ..." — one bad
			// spec invalidates the whole header, not just that spec.
			return nil, ErrMalformed
		}
		if satisfiable {
			raw = append(raw, r)
		}
	}

	if len(raw) == 0 {
		return nil, ErrUnsatisfiable
	}

	if cfg.coalesce {
		raw = coalesceRanges(raw)
	}

	if cfg.maxTotalBytes > 0 {
		if total := Ranges(raw).TotalBytes(); total > cfg.maxTotalBytes {
			return nil, fmt.Errorf("%w: %d bytes requested, max %d", ErrRangesTooLarge, total, cfg.maxTotalBytes)
		}
	}

	return raw, nil
}

// parseSpec parses a single range-spec (already trimmed of surrounding
// whitespace and its separating comma) against size. ok is false only when
// the spec is syntactically invalid, per RFC 9110 §14.1.1/§14.1.2 — the
// caller must then treat the entire ranges-specifier as invalid. When ok is
// true but satisfiable is false, this one spec is simply not satisfiable
// (RFC 9110 §14.1.2) and should be dropped from the result without
// invalidating the rest of the header.
func parseSpec(spec string, size int64) (r Range, satisfiable bool, ok bool) {
	if spec == "" {
		return Range{}, false, false
	}

	if strings.HasPrefix(spec, "-") {
		// suffix-range = "-" suffix-length
		n, overflow, err := parseDigits(spec[1:])
		if err != nil {
			return Range{}, false, false
		}
		if n == 0 {
			// "a suffix-range with a non-zero suffix-length" is required
			// for satisfiability (RFC 9110 §14.1.2); zero is syntactically
			// valid but never satisfiable.
			return Range{}, false, true
		}
		if size == 0 {
			// RFC 9110 §14.1.2: "When a selected representation has zero
			// length, the only satisfiable form of range-spec in a GET
			// request is a suffix-range with a non-zero suffix-length."
			// The resulting range covers the (empty) representation.
			return Range{Start: 0, End: -1}, true, true
		}
		start := size - n
		if overflow || start < 0 {
			start = 0
		}
		return Range{Start: start, End: size - 1}, true, true
	}

	firstStr, lastStr, hasDash := strings.Cut(spec, "-")
	if !hasDash {
		return Range{}, false, false
	}
	first, firstOverflow, err := parseDigits(firstStr)
	if err != nil {
		return Range{}, false, false
	}

	var last int64
	hasLast := lastStr != ""
	lastOverflow := false
	if hasLast {
		last, lastOverflow, err = parseDigits(lastStr)
		if err != nil {
			return Range{}, false, false
		}
		if !firstOverflow && !lastOverflow && last < first {
			// "An int-range is invalid if the last-pos value is present
			// and less than the first-pos." (RFC 9110 §14.1.1)
			return Range{}, false, false
		}
	}

	if size == 0 {
		// "an int-range with a first-pos that is less than the current
		// length" can never hold when size is 0.
		return Range{}, false, true
	}
	if firstOverflow || first >= size {
		return Range{}, false, true
	}
	if !hasLast || lastOverflow || last >= size {
		last = size - 1
	}
	return Range{Start: first, End: last}, true, true
}

// parseDigits parses s as the decimal digit sequence used by first-pos,
// last-pos and suffix-length (RFC 9110 §14.1.1's 1*DIGIT). RFC 9110 §14.1.2
// requires recipients to "anticipate potentially large decimal numerals and
// prevent parsing errors due to integer conversion overflows": a numeral
// that does not fit in an int64 is reported via overflow rather than err, so
// callers can treat it as "larger than any real size" instead of rejecting
// the whole header.
func parseDigits(s string) (v int64, overflow bool, err error) {
	if s == "" {
		return 0, false, fmt.Errorf("byterange: empty digit sequence")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false, fmt.Errorf("byterange: %q is not a decimal numeral", s)
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return math.MaxInt64, true, nil
	}
	return n, false, nil
}

// coalesceRanges sorts rs by start and merges ranges that overlap or touch
// (RFC 9110 §15.3.7.2: "a server MAY coalesce any of the ranges that
// overlap, or that are separated by a gap that is smaller than the overhead
// of sending multiple parts"). This package only merges strictly overlapping
// or touching ranges (end+1 >= next start) — never ranges separated by a real
// gap — so every byte in the merged result was explicitly requested; the more
// aggressive gap-based merging the RFC also allows is left to the caller via
// a pre-merge on the input if desired.
func coalesceRanges(rs []Range) []Range {
	if len(rs) <= 1 {
		return rs
	}
	sorted := append([]Range(nil), rs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Start < sorted[j].Start })

	out := sorted[:1]
	for _, r := range sorted[1:] {
		last := &out[len(out)-1]
		if r.Start <= last.End+1 {
			if r.End > last.End {
				last.End = r.End
			}
			continue
		}
		out = append(out, r)
	}
	return out
}
