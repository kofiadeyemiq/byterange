// Package byterange parses HTTP Range headers (RFC 9110 §14.1.2) and serves
// the resulting byte ranges, for handlers that cannot hand net/http.ServeContent
// an io.ReadSeeker — for example a handler backed by object storage, a remote
// origin, or computed content addressed by an Open(offset, length) call.
//
// Parse turns a Range header field value into a validated, size-clamped set of
// byte ranges. It applies the defenses RFC 9110 §17.15 recommends against the
// "many overlapping or out-of-order ranges" denial-of-service pattern
// (the class of attack fixed industry-wide after CVE-2011-3192, the Apache
// httpd "Range header" DoS): a cap on the number of ranges, coalescing of
// overlapping or adjacent ranges, and an optional cap on total requested
// bytes.
//
// Serve drives a full Range-aware GET/HEAD response — full body, single 206,
// multipart/byteranges 206, or 416 — from a source that can open an
// arbitrary byte range on demand.
package byterange

import (
	"errors"
)

// Range is an inclusive byte range, resolved against a representation of a
// known size: bytes Start through End, both included, with 0 <= Start <= End.
type Range struct {
	Start int64
	End   int64
}

// Length returns the number of bytes covered by r, inclusive of both ends.
func (r Range) Length() int64 {
	return r.End - r.Start + 1
}

// Ranges is a validated, ordered set of byte ranges produced by Parse.
type Ranges []Range

// TotalBytes returns the sum of the length of every range in rs.
func (rs Ranges) TotalBytes() int64 {
	var total int64
	for _, r := range rs {
		total += r.Length()
	}
	return total
}

// Sentinel errors returned by Parse. Each documents what the caller should do
// next; Serve implements exactly this mapping. Use errors.Is to test for
// them, since Parse wraps some of them with detail via %w.
var (
	// ErrUnsupportedUnit means the Range header used a range unit other than
	// "bytes". RFC 9110 §14.2: "An origin server MUST ignore a Range header
	// field that contains a range unit it does not understand." The caller
	// must respond as if no Range header were present (a normal 200).
	ErrUnsupportedUnit = errors.New("byterange: unsupported range unit")

	// ErrMalformed means the header's range-set did not parse as a valid
	// ranges-specifier (RFC 9110 §14.1.1: "A ranges-specifier is invalid if
	// it contains any range-spec that is invalid ..."). RFC 9110 §14.2
	// permits a server to either ignore or reject such a header; this
	// package's documented default is to ignore it, the same as an
	// unsupported unit, so the caller should respond with a normal 200.
	ErrMalformed = errors.New("byterange: Range header is not a valid ranges-specifier")

	// ErrTooManyRanges means the header requested more ranges than the
	// configured maximum (WithMaxRanges). RFC 9110 §14.2 and §17.15
	// explicitly list "a set of many small ranges" as grounds to ignore or
	// reject the header, since parsing and serving it is far cheaper for
	// the client to request than for the server to do. The caller should
	// treat this the same as ErrMalformed: ignore the header, respond 200.
	ErrTooManyRanges = errors.New("byterange: too many ranges requested")

	// ErrRangesTooLarge means the ranges left after coalescing request more
	// total bytes than the configured maximum (WithMaxTotalBytes). Treat the
	// same as ErrMalformed: ignore the header, respond 200.
	ErrRangesTooLarge = errors.New("byterange: total requested bytes exceed limit")

	// ErrUnsatisfiable means the header was a syntactically valid
	// ranges-specifier, but none of its range-specs are satisfiable against
	// the given size (RFC 9110 §14.1.1's definition of "satisfiable"). Per
	// RFC 9110 §15.5.17, the caller should respond 416 with a
	// Content-Range: bytes */size header (see ContentRangeUnsatisfied).
	ErrUnsatisfiable = errors.New("byterange: no range is satisfiable")
)
