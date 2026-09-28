package byterange

import (
	"net/http"
	"strings"
	"time"
)

// IfRangeSatisfied evaluates an If-Range precondition (RFC 9110 §13.1.5)
// against the current strong validator(s) of a representation, following the
// two evaluation procedures the RFC specifies for an entity-tag and an
// HTTP-date If-Range value:
//
//   - "the entity-tag validator provided exactly matches the ETag field
//     value for the selected representation using the strong comparison
//     function" — so a weak ifRange or a weak etag never satisfies it.
//   - "If the HTTP-date validator provided is not a strong validator ...
//     the condition is false. If [it] exactly matches the Last-Modified
//     field value for the selected representation, the condition is true."
//
// ifRange is the raw If-Range header field value. etag is the
// representation's current ETag field value, including surrounding quotes
// (e.g. `"abc123"` or `W/"abc123"`); pass "" if the resource has none.
// modTime is the representation's current Last-Modified time; pass a zero
// time.Time if it has none or is not known to be a strong validator (an
// HTTP-date If-Range can then never be satisfied, matching the RFC 9110
// requirement above — callers must not pass a modTime that could still
// change within the same HTTP-date second, since that would not be a strong
// validator).
//
// If ifRange is "" (no If-Range header field was present), IfRangeSatisfied
// returns true: there is nothing to invalidate the Range header field with.
func IfRangeSatisfied(ifRange, etag string, modTime time.Time) bool {
	if ifRange == "" {
		return true
	}

	// A valid entity-tag can be distinguished from a valid HTTP-date by
	// examining the first three characters for a DQUOTE (RFC 9110 §13.1.5).
	if looksLikeEntityTag(ifRange) {
		if isWeakETag(ifRange) || isWeakETag(etag) {
			return false
		}
		return etag != "" && etag == ifRange
	}

	t, err := http.ParseTime(ifRange)
	if err != nil || modTime.IsZero() {
		return false
	}
	// HTTP-date has one-second resolution; compare at that resolution so a
	// modTime carrying sub-second precision does not spuriously fail to
	// match a date that round-tripped through an HTTP-date header.
	return t.Equal(modTime.Truncate(time.Second))
}

func looksLikeEntityTag(v string) bool {
	if strings.HasPrefix(v, `"`) {
		return true
	}
	return strings.HasPrefix(v, `W/"`)
}

func isWeakETag(v string) bool {
	return strings.HasPrefix(v, "W/")
}
