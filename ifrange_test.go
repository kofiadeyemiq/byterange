package byterange

import (
	"net/http"
	"testing"
	"time"
)

func TestIfRangeSatisfied(t *testing.T) {
	modTime := time.Date(2024, 3, 15, 12, 0, 0, 0, time.UTC)
	httpDate := modTime.Format(http.TimeFormat)

	tests := []struct {
		name    string
		ifRange string
		etag    string
		modTime time.Time
		want    bool
	}{
		{"empty If-Range always satisfied", "", `"abc"`, modTime, true},
		{"matching strong etag", `"abc"`, `"abc"`, modTime, true},
		{"mismatched etag", `"abc"`, `"def"`, modTime, false},
		{"If-Range etag but no current etag", `"abc"`, "", modTime, false},
		// RFC 9110 §13.1.5 step 1 for entity-tag: "the entity-tag
		// validator provided exactly matches the ETag field value ...
		// using the strong comparison function" — weak on either side
		// fails strong comparison.
		{"weak If-Range etag never satisfies", `W/"abc"`, `"abc"`, modTime, false},
		{"weak current etag never satisfies", `"abc"`, `W/"abc"`, modTime, false},
		{"matching HTTP-date", httpDate, `"abc"`, modTime, true},
		{"mismatched HTTP-date", httpDate, `"abc"`, modTime.Add(time.Hour), false},
		{"HTTP-date but no current modTime", httpDate, `"abc"`, time.Time{}, false},
		{"garbage If-Range value", "not a date or etag", `"abc"`, modTime, false},
		{"sub-second modTime still matches at 1s resolution", httpDate, `"abc"`, modTime.Add(500 * time.Millisecond), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IfRangeSatisfied(tt.ifRange, tt.etag, tt.modTime)
			if got != tt.want {
				t.Errorf("IfRangeSatisfied(%q, %q, %v) = %v, want %v", tt.ifRange, tt.etag, tt.modTime, got, tt.want)
			}
		})
	}
}
