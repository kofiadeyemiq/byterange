package byterange

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"
)

func TestContentRange(t *testing.T) {
	// RFC 9110 §14.4 examples, for a representation of 1234 bytes.
	tests := []struct {
		r    Range
		size int64
		want string
	}{
		{Range{0, 499}, 1234, "bytes 0-499/1234"},
		{Range{500, 999}, 1234, "bytes 500-999/1234"},
		{Range{500, 1233}, 1234, "bytes 500-1233/1234"},
		{Range{734, 1233}, 1234, "bytes 734-1233/1234"},
	}
	for _, tt := range tests {
		if got := ContentRange(tt.r, tt.size); got != tt.want {
			t.Errorf("ContentRange(%v, %d) = %q, want %q", tt.r, tt.size, got, tt.want)
		}
	}
}

func TestContentRangeUnsatisfied(t *testing.T) {
	// RFC 9110 §14.4: "Content-Range: bytes */1234"
	if got := ContentRangeUnsatisfied(1234); got != "bytes */1234" {
		t.Errorf("ContentRangeUnsatisfied(1234) = %q, want %q", got, "bytes */1234")
	}
}

func TestNewBoundary(t *testing.T) {
	a := NewBoundary()
	b := NewBoundary()
	if a == b {
		t.Fatalf("NewBoundary returned the same value twice: %q", a)
	}
	if a == "" || b == "" {
		t.Fatal("NewBoundary returned an empty string")
	}
}

func TestWriteMultipart(t *testing.T) {
	body := []byte("0123456789ABCDEFGHIJ") // 20 bytes
	ranges := Ranges{{0, 4}, {10, 14}}     // "01234", "ABCDE"

	var buf bytes.Buffer
	boundary := NewBoundary()
	n, err := WriteMultipart(&buf, ranges, boundary, "text/plain", int64(len(body)), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("WriteMultipart error = %v", err)
	}
	if n != int64(buf.Len()) {
		t.Fatalf("WriteMultipart reported %d bytes written, buffer holds %d", n, buf.Len())
	}

	// Parse it back with mime/multipart to confirm it is a well-formed
	// multipart/byteranges body (RFC 9110 §14.6), independent of how this
	// package produced it.
	mr := multipart.NewReader(&buf, boundary)
	var gotRanges []string
	var gotBodies []string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading part: %v", err)
		}
		if ct := part.Header.Get("Content-Type"); ct != "text/plain" {
			t.Errorf("part Content-Type = %q, want %q", ct, "text/plain")
		}
		gotRanges = append(gotRanges, part.Header.Get("Content-Range"))
		b, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("reading part body: %v", err)
		}
		gotBodies = append(gotBodies, string(b))
	}

	wantRanges := []string{"bytes 0-4/20", "bytes 10-14/20"}
	wantBodies := []string{"01234", "ABCDE"}
	if len(gotRanges) != len(wantRanges) {
		t.Fatalf("got %d parts, want %d", len(gotRanges), len(wantRanges))
	}
	for i := range wantRanges {
		if gotRanges[i] != wantRanges[i] {
			t.Errorf("part %d Content-Range = %q, want %q", i, gotRanges[i], wantRanges[i])
		}
		if gotBodies[i] != wantBodies[i] {
			t.Errorf("part %d body = %q, want %q", i, gotBodies[i], wantBodies[i])
		}
	}
}

func TestWriteMultipart_ContentTypeHeaderRoundTrips(t *testing.T) {
	// Guard against a regression where the boundary returned/used doesn't
	// match what a real "Content-Type: multipart/byteranges; boundary=..."
	// header (built the way Serve builds it) would declare.
	boundary := NewBoundary()
	header := "multipart/byteranges; boundary=" + boundary
	_, params, err := mime.ParseMediaType(header)
	if err != nil {
		t.Fatalf("mime.ParseMediaType(%q) error = %v", header, err)
	}
	if params["boundary"] != boundary {
		t.Fatalf("parsed boundary %q != %q", params["boundary"], boundary)
	}

	body := []byte("hello world")
	var buf bytes.Buffer
	if _, err := WriteMultipart(&buf, Ranges{{0, 4}}, boundary, "", int64(len(body)), bytes.NewReader(body)); err != nil {
		t.Fatalf("WriteMultipart error = %v", err)
	}
	if !strings.Contains(buf.String(), boundary) {
		t.Fatalf("multipart body does not contain its own boundary %q", boundary)
	}
}
