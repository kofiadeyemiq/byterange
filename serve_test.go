package byterange

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fileOpener returns a ServeOptions.Open implementation backed by a real
// file on disk, opened fresh (and seeked) on every call — closer to how a
// remote-storage-backed Open would behave than holding one shared handle.
func fileOpener(t *testing.T, path string) func(off, n int64) (io.ReadCloser, error) {
	t.Helper()
	return func(off, n int64) (io.ReadCloser, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
		return limitReadCloser{io.LimitReader(f, n), f}, nil
	}
}

type limitReadCloser struct {
	io.Reader
	io.Closer
}

func newTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "content.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

const serveTestBody = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" // 36 bytes

func newServeOptions(t *testing.T) ServeOptions {
	path := newTestFile(t, serveTestBody)
	return ServeOptions{
		Size:        int64(len(serveTestBody)),
		ContentType: "text/plain",
		ETag:        `"etag-1"`,
		ModTime:     time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Open:        fileOpener(t, path),
	}
}

// TestServe_NoRangeHeader is a negative control: a plain GET with no Range
// header gets a normal full 200 response.
func TestServe_NoRangeHeader(t *testing.T) {
	opts := newServeOptions(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	if err := Serve(rec, req, opts); err != nil {
		t.Fatalf("Serve error = %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != serveTestBody {
		t.Fatalf("body = %q, want %q", got, serveTestBody)
	}
	if got := rec.Header().Get("Content-Length"); got != "36" {
		t.Fatalf("Content-Length = %q, want 36", got)
	}
	if got := rec.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Fatalf("Accept-Ranges = %q, want bytes", got)
	}
}

// TestServe_SingleRange is a negative/positive control: a normal single
// range gets a normal 206 with Content-Range and exactly that slice of the
// body.
func TestServe_SingleRange(t *testing.T) {
	opts := newServeOptions(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", "bytes=10-14")
	rec := httptest.NewRecorder()

	if err := Serve(rec, req, opts); err != nil {
		t.Fatalf("Serve error = %v", err)
	}
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rec.Code)
	}
	want := serveTestBody[10:15]
	if got := rec.Body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 10-14/36" {
		t.Fatalf("Content-Range = %q, want %q", got, "bytes 10-14/36")
	}
	if got := rec.Header().Get("Content-Length"); got != "5" {
		t.Fatalf("Content-Length = %q, want 5", got)
	}
}

func TestServe_MultipartRange(t *testing.T) {
	opts := newServeOptions(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", "bytes=0-4,10-14")
	rec := httptest.NewRecorder()

	if err := Serve(rec, req, opts); err != nil {
		t.Fatalf("Serve error = %v", err)
	}
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/byteranges; boundary=") {
		t.Fatalf("Content-Type = %q, want multipart/byteranges with boundary", ct)
	}
	if !strings.Contains(rec.Body.String(), serveTestBody[0:5]) || !strings.Contains(rec.Body.String(), serveTestBody[10:15]) {
		t.Fatalf("body missing expected ranges: %q", rec.Body.String())
	}
	// The Content-Length Serve computed ahead of time (multipartContentLength)
	// must match the bytes actually written, or a real HTTP client would
	// truncate or hang reading the response.
	if got, want := rec.Header().Get("Content-Length"), rec.Body.Len(); got != itoa(want) {
		t.Fatalf("Content-Length header = %q, actual body length = %d", got, want)
	}
}

// TestServe_Unsatisfiable is a negative control alongside the positive
// range tests: an out-of-bounds range gets a 416 with Content-Range: bytes
// */size and no body.
func TestServe_Unsatisfiable(t *testing.T) {
	opts := newServeOptions(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", "bytes=1000-2000")
	rec := httptest.NewRecorder()

	if err := Serve(rec, req, opts); err != nil {
		t.Fatalf("Serve error = %v", err)
	}
	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want 416", rec.Code)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes */36" {
		t.Fatalf("Content-Range = %q, want %q", got, "bytes */36")
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", rec.Body.String())
	}
}

// TestServe_UnsupportedUnitIgnored is a negative control: an unknown range
// unit must not turn into a 416 — RFC 9110 §14.2 requires ignoring it. See
// TestStdlibComparison_UnknownUnit for the same input against
// net/http.ServeContent.
func TestServe_UnsupportedUnitIgnored(t *testing.T) {
	opts := newServeOptions(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", "items=0-5")
	rec := httptest.NewRecorder()

	if err := Serve(rec, req, opts); err != nil {
		t.Fatalf("Serve error = %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (Range header ignored)", rec.Code)
	}
	if got := rec.Body.String(); got != serveTestBody {
		t.Fatalf("body = %q, want full body %q", got, serveTestBody)
	}
}

// TestServe_TooManyRangesIgnored shows the defense from the amplification
// case: more ranges than the default cap allows falls back to a full 200,
// not a 416 and not an oversized 206.
func TestServe_TooManyRangesIgnored(t *testing.T) {
	opts := newServeOptions(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", manySmallRangesHeader(defaultMaxRanges+1))
	rec := httptest.NewRecorder()

	if err := Serve(rec, req, opts); err != nil {
		t.Fatalf("Serve error = %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != serveTestBody {
		t.Fatalf("body = %q, want full body %q", got, serveTestBody)
	}
}

// TestServe_HEAD is a negative control confirming HEAD gets headers only:
// no Open call, no body, but the same status and headers a GET would carry.
func TestServe_HEAD(t *testing.T) {
	opened := false
	opts := newServeOptions(t)
	realOpen := opts.Open
	opts.Open = func(off, n int64) (io.ReadCloser, error) {
		opened = true
		return realOpen(off, n)
	}

	req := httptest.NewRequest(http.MethodHead, "/", nil)
	req.Header.Set("Range", "bytes=10-14")
	rec := httptest.NewRecorder()

	if err := Serve(rec, req, opts); err != nil {
		t.Fatalf("Serve error = %v", err)
	}
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rec.Code)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 10-14/36" {
		t.Fatalf("Content-Range = %q, want %q", got, "bytes 10-14/36")
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD body = %q, want empty", rec.Body.String())
	}
	if opened {
		t.Fatal("Serve called Open for a HEAD request")
	}
}

func TestServe_IfRangeFalseIgnoresRange(t *testing.T) {
	opts := newServeOptions(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", "bytes=10-14")
	req.Header.Set("If-Range", `"stale-etag"`)
	rec := httptest.NewRecorder()

	if err := Serve(rec, req, opts); err != nil {
		t.Fatalf("Serve error = %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (If-Range false)", rec.Code)
	}
	if got := rec.Body.String(); got != serveTestBody {
		t.Fatalf("body = %q, want full body", got)
	}
}

func TestServe_IfRangeTrueHonorsRange(t *testing.T) {
	opts := newServeOptions(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", "bytes=10-14")
	req.Header.Set("If-Range", opts.ETag)
	rec := httptest.NewRecorder()

	if err := Serve(rec, req, opts); err != nil {
		t.Fatalf("Serve error = %v", err)
	}
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206 (If-Range true)", rec.Code)
	}
}

func TestServe_RejectsInvalidOptions(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if err := Serve(rec, req, ServeOptions{Size: -1, Open: func(int64, int64) (io.ReadCloser, error) { return nil, nil }}); err == nil {
		t.Error("negative Size: want error")
	}
	if err := Serve(rec, req, ServeOptions{Size: 10}); err == nil {
		t.Error("nil Open: want error")
	}
}
