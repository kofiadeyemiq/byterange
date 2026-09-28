package byterange

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This file drives identical requests through net/http.ServeContent and
// byterange.Serve and documents every behavioral difference found, per this
// package's build instructions. Every difference below traces back to an
// RFC 9110 requirement or to one of this package's documented defenses —
// none are accidental.

const compareBody = "the quick brown fox jumps over the lazy dog, thirty-six" // 55 bytes

func compareOpts(body []byte) ServeOptions {
	return ServeOptions{
		Size: int64(len(body)),
		Open: func(off, n int64) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body[off : off+n])), nil
		},
	}
}

// TestStdlibComparison_UnknownUnit: net/http.ServeContent on this
// environment's go1.27.1 answers a Range header with an unrecognized unit
// with 416, which contradicts RFC 9110 §14.2's "An origin server MUST
// ignore a Range header field that contains a range unit it does not
// understand." This is a known, open Go bug: golang/go issue #81508
// ("net/http: ServeContent returns 416 for an unsupported Range unit
// instead of ignoring it"), with an open fix at golang/go pull request
// #81746 at the time this package was written. byterange.Serve implements
// the RFC's MUST and returns 200 with the full body instead.
func TestStdlibComparison_UnknownUnit(t *testing.T) {
	body := []byte(compareBody)
	header := "items=0-5"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", header)
	stdlibRec := httptest.NewRecorder()
	http.ServeContent(stdlibRec, req, "body.bin", time.Unix(0, 0), bytes.NewReader(body))

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Range", header)
	oursRec := httptest.NewRecorder()
	if err := Serve(oursRec, req2, compareOpts(body)); err != nil {
		t.Fatalf("Serve error = %v", err)
	}

	t.Logf("stdlib ServeContent: status %d, body %q", stdlibRec.Code, stdlibRec.Body.String())
	t.Logf("byterange.Serve:     status %d, body %q", oursRec.Code, oursRec.Body.String())

	if stdlibRec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Skipf("net/http.ServeContent no longer returns 416 for an unknown range unit "+
			"(got %d) — golang/go#81508 appears fixed in this Go version; "+
			"the difference documented by this test no longer applies", stdlibRec.Code)
	}
	if oursRec.Code != http.StatusOK {
		t.Errorf("byterange.Serve status = %d, want 200 (RFC 9110 §14.2 MUST ignore)", oursRec.Code)
	}
	if oursRec.Body.String() != compareBody {
		t.Errorf("byterange.Serve body = %q, want full body", oursRec.Body.String())
	}
}

// TestStdlibComparison_ManySmallRanges measures the same amplification case
// as bench/amplify (1300 single-byte, non-overlapping, ascending ranges
// against a 10000-byte body) directly in the test suite, so `go test`
// itself verifies the claim: net/http.ServeContent answers with a 206
// containing every requested part; byterange.Serve's default
// defaultMaxRanges cap (16) rejects the header as ErrTooManyRanges and
// falls back to a full 200. Real numbers are logged, not hardcoded, since
// exact multipart overhead can shift between Go versions.
func TestStdlibComparison_ManySmallRanges(t *testing.T) {
	const size = 10000
	body := bytes.Repeat([]byte("x"), size)
	header := manySmallRangesHeader(1300)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", header)
	stdlibRec := httptest.NewRecorder()
	http.ServeContent(stdlibRec, req, "body.bin", time.Unix(0, 0), bytes.NewReader(body))

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Range", header)
	oursRec := httptest.NewRecorder()
	if err := Serve(oursRec, req2, compareOpts(body)); err != nil {
		t.Fatalf("Serve error = %v", err)
	}

	stdlibTotal := stdlibRec.Body.Len()
	oursTotal := oursRec.Body.Len()
	t.Logf("1300-range request against a %d-byte body:", size)
	t.Logf("  stdlib ServeContent: status %d, body %d bytes (%.1fx)", stdlibRec.Code, stdlibTotal, float64(stdlibTotal)/float64(size))
	t.Logf("  byterange.Serve:     status %d, body %d bytes (%.1fx)", oursRec.Code, oursTotal, float64(oursTotal)/float64(size))

	if stdlibRec.Code != http.StatusPartialContent {
		t.Fatalf("stdlib status = %d, want 206 (premise for this test)", stdlibRec.Code)
	}
	if stdlibTotal <= size {
		t.Fatalf("stdlib body %d bytes did not amplify past body size %d (premise for this test)", stdlibTotal, size)
	}

	if oursRec.Code != http.StatusOK {
		t.Errorf("byterange.Serve status = %d, want 200 (ErrTooManyRanges falls back to full body)", oursRec.Code)
	}
	if oursTotal != size {
		t.Errorf("byterange.Serve body %d bytes, want exactly %d (the unamplified full body)", oursTotal, size)
	}
}

// TestStdlibComparison_SingleRange is a positive control: for a normal,
// well-formed single-range request, both implementations agree exactly.
func TestStdlibComparison_SingleRange(t *testing.T) {
	body := []byte(compareBody)
	header := "bytes=5-14"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", header)
	stdlibRec := httptest.NewRecorder()
	http.ServeContent(stdlibRec, req, "body.bin", time.Unix(0, 0), bytes.NewReader(body))

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Range", header)
	oursRec := httptest.NewRecorder()
	if err := Serve(oursRec, req2, compareOpts(body)); err != nil {
		t.Fatalf("Serve error = %v", err)
	}

	if stdlibRec.Code != oursRec.Code {
		t.Errorf("status: stdlib %d, ours %d", stdlibRec.Code, oursRec.Code)
	}
	if stdlibRec.Body.String() != oursRec.Body.String() {
		t.Errorf("body: stdlib %q, ours %q", stdlibRec.Body.String(), oursRec.Body.String())
	}
	if stdlibRec.Header().Get("Content-Range") != oursRec.Header().Get("Content-Range") {
		t.Errorf("Content-Range: stdlib %q, ours %q", stdlibRec.Header().Get("Content-Range"), oursRec.Header().Get("Content-Range"))
	}
}

// TestStdlibComparison_FullFile is a negative control: no Range header,
// both serve the identical full body with 200.
func TestStdlibComparison_FullFile(t *testing.T) {
	body := []byte(compareBody)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	stdlibRec := httptest.NewRecorder()
	http.ServeContent(stdlibRec, req, "body.bin", time.Unix(0, 0), bytes.NewReader(body))

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	oursRec := httptest.NewRecorder()
	if err := Serve(oursRec, req2, compareOpts(body)); err != nil {
		t.Fatalf("Serve error = %v", err)
	}

	if stdlibRec.Code != http.StatusOK || oursRec.Code != http.StatusOK {
		t.Fatalf("status: stdlib %d, ours %d, want 200/200", stdlibRec.Code, oursRec.Code)
	}
	if stdlibRec.Body.String() != oursRec.Body.String() {
		t.Errorf("body: stdlib %q, ours %q", stdlibRec.Body.String(), oursRec.Body.String())
	}
}

// TestStdlibComparison_HEAD compares HEAD-with-Range handling: both send
// 206 and the Content-Range header without a body.
func TestStdlibComparison_HEAD(t *testing.T) {
	body := []byte(compareBody)
	header := "bytes=5-14"

	req := httptest.NewRequest(http.MethodHead, "/", nil)
	req.Header.Set("Range", header)
	stdlibRec := httptest.NewRecorder()
	http.ServeContent(stdlibRec, req, "body.bin", time.Unix(0, 0), bytes.NewReader(body))

	req2 := httptest.NewRequest(http.MethodHead, "/", nil)
	req2.Header.Set("Range", header)
	oursRec := httptest.NewRecorder()
	if err := Serve(oursRec, req2, compareOpts(body)); err != nil {
		t.Fatalf("Serve error = %v", err)
	}

	t.Logf("stdlib HEAD: status %d, Content-Range %q, body %d bytes", stdlibRec.Code, stdlibRec.Header().Get("Content-Range"), stdlibRec.Body.Len())
	t.Logf("ours HEAD:   status %d, Content-Range %q, body %d bytes", oursRec.Code, oursRec.Header().Get("Content-Range"), oursRec.Body.Len())

	if oursRec.Code != http.StatusPartialContent {
		t.Errorf("byterange.Serve HEAD status = %d, want 206", oursRec.Code)
	}
	if oursRec.Body.Len() != 0 {
		t.Errorf("byterange.Serve HEAD body = %d bytes, want 0", oursRec.Body.Len())
	}
	if oursRec.Header().Get("Content-Range") != "bytes 5-14/55" {
		t.Errorf("byterange.Serve HEAD Content-Range = %q, want %q", oursRec.Header().Get("Content-Range"), "bytes 5-14/55")
	}
}
