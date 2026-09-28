// Command amplify measures the response net/http.ServeContent and
// byterange.Serve each produce for a Range header requesting 1300 small,
// non-overlapping, ascending byte ranges against a 10000-byte body — the
// CVE-2011-3192-class amplification shape this package's Parse defends
// against by default (see the defaultMaxRanges doc comment in parse.go).
//
// Run with: go run ./bench/amplify
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/kofiadeyemiq/byterange"
)

const bodySize = 10000

func manyRangesHeader(n int) string {
	var b strings.Builder
	b.WriteString("bytes=")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		pos := i * 2
		b.WriteString(strconv.Itoa(pos))
		b.WriteByte('-')
		b.WriteString(strconv.Itoa(pos))
	}
	return b.String()
}

func main() {
	body := bytes.Repeat([]byte("x"), bodySize)
	header := manyRangesHeader(1300)

	stdlibStatus, stdlibBytes := runStdlib(body, header)
	fmt.Printf("net/http.ServeContent : status %d, response %d bytes (%.1fx body size)\n",
		stdlibStatus, stdlibBytes, float64(stdlibBytes)/float64(bodySize))

	ourStatus, ourBytes := runOurs(body, header)
	fmt.Printf("byterange.Serve        : status %d, response %d bytes (%.1fx body size)\n",
		ourStatus, ourBytes, float64(ourBytes)/float64(bodySize))
}

func runStdlib(body []byte, header string) (status int, responseBytes int) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", header)
	rec := httptest.NewRecorder()

	http.ServeContent(rec, req, "body.bin", time.Unix(0, 0), bytes.NewReader(body))

	return rec.Code, headerBytes(rec) + rec.Body.Len()
}

func runOurs(body []byte, header string) (status int, responseBytes int) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", header)
	rec := httptest.NewRecorder()

	opts := byterange.ServeOptions{
		Size: bodySize,
		Open: func(off, n int64) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body[off : off+n])), nil
		},
	}
	if err := byterange.Serve(rec, req, opts); err != nil {
		panic(err)
	}

	return rec.Code, headerBytes(rec) + rec.Body.Len()
}

// headerBytes gives a rough but consistent accounting of header bytes on
// the wire, so the two runs are compared on the same basis; it is not meant
// to reproduce exact HTTP/1.1 framing.
func headerBytes(rec *httptest.ResponseRecorder) int {
	n := 0
	for k, vs := range rec.Header() {
		for _, v := range vs {
			n += len(k) + len(v) + 4 // ": " + "\r\n"
		}
	}
	return n
}
