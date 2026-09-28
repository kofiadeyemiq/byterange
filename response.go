package byterange

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
)

// ContentRange formats the Content-Range header field value for a single
// satisfiable range in a 206 (Partial Content) response, per RFC 9110 §14.4:
// "Content-Range = range-unit SP ( range-resp / unsatisfied-range )".
//
//	ContentRange(Range{Start: 0, End: 499}, 1234) == "bytes 0-499/1234"
func ContentRange(r Range, size int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.Start, r.End, size)
}

// ContentRangeUnsatisfied formats the Content-Range header field value RFC
// 9110 §14.4 and §15.5.17 direct a server to send alongside a 416 (Range Not
// Satisfiable) response: "bytes */size", naming the current length of the
// representation so the client can retry with a satisfiable range.
func ContentRangeUnsatisfied(size int64) string {
	return fmt.Sprintf("bytes */%d", size)
}

// NewBoundary returns a fresh random boundary string suitable for a
// multipart/byteranges Content-Type header field, for use with
// WriteMultipart. Callers need the boundary before the first byte of the
// response body is written (it must appear in the Content-Type header), so
// it is generated separately rather than returned from WriteMultipart.
func NewBoundary() string {
	var buf [16]byte
	// crypto/rand.Read on the platforms Go supports does not return a
	// short read without an error; a non-nil error here means the system
	// CSPRNG is unavailable, which is already fatal for the process in
	// practice. Fall back to a fixed-but-still-unguessable-length boundary
	// rather than a partially-zero one.
	if _, err := rand.Read(buf[:]); err != nil {
		copy(buf[:], "byterangefallback")
	}
	return "byterange-" + hex.EncodeToString(buf[:])
}

// WriteMultipart writes ranges as a multipart/byteranges response body
// (RFC 9110 §14.6) to w, using boundary as the MIME boundary — the same
// boundary the caller placed in the response's
// "Content-Type: multipart/byteranges; boundary=..." header field, typically
// obtained from NewBoundary. contentType is used as the Content-Type header
// of each body part, and size as the complete-length in each part's
// Content-Range field. Bytes for each range are read via
// ra.ReadAt(buf, range.Start). WriteMultipart reports the number of bytes
// written to w.
//
// RFC 9110 §15.3.7.2: "A server MUST NOT generate a multipart response to a
// request for a single range." WriteMultipart does not enforce this itself
// — it is a body-writing primitive, not a policy — so callers should send a
// single-range response (see ContentRange) instead of calling WriteMultipart
// when len(ranges) == 1. Serve does this automatically.
func WriteMultipart(w io.Writer, ranges Ranges, boundary, contentType string, size int64, ra io.ReaderAt) (int64, error) {
	cw := &countingWriter{w: w}
	mw := multipart.NewWriter(cw)
	if err := mw.SetBoundary(boundary); err != nil {
		return cw.n, fmt.Errorf("byterange: invalid multipart boundary: %w", err)
	}

	for _, r := range ranges {
		header := textproto.MIMEHeader{}
		if contentType != "" {
			header.Set("Content-Type", contentType)
		}
		header.Set("Content-Range", ContentRange(r, size))

		part, err := mw.CreatePart(header)
		if err != nil {
			return cw.n, fmt.Errorf("byterange: create multipart part: %w", err)
		}
		section := io.NewSectionReader(ra, r.Start, r.Length())
		if _, err := io.Copy(part, section); err != nil {
			return cw.n, fmt.Errorf("byterange: write multipart part %s: %w", ContentRange(r, size), err)
		}
	}

	if err := mw.Close(); err != nil {
		return cw.n, fmt.Errorf("byterange: close multipart writer: %w", err)
	}
	return cw.n, nil
}

// countingWriter wraps an io.Writer to report how many bytes passed through
// it, so WriteMultipart can report a byte count without every caller having
// to wrap w itself.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
