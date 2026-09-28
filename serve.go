package byterange

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"time"
)

// ServeOptions describes the representation Serve responds with. Construct
// one per request: Open typically closes over req.Context() if the backing
// store needs it (e.g. an S3 GetObject call), since ServeOptions itself
// carries no context.
type ServeOptions struct {
	// Size is the total length in bytes of the representation. Required.
	Size int64
	// ContentType is sent as the response's (or, for a multipart response,
	// each part's) Content-Type header field. Optional.
	ContentType string
	// ETag is the representation's current strong or weak entity-tag,
	// including quotes (e.g. `"abc123"`). Optional; used for the response's
	// ETag header and for evaluating If-Range.
	ETag string
	// ModTime is the representation's current Last-Modified time. Optional;
	// used for the response's Last-Modified header and for evaluating
	// If-Range. Pass a strong validator only — see IfRangeSatisfied.
	ModTime time.Time
	// Open returns a reader for the n bytes starting at offset off. It is
	// called once for a full-body or single-range response, and once per
	// range for a multipart response. Required.
	Open func(off, n int64) (io.ReadCloser, error)
}

// Serve writes a full, Range-aware GET or HEAD response for opts to w,
// following RFC 9110 §14. It parses req's Range header field with Parse
// (rangeOpts configures Parse's defenses; see WithMaxRanges,
// WithMaxTotalBytes, WithCoalesce), evaluates If-Range if present, and then
// sends whichever of these RFC 9110 describes is appropriate:
//
//   - a full 200 response, when there is no usable Range header field —
//     absent, defeated by If-Range, using an unsupported unit
//     (ErrUnsupportedUnit), syntactically invalid (ErrMalformed), or
//     rejected by a defense (ErrTooManyRanges, ErrRangesTooLarge). RFC 9110
//     §14.2 permits treating all of these as "ignore the Range header
//     field."
//   - a single-range 206 response with a Content-Range header field
//     (§14.4), when exactly one satisfiable range remains after parsing.
//   - a multipart/byteranges 206 response (§14.6), when more than one
//     satisfiable range remains.
//   - a 416 response with a Content-Range: bytes */size header field
//     (§14.4, §15.5.17), when Parse returns ErrUnsatisfiable.
//
// For a HEAD request, Serve sends the same status and headers it would for
// the equivalent GET but never calls opts.Open and writes no body, per
// RFC 9110 §9.3.2. Range handling for methods other than GET and HEAD is not
// defined by RFC 9110 §14.2 ("GET is the only method for which range
// handling is defined"); Serve extends the same handling to HEAD to match
// net/http.ServeContent and near-universal server practice, and ignores any
// Range header field for every other method.
//
// Serve always sends "Accept-Ranges: bytes", so callers should not also
// call Serve for a resource that cannot actually support range requests.
func Serve(w http.ResponseWriter, req *http.Request, opts ServeOptions, rangeOpts ...Option) error {
	if opts.Size < 0 {
		return fmt.Errorf("byterange: negative Size %d", opts.Size)
	}
	if opts.Open == nil {
		return fmt.Errorf("byterange: ServeOptions.Open is required")
	}

	h := w.Header()
	h.Set("Accept-Ranges", "bytes")
	if opts.ETag != "" {
		h.Set("ETag", opts.ETag)
	}
	if !opts.ModTime.IsZero() {
		h.Set("Last-Modified", opts.ModTime.UTC().Format(http.TimeFormat))
	}

	isHead := req.Method == http.MethodHead
	rangeHandlingDefined := req.Method == http.MethodGet || isHead

	rangeHeader := ""
	if rangeHandlingDefined {
		rangeHeader = req.Header.Get("Range")
	}
	if rangeHeader != "" {
		if ifRange := req.Header.Get("If-Range"); ifRange != "" {
			if !IfRangeSatisfied(ifRange, opts.ETag, opts.ModTime) {
				rangeHeader = ""
			}
		}
	}

	if rangeHeader == "" {
		return serveFull(w, isHead, opts)
	}

	ranges, err := Parse(rangeHeader, opts.Size, rangeOpts...)
	switch {
	case errors.Is(err, ErrUnsatisfiable):
		h.Set("Content-Range", ContentRangeUnsatisfied(opts.Size))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return nil
	case err != nil:
		// ErrUnsupportedUnit, ErrMalformed, ErrTooManyRanges or
		// ErrRangesTooLarge: RFC 9110 §14.2 permits ignoring the header.
		return serveFull(w, isHead, opts)
	case len(ranges) == 1:
		return serveSingleRange(w, isHead, opts, ranges[0])
	default:
		return serveMultipartRange(w, isHead, opts, ranges)
	}
}

func serveFull(w http.ResponseWriter, isHead bool, opts ServeOptions) error {
	h := w.Header()
	if opts.ContentType != "" {
		h.Set("Content-Type", opts.ContentType)
	}
	h.Set("Content-Length", strconv.FormatInt(opts.Size, 10))
	w.WriteHeader(http.StatusOK)
	if isHead {
		return nil
	}
	rc, err := opts.Open(0, opts.Size)
	if err != nil {
		return fmt.Errorf("byterange: open full body: %w", err)
	}
	defer rc.Close()
	_, err = io.Copy(w, rc)
	if err != nil {
		return fmt.Errorf("byterange: write full body: %w", err)
	}
	return nil
}

func serveSingleRange(w http.ResponseWriter, isHead bool, opts ServeOptions, r Range) error {
	h := w.Header()
	if opts.ContentType != "" {
		h.Set("Content-Type", opts.ContentType)
	}
	h.Set("Content-Range", ContentRange(r, opts.Size))
	h.Set("Content-Length", strconv.FormatInt(r.Length(), 10))
	w.WriteHeader(http.StatusPartialContent)
	if isHead {
		return nil
	}
	rc, err := opts.Open(r.Start, r.Length())
	if err != nil {
		return fmt.Errorf("byterange: open range %s: %w", ContentRange(r, opts.Size), err)
	}
	defer rc.Close()
	if _, err := io.Copy(w, rc); err != nil {
		return fmt.Errorf("byterange: write range %s: %w", ContentRange(r, opts.Size), err)
	}
	return nil
}

func serveMultipartRange(w http.ResponseWriter, isHead bool, opts ServeOptions, ranges Ranges) error {
	boundary := NewBoundary()
	contentLength, err := multipartContentLength(ranges, boundary, opts.ContentType, opts.Size)
	if err != nil {
		return fmt.Errorf("byterange: compute multipart length: %w", err)
	}

	h := w.Header()
	h.Set("Content-Type", "multipart/byteranges; boundary="+boundary)
	h.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.WriteHeader(http.StatusPartialContent)
	if isHead {
		return nil
	}

	mw := multipart.NewWriter(w)
	if err := mw.SetBoundary(boundary); err != nil {
		return fmt.Errorf("byterange: set multipart boundary: %w", err)
	}
	for _, r := range ranges {
		header := textproto.MIMEHeader{}
		if opts.ContentType != "" {
			header.Set("Content-Type", opts.ContentType)
		}
		header.Set("Content-Range", ContentRange(r, opts.Size))

		part, err := mw.CreatePart(header)
		if err != nil {
			return fmt.Errorf("byterange: create multipart part %s: %w", ContentRange(r, opts.Size), err)
		}
		// One Open call per range, read sequentially: unlike an
		// io.ReaderAt adapter driven through io.NewSectionReader, this
		// never re-opens a fresh reader partway through a large range,
		// which matters when Open is backed by a remote call such as an
		// S3 GetObject.
		rc, err := opts.Open(r.Start, r.Length())
		if err != nil {
			return fmt.Errorf("byterange: open range %s: %w", ContentRange(r, opts.Size), err)
		}
		_, copyErr := io.Copy(part, rc)
		closeErr := rc.Close()
		if copyErr != nil {
			return fmt.Errorf("byterange: write multipart part %s: %w", ContentRange(r, opts.Size), copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("byterange: close range reader %s: %w", ContentRange(r, opts.Size), closeErr)
		}
	}
	if err := mw.Close(); err != nil {
		return fmt.Errorf("byterange: close multipart writer: %w", err)
	}
	return nil
}

// multipartContentLength computes the exact byte length WriteMultipart would
// produce for the same arguments, without reading any range's actual
// content: it drives the same mime/multipart.Writer to measure every part's
// boundary-plus-headers overhead, then adds each range's length arithmetic-
// ally instead of copying real bytes. This lets Serve send an accurate
// Content-Length for a multipart/byteranges response — which RFC 9110
// §15.3.7 notes is not always the complete representation length but does
// not say a server may omit it — without a wasted read pass over
// potentially remote data.
func multipartContentLength(ranges Ranges, boundary, contentType string, size int64) (int64, error) {
	cw := &countingWriter{w: io.Discard}
	mw := multipart.NewWriter(cw)
	if err := mw.SetBoundary(boundary); err != nil {
		return 0, err
	}
	for _, r := range ranges {
		header := textproto.MIMEHeader{}
		if contentType != "" {
			header.Set("Content-Type", contentType)
		}
		header.Set("Content-Range", ContentRange(r, size))
		if _, err := mw.CreatePart(header); err != nil {
			return 0, err
		}
		cw.n += r.Length()
	}
	if err := mw.Close(); err != nil {
		return 0, err
	}
	return cw.n, nil
}
