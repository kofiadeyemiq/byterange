# byterange

Range header parsing and serving for handlers that don't have an `io.ReadSeeker`.

```go
byterange.Serve(w, req, byterange.ServeOptions{
    Size:        size,
    ContentType: "video/mp4",
    ETag:        etag,
    Open: func(off, n int64) (io.ReadCloser, error) {
        return s3Client.GetObjectRange(ctx, bucket, key, off, n)
    },
})
```

## Why

`net/http.ServeContent` handles Range headers, but only against an
`io.ReadSeeker`. A handler backed by object storage, a remote origin, or
computed content has no seekable value to hand it — it can only open a given
byte offset and length on demand — so it either drops Range support or
hand-rolls a parser. A search of pkg.go.dev turned up Range parsers embedded
inside larger projects, not a maintained standalone one.

Hand-rolling this is also where the security bugs live. `net/http.ServeContent`
itself gets part of it wrong: RFC 9110 §14.2 says an origin server "MUST ignore
a Range header field that contains a range unit it does not understand," but
`ServeContent` answers a header like `Range: items=0-5` with 416.

Measured: `go test -run TestStdlibComparison_UnknownUnit -v .`

```
stdlib ServeContent: status 416, body "invalid range\n"
byterange.Serve:     status 200, body "the quick brown fox jumps over the lazy dog, thirty-six"
```

That's a known, open Go bug: [golang/go#81508](https://github.com/golang/go/issues/81508),
with an open fix at [golang/go#81746](https://github.com/golang/go/pull/81746) at
the time this package was written.

The other gap is the amplification pattern behind
[CVE-2011-3192](https://httpd.apache.org/security/CVE-2011-3192.txt), the 2011
Apache httpd "Range header" denial-of-service: a Range header naming many
small or overlapping ranges costs the client almost nothing to send and the
server far more to parse and serve as a multipart response.
`net/http.ServeContent` only rejects a Range header when the *sum of the
requested lengths* exceeds the file size — not the range count, and not the
multipart overhead those ranges produce.

Measured: `go test -run TestStdlibComparison_ManySmallRanges -v .`, 1300
single-byte, non-overlapping, ascending ranges against a 10000-byte body:

```
stdlib ServeContent: status 206, body 190056 bytes (19.0x)
byterange.Serve:     status 200, body 10000 bytes (1.0x)
```

`byterange.Parse`'s default range-count cap (16, see the `Options` table)
rejects that header outright, so `Serve` falls back to the ordinary full
response instead of amplifying it. RFC 9110 §17.15 names exactly this pattern
as a denial-of-service concern and says servers "ought to ignore, coalesce, or
reject" it.

## Installation

```sh
go get github.com/__GH_OWNER__/byterange
```

Go 1.23 or later. No runtime dependencies.

## Usage

### Parse a Range header

```go
ranges, err := byterange.Parse(req.Header.Get("Range"), size)
switch {
case errors.Is(err, byterange.ErrUnsatisfiable):
    w.Header().Set("Content-Range", byterange.ContentRangeUnsatisfied(size))
    w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
case err != nil:
    // ErrUnsupportedUnit, ErrMalformed, ErrTooManyRanges, ErrRangesTooLarge:
    // RFC 9110 §14.2 permits ignoring the header. Serve the full body.
default:
    // ranges is non-empty, ascending, and clamped to [0, size).
}
```

### Serve a resource that can open arbitrary byte ranges

`Serve` handles the whole request: full body, single-range 206,
multipart/byteranges 206, or 416, plus `If-Range`, `Accept-Ranges`, and HEAD.

```go
func handleVideo(w http.ResponseWriter, req *http.Request) {
    byterange.Serve(w, req, byterange.ServeOptions{
        Size:        video.Size,
        ContentType: "video/mp4",
        ETag:        video.ETag,
        ModTime:     video.ModTime,
        Open: func(off, n int64) (io.ReadCloser, error) {
            return storage.OpenRange(req.Context(), video.Key, off, n)
        },
    })
}
```

### Serve a resource you already have an `io.ReaderAt` for

For a local file or an in-memory buffer, `WriteMultipart` and `ContentRange`
are the lower-level pieces `Serve` builds on:

```go
if len(ranges) == 1 {
    w.Header().Set("Content-Range", byterange.ContentRange(ranges[0], size))
    w.WriteHeader(http.StatusPartialContent)
    io.Copy(w, io.NewSectionReader(readerAt, ranges[0].Start, ranges[0].Length()))
    return
}

boundary := byterange.NewBoundary()
w.Header().Set("Content-Type", "multipart/byteranges; boundary="+boundary)
w.WriteHeader(http.StatusPartialContent)
byterange.WriteMultipart(w, ranges, boundary, contentType, size, readerAt)
```

### Honor If-Range

```go
if req.Header.Get("Range") != "" &&
    !byterange.IfRangeSatisfied(req.Header.Get("If-Range"), etag, modTime) {
    // validator is stale: serve the full, current representation instead
}
```

`Serve` already does this internally when `ServeOptions.ETag` or `ModTime` is
set; call `IfRangeSatisfied` directly only when building a response by hand.

### Tune the defenses

```go
ranges, err := byterange.Parse(header, size,
    byterange.WithMaxRanges(4),
    byterange.WithMaxTotalBytes(50<<20),
)
```

## Reference

### `Parse(header string, size int64, opts ...Option) (Ranges, error)`

Parses a Range header field value against a representation of `size` bytes.

| Error | Meaning | Caller should |
| --- | --- | --- |
| `ErrUnsupportedUnit` | Range unit is not `bytes` | Ignore the header, serve normally |
| `ErrMalformed` | Not a valid ranges-specifier (RFC 9110 §14.1.1) | Ignore the header, serve normally |
| `ErrTooManyRanges` | More ranges than `WithMaxRanges` allows | Ignore the header, serve normally |
| `ErrRangesTooLarge` | More total bytes than `WithMaxTotalBytes` allows | Ignore the header, serve normally |
| `ErrUnsatisfiable` | Valid header, no range is satisfiable | Respond 416 with `ContentRangeUnsatisfied(size)` |

### Options

| Option | Default | What it bounds |
| --- | --- | --- |
| `WithMaxRanges(n)` | 16 | Number of range-specs per header. `n <= 0` disables it. |
| `WithMaxTotalBytes(n)` | 0 (disabled) | Total bytes across all ranges, after coalescing. |
| `WithCoalesce(enabled)` | `true` | Merge overlapping or touching ranges into one. |

### Types

- `Range{Start, End int64}` — an inclusive byte range. `Length()` returns `End - Start + 1`.
- `Ranges []Range` — a validated, ascending range set. `TotalBytes()` sums every range's length.

### Response helpers

- `ContentRange(r Range, size int64) string` — a `Content-Range` value for a 206.
- `ContentRangeUnsatisfied(size int64) string` — a `Content-Range` value for a 416.
- `NewBoundary() string` — a random `multipart/byteranges` boundary.
- `WriteMultipart(w io.Writer, ranges Ranges, boundary, contentType string, size int64, ra io.ReaderAt) (int64, error)`
  — writes a `multipart/byteranges` body; returns bytes written.
- `IfRangeSatisfied(ifRange, etag string, modTime time.Time) bool` — evaluates
  an `If-Range` precondition (RFC 9110 §13.1.5) by strong comparison.

### `Serve(w http.ResponseWriter, req *http.Request, opts ServeOptions, rangeOpts ...Option) error`

| `ServeOptions` field | Required | Meaning |
| --- | --- | --- |
| `Size` | yes | Total length in bytes |
| `ContentType` | no | Sent as `Content-Type` |
| `ETag` | no | Sent as `ETag`; used for `If-Range` |
| `ModTime` | no | Sent as `Last-Modified`; used for `If-Range` |
| `Open` | yes | `func(off, n int64) (io.ReadCloser, error)` |

## How it works

`Parse` splits the header on `=`, checks the unit case-insensitively against
`bytes`, and rejects the whole header outright if there are more range-specs
than `WithMaxRanges` allows — before parsing a single one, so a hostile header
costs this package O(1) work instead of O(n). Each remaining range-spec is
parsed per RFC 9110 §14.1.2's grammar (`first-last`, `first-`, `-suffix`),
clamped against `size`, and dropped if unsatisfiable; any spec that is
syntactically invalid invalidates the whole header (RFC 9110 §14.1.1). What's
left is sorted and coalesced (RFC 9110 §15.3.7.2), then checked against
`WithMaxTotalBytes`.

`Serve` layers HTTP semantics on top: it evaluates `If-Range`, maps each
`Parse` outcome to the response RFC 9110 §14.2 describes for it, and for a
multipart response precomputes the exact `Content-Length` by driving the same
`mime/multipart.Writer` machinery `WriteMultipart` uses — accounting for each
part's boundary and header bytes without reading any of the range's actual
content — so it can send an accurate `Content-Length` without a wasted read
pass over what may be remote data.

## Limitations

- Range units other than `bytes` are not supported (RFC 9110 defines byte
  ranges as the only unit registered by this specification); a header using
  another unit is always treated as absent, matching RFC 9110 §14.2's MUST.
- Coalescing only merges ranges that overlap or touch. RFC 9110 §15.3.7.2 also
  permits merging ranges separated by a small gap (smaller than the multipart
  overhead); this package does not, so it never sends a byte that wasn't
  explicitly requested.
- `Serve` handles `Range` and `If-Range` only. Other conditional request
  headers (`If-None-Match`, `If-Modified-Since`, `If-Match`,
  `If-Unmodified-Since`) are the caller's responsibility, evaluated before
  calling `Serve`.
- `Serve` extends Range handling to HEAD requests to match
  `net/http.ServeContent` and common server practice; RFC 9110 §14.2 only
  defines range handling for GET.
- No `Content-Encoding` awareness: ranges are always byte offsets into the
  representation as `Open` or the `io.ReaderAt` returns it. RFC 9110 §14.1.2
  notes ranges are computed against the encoded bytes when a content coding is
  applied — this package does not encode or decode on your behalf.
- `WriteMultipart`'s `io.ReaderAt` path issues potentially many small
  `ReadAt` calls per range for a large range (whatever `io.Copy`'s internal
  buffer size drives); `Serve`'s `Open`-based path instead opens each range
  exactly once, which matters more for a remote source.

## Compatibility

Tested with `go1.27.1 darwin/arm64`. CI runs the same checks on Ubuntu with Go
1.23 (`.github/workflows/test.yml`); other platforms are untested.

## Development

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
gofmt -l .              # must print nothing
go test -fuzz=FuzzParse -fuzztime=30s .
go run ./bench/amplify
```

## License

MIT, see [LICENSE](LICENSE).
