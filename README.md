# pkg

A toolkit of small, independently versioned Go libraries by Glasskube.

Each package lives in its own Go module and is documented on
[pkg.go.dev](https://pkg.go.dev/github.com/glasskube/pkg).

## Packages

- [`crypto`](https://pkg.go.dev/github.com/glasskube/pkg/crypto) — seals secrets at rest with AES-256-GCM.
- [`seekbuf`](https://pkg.go.dev/github.com/glasskube/pkg/seekbuf) — buffers an `io.Reader` into a seekable, randomly addressable stream, backed by memory or a temporary file.
