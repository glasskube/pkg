package seekbuf

import (
	"io"
)

type ReadSeekAt interface {
	io.ReadSeeker
	io.ReaderAt
}

type ReadSeekAtCloser interface {
	ReadSeekAt
	io.Closer
}

// Buffer represents a resource that can be accessed via io interfaces and destroyed if no longer needed.
type Buffer interface {
	Get() (ReadSeekAtCloser, error)
	Destroy() error
}

// New creates a new [Buffer] that buffers an [io.Reader] into a [ReadSeekAtCloser] (seekable and randomly
// addressable via [io.ReaderAt], e.g. for use with [io.NewSectionReader]) by either buffering it in memory
// or writing it to a temporary file.
func New(src io.Reader) (Buffer, error) {
	return Default.New(src)
}
