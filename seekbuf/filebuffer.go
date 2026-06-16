package seekbuf

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// FileBufferFactory creates [Buffer]s for temporary files in Dir.
// If Dir is the empty string, the default directory for temporary files is used (see [os.TempDir]).
type FileBufferFactory struct {
	Dir string
}

func (f *FileBufferFactory) New(src io.Reader) (result Buffer, rerr error) {
	tmpFile, err := os.CreateTemp(f.Dir, "blob")
	if err != nil {
		return nil, fmt.Errorf("failed to create tempfile: %w", err)
	}
	defer func() { rerr = errors.Join(rerr, tmpFile.Close()) }()
	if _, err := io.Copy(tmpFile, src); err != nil {
		return nil, fmt.Errorf("failed to copy source to tempfile: %w", err)
	}
	return &fileBuffer{fileName: tmpFile.Name()}, nil
}

// fileBuffer is file-backed [Buffer] implementation
type fileBuffer struct{ fileName string }

func (t *fileBuffer) Destroy() error {
	if err := os.Remove(t.fileName); err != nil {
		return fmt.Errorf("failed to cleanup tempfile: %w", err)
	}
	return nil
}

func (t *fileBuffer) Get() (ReadSeekAtCloser, error) {
	if file, err := os.Open(t.fileName); err != nil {
		return nil, fmt.Errorf("failed to open tempfile: %w", err)
	} else {
		return file, nil
	}
}
