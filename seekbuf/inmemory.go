package seekbuf

import (
	"bytes"
	"fmt"
	"io"
)

type inMemoryBuffer struct{ data []byte }

func (i *inMemoryBuffer) Destroy() error { return nil }

func (i *inMemoryBuffer) Get() (ReadSeekAtCloser, error) {
	return &noopReadSeekAtCloser{bytes.NewReader(i.data)}, nil
}

func NewInMemoryBUffer(src io.Reader) (result Buffer, rerr error) {
	if data, err := io.ReadAll(src); err != nil {
		return nil, fmt.Errorf("failed to read source stream into memory: %w", err)
	} else {
		return &inMemoryBuffer{data: data}, nil
	}
}

var InMemoryFactory = FactoryFunc(NewInMemoryBUffer)

type noopReadSeekAtCloser struct{ ReadSeekAt }

func (n *noopReadSeekAtCloser) Close() error { return nil }
