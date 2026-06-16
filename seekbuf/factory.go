package seekbuf

import "io"

type Factory interface {
	New(io.Reader) (Buffer, error)
}

type FactoryFunc func(io.Reader) (Buffer, error)

func (f FactoryFunc) New(r io.Reader) (Buffer, error) { return f(r) }

var Default Factory = InMemoryFactory

func SetDefault(f Factory) {
	Default = f
}
