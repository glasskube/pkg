package seekbuf

import (
	"io"
	"strings"
	"testing"

	g "github.com/onsi/gomega"
)

const payload = "the quick brown fox"

// exerciseFactory runs the common [Buffer] contract against a [Factory].
func exerciseFactory(om g.Gomega, f Factory) {
	ts, err := f.New(strings.NewReader(payload))
	om.Expect(err).NotTo(g.HaveOccurred())
	defer func() { om.Expect(ts.Destroy()).To(g.Succeed()) }()

	rsc, err := ts.Get()
	om.Expect(err).NotTo(g.HaveOccurred())
	defer func() { _ = rsc.Close() }()

	got, err := io.ReadAll(rsc)
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(string(got)).To(g.Equal(payload))

	// ReaderAt: read "brown" at offset 10.
	buf := make([]byte, 5)
	_, err = rsc.ReadAt(buf, 10)
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(string(buf)).To(g.Equal("brown"))

	// Seeker: rewind and re-read fully.
	_, err = rsc.Seek(0, io.SeekStart)
	om.Expect(err).NotTo(g.HaveOccurred())
	again, err := io.ReadAll(rsc)
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(string(again)).To(g.Equal(payload))
}

func TestInMemoryFactory(t *testing.T) {
	exerciseFactory(g.NewWithT(t), InMemoryFactory)
}

func TestFileBufferFactory(t *testing.T) {
	exerciseFactory(g.NewWithT(t), &FileBufferFactory{Dir: t.TempDir()})
}

func TestSetDefault(t *testing.T) {
	om := g.NewWithT(t)
	orig := Default
	t.Cleanup(func() { Default = orig })

	tf := &FileBufferFactory{Dir: t.TempDir()}
	SetDefault(tf)
	om.Expect(Default).To(g.BeIdenticalTo(tf))

	ts, err := New(strings.NewReader(payload))
	om.Expect(err).NotTo(g.HaveOccurred())
	t.Cleanup(func() { _ = ts.Destroy() })

	om.Expect(ts).To(g.BeAssignableToTypeOf(&fileBuffer{}))
}
