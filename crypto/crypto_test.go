package crypto

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"testing"

	g "github.com/onsi/gomega"
)

const (
	key       = "correct horse battery staple"
	plaintext = "the quick brown fox"
)

// newT builds an [Encryptor] from k and fails the test if that does not succeed.
func newT(om g.Gomega, k string) *Encryptor {
	e, err := New([]byte(k))
	om.Expect(err).NotTo(g.HaveOccurred())
	return e
}

func TestRoundTrip(t *testing.T) {
	om := g.NewWithT(t)
	e := newT(om, key)

	ciphertext, err := e.Encrypt([]byte(plaintext))
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(ciphertext).NotTo(g.ContainSubstring(plaintext))

	got, err := e.Decrypt(ciphertext)
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(string(got)).To(g.Equal(plaintext))
}

func TestRoundTripString(t *testing.T) {
	om := g.NewWithT(t)
	e := newT(om, key)

	ciphertext, err := e.EncryptString(plaintext)
	om.Expect(err).NotTo(g.HaveOccurred())

	got, err := e.DecryptString(ciphertext)
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(got).To(g.Equal(plaintext))
}

// TestRoundTripPayloads covers payload edge cases around the AES block size.
func TestRoundTripPayloads(t *testing.T) {
	for name, payload := range map[string][]byte{
		"nil":         nil,
		"empty":       {},
		"single byte": {0x00},
		"block size":  bytes.Repeat([]byte{'a'}, aes.BlockSize),
		"large":       bytes.Repeat([]byte{'a'}, 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			e := newT(om, key)

			ciphertext, err := e.Encrypt(payload)
			om.Expect(err).NotTo(g.HaveOccurred())

			got, err := e.Decrypt(ciphertext)
			om.Expect(err).NotTo(g.HaveOccurred())
			om.Expect(got).To(g.HaveLen(len(payload)))
			om.Expect(bytes.Equal(got, payload)).To(g.BeTrue())
		})
	}
}

// TestKeyIsHashed asserts that keys shorter and longer than the 32 byte AES-256 key size are accepted.
func TestKeyIsHashed(t *testing.T) {
	for name, k := range map[string]string{
		"single byte":   "x",
		"exactly 32":    "0123456789abcdef0123456789abcdef",
		"much longer":   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef!",
		"non printable": "\x00\x01\x02",
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			e := newT(om, k)

			got, err := e.DecryptString(mustEncrypt(om, e))
			om.Expect(err).NotTo(g.HaveOccurred())
			om.Expect(got).To(g.Equal(plaintext))
		})
	}
}

func TestNewEmptyKey(t *testing.T) {
	for name, k := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			e, err := New(k)
			om.Expect(err).To(g.MatchError(ErrEmptyKey))
			om.Expect(e).To(g.BeNil())
		})
	}
}

// TestNonceIsFresh asserts that sealing the same plaintext twice does not produce the same ciphertext.
func TestNonceIsFresh(t *testing.T) {
	om := g.NewWithT(t)
	e := newT(om, key)

	first, second := mustEncrypt(om, e), mustEncrypt(om, e)
	om.Expect(first).NotTo(g.Equal(second))

	// The nonce prefix is what differs, the sealed remainder has a constant length.
	nonceSize := e.gcm.NonceSize()
	om.Expect(first[:nonceSize]).NotTo(g.Equal(second[:nonceSize]))
	om.Expect(first).To(g.HaveLen(nonceSize + len(plaintext) + e.gcm.Overhead()))
	om.Expect(second).To(g.HaveLen(len(first)))
}

func TestDecryptWrongKey(t *testing.T) {
	om := g.NewWithT(t)
	ciphertext := mustEncrypt(om, newT(om, key))

	got, err := newT(om, key+"!").Decrypt(ciphertext)
	om.Expect(err).To(g.HaveOccurred())
	om.Expect(got).To(g.BeNil())
}

// TestDecryptTampered asserts that GCM authentication rejects modified ciphertext.
func TestDecryptTampered(t *testing.T) {
	om := g.NewWithT(t)
	e := newT(om, key)
	ciphertext := mustEncrypt(om, e)

	for name, at := range map[string]int{
		"in the nonce":  0,
		"in the sealed": e.gcm.NonceSize(),
		"in the tag":    len(ciphertext) - 1,
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			tampered := bytes.Clone(ciphertext)
			tampered[at] ^= 0xff

			got, err := e.Decrypt(tampered)
			om.Expect(err).To(g.HaveOccurred())
			om.Expect(got).To(g.BeNil())
		})
	}
}

func TestDecryptTooShort(t *testing.T) {
	om := g.NewWithT(t)
	e := newT(om, key)

	for _, length := range []int{0, 1, e.gcm.NonceSize() - 1} {
		got, err := e.Decrypt(make([]byte, length))
		om.Expect(err).To(g.MatchError(ErrCiphertextTooShort))
		om.Expect(got).To(g.BeNil())
	}

	// A ciphertext holding a full nonce but no authentication tag is long enough to attempt to open.
	got, err := e.Decrypt(make([]byte, e.gcm.NonceSize()))
	om.Expect(err).To(g.HaveOccurred())
	om.Expect(err).NotTo(g.MatchError(ErrCiphertextTooShort))
	om.Expect(got).To(g.BeNil())
}

// TestConcurrentUse asserts that an Encryptor can be shared between goroutines.
func TestConcurrentUse(t *testing.T) {
	om := g.NewWithT(t)
	e := newT(om, key)

	const goroutines = 32
	errs := make(chan error, goroutines)
	for range goroutines {
		go func() {
			ciphertext, err := e.EncryptString(plaintext)
			if err != nil {
				errs <- err
				return
			}
			got, err := e.DecryptString(ciphertext)
			if err == nil && got != plaintext {
				err = fmt.Errorf("got %q, want %q", got, plaintext)
			}
			errs <- err
		}()
	}
	for range goroutines {
		om.Expect(<-errs).NotTo(g.HaveOccurred())
	}
}

// TestDecryptGolden pins the on-disk ciphertext format so that stored secrets stay readable.
// The golden value seals [plaintext] under [key] and must never be regenerated: changing the key derivation,
// the cipher or the nonce||sealed layout would make previously encrypted data undecryptable.
func TestDecryptGolden(t *testing.T) {
	om := g.NewWithT(t)
	e := newT(om, key)

	ciphertext, err := hex.DecodeString(
		"c59237728555d35223ba97b3805823e3bf4a544d8771cd0e02675bf24d1b8d332b15c937f4e0f212ddc01971697f14",
	)
	om.Expect(err).NotTo(g.HaveOccurred())

	got, err := e.DecryptString(ciphertext)
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(got).To(g.Equal(plaintext))
}

// mustEncrypt seals [plaintext] and fails the test if that does not succeed.
func mustEncrypt(om g.Gomega, e *Encryptor) []byte {
	ciphertext, err := e.EncryptString(plaintext)
	om.Expect(err).NotTo(g.HaveOccurred())
	return ciphertext
}
