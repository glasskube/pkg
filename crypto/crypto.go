package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
)

var (
	// ErrEmptyKey is returned by [New] if the given key contains no bytes.
	ErrEmptyKey = errors.New("encryption key is empty")

	// ErrCiphertextTooShort is returned by [Encryptor.Decrypt] if the given ciphertext is shorter than the
	// nonce it is expected to be prefixed with.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// Encryptor seals and opens secrets with AES-256-GCM.
// The zero value is not usable, use [New] to obtain an Encryptor.
// An Encryptor is safe for concurrent use by multiple goroutines.
type Encryptor struct {
	gcm cipher.AEAD
}

// New builds an [Encryptor] from key. The key is hashed to 32 bytes, so any non-empty length is accepted.
// See the package documentation for what makes a suitable key.
func New(key []byte) (*Encryptor, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	derived := sha256.Sum256(key)
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return &Encryptor{gcm: gcm}, nil
}

// Encrypt seals plaintext and returns the ciphertext in the form nonce||sealed.
// Every call draws a fresh random nonce, so sealing the same plaintext twice yields different ciphertexts.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	return e.EncryptWithAAD(plaintext, nil)
}

// EncryptWithAAD seals plaintext like [Encryptor.Encrypt] does and additionally authenticates aad, binding the
// ciphertext to metadata that is stored in the clear next to it. The aad is neither encrypted nor part of the
// ciphertext, it only has to be presented again to [Encryptor.DecryptWithAAD]. A nil aad is what Encrypt uses.
func (e *Encryptor) EncryptWithAAD(plaintext, aad []byte) ([]byte, error) {
	return e.sealAppend(nil, plaintext, aad)
}

// sealAppend appends nonce||sealed to dst, so that a caller can prefix the ciphertext with a header of its own
// without copying the result a second time. With an empty dst it is [Encryptor.EncryptWithAAD].
func (e *Encryptor) sealAppend(dst, plaintext, aad []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	dst = slices.Grow(dst, nonceSize+len(plaintext)+e.gcm.Overhead())
	nonce := dst[len(dst) : len(dst)+nonceSize]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return e.gcm.Seal(dst[:len(dst)+nonceSize], nonce, plaintext, aad), nil
}

// Decrypt opens a ciphertext produced by [Encryptor.Encrypt] and returns the plaintext.
// It fails if the ciphertext was sealed with a different key or has been tampered with.
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	return e.DecryptWithAAD(ciphertext, nil)
}

// DecryptWithAAD opens a ciphertext produced by [Encryptor.EncryptWithAAD] and returns the plaintext.
// It fails like [Encryptor.Decrypt] does, and also if aad is not byte for byte the data it was sealed with.
func (e *Encryptor) DecryptWithAAD(ciphertext, aad []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}
	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// EncryptString seals plaintext like [Encryptor.Encrypt] does, accepting the plaintext as a string.
func (e *Encryptor) EncryptString(plaintext string) ([]byte, error) {
	return e.Encrypt([]byte(plaintext))
}

// DecryptString opens ciphertext like [Encryptor.Decrypt] does, returning the plaintext as a string.
func (e *Encryptor) DecryptString(ciphertext []byte) (string, error) {
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
