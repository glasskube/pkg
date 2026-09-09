package crypto

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	g "github.com/onsi/gomega"
)

// Base64 keys of exactly [MinKeyLen] bytes. keyA is the key of the golden envelopes and must not change.
const (
	keyA     = "Y29ycmVjdCBob3JzZSBiYXR0ZXJ5IHN0YXBsZSA0MiE=" // "correct horse battery staple 42!"
	keyB     = "YW4gZW50aXJlbHkgZGlmZmVyZW50IDMyYiBrZXkhISE=" // "an entirely different 32b key!!!"
	shortKey = "dGhpcyBrZXkgaXMgMzEgYnl0ZXMgbG9uZywgb25lIQ==" // 31 bytes, one short
)

// compressible is a payload above [compressThreshold] that deflate can shrink.
var compressible = bytes.Repeat([]byte(plaintext+" "), 64)

// parseT builds a [Keyring] from spec and fails the test if that does not succeed.
func parseT(om g.Gomega, spec string) *Keyring {
	k, err := ParseKeyring(spec)
	om.Expect(err).NotTo(g.HaveOccurred())
	return k
}

// sealT seals payload with k and fails the test if that does not succeed.
func sealT(om g.Gomega, k *Keyring, payload []byte, opts ...EncryptOption) []byte {
	value, err := k.Encrypt(payload, opts...)
	om.Expect(err).NotTo(g.HaveOccurred())
	return value
}

// withByte returns a copy of value with the byte at index at replaced.
func withByte(value []byte, at int, b byte) []byte {
	modified := bytes.Clone(value)
	modified[at] = b
	return modified
}

func TestKeyringRoundTrip(t *testing.T) {
	for name, payload := range map[string][]byte{
		"nil":   nil,
		"text":  []byte(plaintext),
		"large": bytes.Repeat([]byte{'a'}, 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			k := parseT(om, keyA)

			value := sealT(om, k, payload)
			om.Expect(value[0]).To(g.Equal(FormatVersion))
			om.Expect(value[1]).To(g.Equal(k.ActiveKeyID()))
			om.Expect(value[2]).To(g.BeZero())

			got, err := k.Decrypt(value)
			om.Expect(err).NotTo(g.HaveOccurred())
			om.Expect(got).To(g.HaveLen(len(payload)))
			om.Expect(bytes.Equal(got, payload)).To(g.BeTrue())
		})
	}
}

// TestKeyringNonceIsFresh asserts that sealing the same plaintext twice does not produce the same value.
func TestKeyringNonceIsFresh(t *testing.T) {
	om := g.NewWithT(t)
	k := parseT(om, keyA)

	first, second := sealT(om, k, []byte(plaintext)), sealT(om, k, []byte(plaintext))
	om.Expect(first).NotTo(g.Equal(second))

	// Only the ciphertext differs, the header is the same and the length is constant.
	om.Expect(first[:headerLen]).To(g.Equal(second[:headerLen]))
	gcm := k.active.enc.gcm
	om.Expect(first).To(g.HaveLen(headerLen + gcm.NonceSize() + len(plaintext) + gcm.Overhead()))
	om.Expect(second).To(g.HaveLen(len(first)))
}

// TestKeyringRotation asserts that a rotated keyring writes under its new key, still reads a value its old key
// sealed, and stops reading that value once the old key is retired.
func TestKeyringRotation(t *testing.T) {
	om := g.NewWithT(t)

	before := parseT(om, "0:"+keyA)
	om.Expect(before.ActiveKeyID()).To(g.Equal(byte(0)))
	old := sealT(om, before, []byte(plaintext))
	om.Expect(old[1]).To(g.Equal(byte(0)))

	rotated := parseT(om, "1:"+keyB+",0:"+keyA)
	om.Expect(rotated.ActiveKeyID()).To(g.Equal(byte(1)))
	om.Expect(rotated.KeyIDs()).To(g.Equal([]byte{1, 0}))

	// A value written before the rotation is still readable, because its key is still configured.
	got, err := rotated.Decrypt(old)
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(string(got)).To(g.Equal(plaintext))

	// New writes use the new key.
	fresh := sealT(om, rotated, []byte(plaintext))
	om.Expect(fresh[1]).To(g.Equal(byte(1)))
	got, err = rotated.Decrypt(fresh)
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(string(got)).To(g.Equal(plaintext))

	// Once the old key is retired its values are no longer readable, but the new ones still are.
	retired := parseT(om, "1:"+keyB)
	got, err = retired.Decrypt(old)
	om.Expect(err).To(g.MatchError(ErrUnknownKeyID))
	om.Expect(got).To(g.BeNil())

	got, err = retired.Decrypt(fresh)
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(string(got)).To(g.Equal(plaintext))
}

// TestKeyringDecryptWrongKey asserts that a value is not readable by a keyring that holds a different key
// under the same id.
func TestKeyringDecryptWrongKey(t *testing.T) {
	om := g.NewWithT(t)
	value := sealT(om, parseT(om, "0:"+keyA), []byte(plaintext))

	got, err := parseT(om, "0:"+keyB).Decrypt(value)
	om.Expect(err).To(g.HaveOccurred())
	om.Expect(err).NotTo(g.MatchError(ErrUnknownKeyID))
	om.Expect(got).To(g.BeNil())
}

// TestKeyringDecryptMalformed asserts that every way a value can fail to be an envelope this code understands
// is reported distinguishably.
func TestKeyringDecryptMalformed(t *testing.T) {
	om := g.NewWithT(t)
	k := parseT(om, "0:"+keyA)
	value := sealT(om, k, []byte(plaintext))

	type malformed struct {
		err   error
		value []byte
	}

	for name, m := range map[string]malformed{
		"empty":                {ErrValueTooShort, nil},
		"header truncated":     {ErrValueTooShort, value[:headerLen-1]},
		"reserved version 0":   {ErrReservedVersion, withByte(value, 0, reservedVersion)},
		"unknown version":      {ErrUnknownVersion, withByte(value, 0, FormatVersion+1)},
		"unconfigured key id":  {ErrUnknownKeyID, withByte(value, 1, 9)},
		"unknown flag bit":     {ErrUnknownFlag, withByte(value, 2, 1<<1)},
		"ciphertext truncated": {ErrCiphertextTooShort, value[:headerLen+1]},
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			got, err := k.Decrypt(m.value)
			om.Expect(err).To(g.MatchError(m.err))
			om.Expect(got).To(g.BeNil())
		})
	}
}

// TestKeyringRoundTripWithAAD asserts that a bound value opens under the data it was bound to, and that the
// header stays authenticated alongside it.
func TestKeyringRoundTripWithAAD(t *testing.T) {
	om := g.NewWithT(t)
	k := parseT(om, keyA)

	value := sealT(om, k, []byte(plaintext), WithAAD([]byte(aad)))
	om.Expect(value).NotTo(g.ContainSubstring(aad))
	// The aad is authenticated rather than stored, so a bound value is no longer than an unbound one.
	om.Expect(value).To(g.HaveLen(len(sealT(om, k, []byte(plaintext)))))

	got, err := k.DecryptWithAAD(value, []byte(aad))
	om.Expect(err).NotTo(g.HaveOccurred())
	om.Expect(string(got)).To(g.Equal(plaintext))

	// The header is part of the authenticated data, in front of the aad.
	got, err = k.DecryptWithAAD(withByte(value, 2, flagCompressed), []byte(aad))
	om.Expect(err).To(g.HaveOccurred())
	om.Expect(got).To(g.BeNil())
}

// TestKeyringAADMismatch asserts that a value only opens under the exact data it was bound to, and that an
// unbound value and a bound one are not interchangeable.
func TestKeyringAADMismatch(t *testing.T) {
	type mismatch struct{ sealed, opened []byte }

	for name, m := range map[string]mismatch{
		"different aad":     {[]byte(aad), []byte("jumps over the lazy cat")},
		"aad only on write": {[]byte(aad), nil},
		"aad only on read":  {nil, []byte(aad)},
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			k := parseT(om, keyA)

			value := sealT(om, k, []byte(plaintext), WithAAD(m.sealed))
			got, err := k.DecryptWithAAD(value, m.opened)
			om.Expect(err).To(g.HaveOccurred())
			om.Expect(got).To(g.BeNil())
		})
	}
}

// TestKeyringAADEmptyIsUnbound asserts that binding nothing is the same as not binding, which is what keeps
// [WithAAD] from changing the envelope of a value that does not use it.
func TestKeyringAADEmptyIsUnbound(t *testing.T) {
	om := g.NewWithT(t)
	k := parseT(om, keyA)

	for _, value := range [][]byte{
		sealT(om, k, []byte(plaintext), WithAAD(nil)),
		sealT(om, k, []byte(plaintext), WithAAD([]byte{})),
	} {
		got, err := k.Decrypt(value)
		om.Expect(err).NotTo(g.HaveOccurred())
		om.Expect(string(got)).To(g.Equal(plaintext))

		got, err = k.DecryptWithAAD(value, []byte{})
		om.Expect(err).NotTo(g.HaveOccurred())
		om.Expect(string(got)).To(g.Equal(plaintext))
	}
}

// TestKeyringHeaderIsAuthenticated asserts that the header is bound to the ciphertext, so that a modification
// of it that is still well formed fails to open rather than yielding a different plaintext.
func TestKeyringHeaderIsAuthenticated(t *testing.T) {
	om := g.NewWithT(t)
	k := parseT(om, "0:"+keyA+",1:"+keyB)

	stored := sealT(om, k, compressible)
	om.Expect(stored[2] & flagCompressed).To(g.BeZero())
	deflated := sealT(om, k, compressible, WithCompression())
	om.Expect(deflated[2] & flagCompressed).NotTo(g.BeZero())

	for name, value := range map[string][]byte{
		"compressed flag set on a stored payload":       withByte(stored, 2, flagCompressed),
		"compressed flag cleared on a deflated payload": withByte(deflated, 2, 0),
		"key id repointed to another configured key":    withByte(stored, 1, 1),
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			got, err := k.Decrypt(value)
			om.Expect(err).To(g.HaveOccurred())
			om.Expect(got).To(g.BeNil())
		})
	}
}

func TestParseKeyring(t *testing.T) {
	type parsed struct {
		spec string
		ids  []byte
	}

	for name, p := range map[string]parsed{
		"single entry without an id":    {keyA, []byte{0}},
		"single entry with an id":       {"7:" + keyA, []byte{7}},
		"first entry is active":         {"3:" + keyA + ",1:" + keyB, []byte{3, 1}},
		"whitespace is trimmed":         {" 3 : " + keyA + " , 1 : " + keyB + " ", []byte{3, 1}},
		"empty entries are skipped":     {"3:" + keyA + ",,1:" + keyB + ",", []byte{3, 1}},
		"the highest id is in range":    {"255:" + keyA, []byte{255}},
		"an explicit id may still be 0": {"0:" + keyA, []byte{0}},
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			k := parseT(om, p.spec)

			om.Expect(k.ActiveKeyID()).To(g.Equal(p.ids[0]))
			om.Expect(k.KeyIDs()).To(g.Equal(p.ids))

			got, err := k.Decrypt(sealT(om, k, []byte(plaintext)))
			om.Expect(err).NotTo(g.HaveOccurred())
			om.Expect(string(got)).To(g.Equal(plaintext))
		})
	}
}

func TestParseKeyringInvalid(t *testing.T) {
	for name, i := range map[string]struct {
		err  error
		spec string
	}{
		"empty spec":              {ErrNoKeys, ""},
		"whitespace only":         {ErrNoKeys, " \t "},
		"separators only":         {ErrNoKeys, ",,"},
		"duplicate id":            {ErrDuplicateKeyID, "0:" + keyA + ",0:" + keyB},
		"duplicate implicit id":   {ErrDuplicateKeyID, keyA + ",0:" + keyB},
		"id is not a number":      {ErrInvalidKeyID, "x:" + keyA},
		"id is missing":           {ErrInvalidKeyID, ":" + keyA},
		"id is negative":          {ErrInvalidKeyID, "-1:" + keyA},
		"id is above the range":   {ErrInvalidKeyID, "256:" + keyA},
		"key is not base64":       {ErrInvalidKey, "0:not valid base64!"},
		"key is unpadded base64":  {ErrInvalidKey, "0:" + keyA[:len(keyA)-1]},
		"key is too short":        {ErrKeyTooShort, "0:" + shortKey},
		"key is missing":          {ErrInvalidKey, "0:"},
		"key is whitespace":       {ErrInvalidKey, "0:   "},
		"a later entry is broken": {ErrKeyTooShort, "0:" + keyA + ",1:" + shortKey},
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			k, err := ParseKeyring(i.spec)
			om.Expect(err).To(g.MatchError(i.err))
			om.Expect(k).To(g.BeNil())
		})
	}
}

// TestKeyIDsIsCopy asserts that a caller cannot reach the ids of a keyring through the slice it returns.
func TestKeyIDsIsCopy(t *testing.T) {
	om := g.NewWithT(t)
	k := parseT(om, "3:"+keyA+",1:"+keyB)

	ids := k.KeyIDs()
	ids[0] = 9
	om.Expect(k.KeyIDs()).To(g.Equal([]byte{3, 1}))
	om.Expect(k.ActiveKeyID()).To(g.Equal(byte(3)))
}

// TestSubkeysAreIndependent asserts that a key is expanded into an encryption and a MAC subkey that are
// neither each other nor the configured key itself.
func TestSubkeysAreIndependent(t *testing.T) {
	om := g.NewWithT(t)
	secret, err := base64.StdEncoding.DecodeString(keyA)
	om.Expect(err).NotTo(g.HaveOccurred())
	k := parseT(om, keyA)

	encKey, err := hkdf.Key(sha256.New, secret, nil, encryptInfo, subkeyLen)
	om.Expect(err).NotTo(g.HaveOccurred())

	om.Expect(k.active.mac).To(g.HaveLen(subkeyLen))
	om.Expect(k.active.mac).NotTo(g.Equal(encKey))
	om.Expect(k.active.mac).NotTo(g.Equal(secret))
	om.Expect(encKey).NotTo(g.Equal(secret))
}

// TestHMAC asserts that a digest is deterministic, keyed and one way.
func TestHMAC(t *testing.T) {
	om := g.NewWithT(t)
	k := parseT(om, keyA)

	digest := k.HMAC([]byte(plaintext))
	om.Expect(digest).To(g.HaveLen(sha256.Size))
	om.Expect(digest).To(g.Equal(k.HMAC([]byte(plaintext))))
	om.Expect(digest).NotTo(g.ContainSubstring(plaintext))
	om.Expect(digest).NotTo(g.Equal(k.HMAC([]byte(plaintext + "!"))))

	// The digest is keyed with the mac subkey, so another key derives another one.
	om.Expect(digest).NotTo(g.Equal(parseT(om, keyB).HMAC([]byte(plaintext))))
	// It is not the digest of the mac subkey used as the message either.
	om.Expect(digest).NotTo(g.Equal(macSum([]byte(plaintext), k.active.mac)))
}

// TestHMACAll asserts that every configured key derives a digest, the active one first, so that a lookup finds
// a credential that was hashed before a rotation.
func TestHMACAll(t *testing.T) {
	om := g.NewWithT(t)
	rotated := parseT(om, "1:"+keyB+",0:"+keyA)

	all := rotated.HMACAll([]byte(plaintext))
	om.Expect(all).To(g.HaveLen(2))
	om.Expect(all[0]).NotTo(g.Equal(all[1]))

	// The first digest is the active key's, which is what HMAC derives on write.
	om.Expect(all[0]).To(g.Equal(rotated.HMAC([]byte(plaintext))))
	// The trailing digest is the one the retired key derived before the rotation.
	om.Expect(all[1]).To(g.Equal(parseT(om, "0:"+keyA).HMAC([]byte(plaintext))))

	// A single key keyring derives exactly one digest.
	om.Expect(parseT(om, keyA).HMACAll([]byte(plaintext))).To(g.HaveLen(1))
}

// TestEncryptCompression asserts that compression is opt in, best effort, and round trips.
func TestEncryptCompression(t *testing.T) {
	incompressible := make([]byte, 4096)
	_, err := rand.Read(incompressible)
	g.NewWithT(t).Expect(err).NotTo(g.HaveOccurred())

	type compression struct {
		payload     []byte
		opts        []EncryptOption
		wantFlags   byte
		wantSmaller bool
	}

	compress := []EncryptOption{WithCompression()}

	for name, c := range map[string]compression{
		"a large compressible payload":  {compressible, compress, flagCompressed, true},
		"an incompressible payload":     {incompressible, compress, 0, false},
		"a payload below the threshold": {bytes.Repeat([]byte{'a'}, compressThreshold-1), compress, 0, false},
		"compression not requested":     {compressible, nil, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			k := parseT(om, keyA)

			value := sealT(om, k, c.payload, c.opts...)
			om.Expect(value[2]).To(g.Equal(c.wantFlags))
			if c.wantSmaller {
				om.Expect(len(value)).To(g.BeNumerically("<", len(c.payload)))
			} else {
				om.Expect(len(value)).To(g.BeNumerically(">=", len(c.payload)))
			}

			got, err := k.Decrypt(value)
			om.Expect(err).NotTo(g.HaveOccurred())
			om.Expect(bytes.Equal(got, c.payload)).To(g.BeTrue())
		})
	}
}

// TestKeyringDecryptGolden pins the stored envelope format. The golden values seal their plaintext under
// [keyA] with key id 3 and must never be regenerated: changing the envelope layout, the subkey derivation, the
// additional authenticated data, the cipher or the compression would make encrypted data undecryptable.
func TestKeyringDecryptGolden(t *testing.T) {
	type golden struct {
		value string
		want  []byte
		aad   []byte
	}

	for name, gold := range map[string]golden{
		"stored": {
			"010300e1d5ca7dd5a9b410d49eace966300333753405ec684739de2e373fe90d9221d79b8fc4dc9146fc352baa98dfa8403e",
			[]byte(plaintext),
			nil,
		},
		"deflated": {
			"0103010ddfe13293a115accf51197cdac856babbc9b9eda7ea08cb1888dc8ac72b3338f59f0f8cba7f002508ba3ea488d7c" +
				"0702ab42bf2c5de05e4e3a989f48f60dc3d25",
			compressible,
			nil,
		},
		// Pins that bound data follows the header rather than preceding it.
		"bound": {
			"010300f0e6e364dc3003249f489247e76761ba4dfd8053b80ff5a7bde05ca7137928c05b8883a49a61566e2786b2aecb0455",
			[]byte(plaintext),
			[]byte(aad),
		},
	} {
		t.Run(name, func(t *testing.T) {
			om := g.NewWithT(t)
			k := parseT(om, "3:"+keyA+",1:"+keyB)

			value, err := hex.DecodeString(gold.value)
			om.Expect(err).NotTo(g.HaveOccurred())
			om.Expect(value[0]).To(g.Equal(FormatVersion))
			om.Expect(value[1]).To(g.Equal(byte(3)))

			got, err := k.DecryptWithAAD(value, gold.aad)
			om.Expect(err).NotTo(g.HaveOccurred())
			om.Expect(bytes.Equal(got, gold.want)).To(g.BeTrue())
		})
	}
}
