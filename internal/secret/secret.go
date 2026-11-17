// Package secret hashes personal identifiers (phone numbers, bank accounts)
// with a server-side HMAC key so the database never stores them in plain
// text. Without the key, hashes cannot be brute-forced from the small space
// of possible phone numbers.
package secret

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// MinKeyLen is the minimum accepted key length in bytes.
const MinKeyLen = 32

// Hasher computes keyed hashes.
type Hasher struct{ key []byte }

// NewHasher returns a hasher. The key must be at least MinKeyLen bytes.
func NewHasher(key []byte) (*Hasher, error) {
	if len(key) < MinKeyLen {
		return nil, errors.New("kunci HMAC minimal 32 byte (atur CEKDULU_HMAC_KEY)")
	}
	return &Hasher{key: append([]byte(nil), key...)}, nil
}

// Hash returns hex(HMAC-SHA256(key, kind + ":" + value)).
func (h *Hasher) Hash(kind, value string) string {
	m := hmac.New(sha256.New, h.key)
	m.Write([]byte(kind))
	m.Write([]byte{':'})
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))
}
