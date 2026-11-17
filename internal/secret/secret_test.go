package secret

import "testing"

func TestHasher(t *testing.T) {
	if _, err := NewHasher([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
	h, err := NewHasher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	a := h.Hash("phone", "+628123")
	if a != h.Hash("phone", "+628123") || a == h.Hash("account", "+628123") || len(a) != 64 {
		t.Fatal("hash must be deterministic and domain-separated")
	}
	h2, _ := NewHasher([]byte("ffffffffffffffffffffffffffffffff"))
	if a == h2.Hash("phone", "+628123") {
		t.Fatal("hash must depend on key")
	}
}
