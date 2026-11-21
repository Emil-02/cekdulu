package app

import (
	"context"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestFromEnv(t *testing.T) {
	c, err := FromEnv(env(nil), true)
	if err != nil || !c.Online || c.Migrate || c.EvidenceBucket != "evidence" {
		t.Fatalf("default = %+v, %v", c, err)
	}
	c, err = FromEnv(env(map[string]string{"CEKDULU_ONLINE": "0", "CEKDULU_MIGRATE": "ya"}), true)
	if err != nil || c.Online || !c.Migrate {
		t.Fatalf("override = %+v, %v", c, err)
	}
	if _, err := FromEnv(env(map[string]string{"CEKDULU_ONLINE": "mungkin"}), false); err == nil {
		t.Fatal("nilai boolean tidak valid harus ditolak")
	}
	if _, err := FromEnv(env(map[string]string{"SUPABASE_URL": "https://x.supabase.co"}), false); err == nil {
		t.Fatal("SUPABASE_URL tanpa service key harus ditolak")
	}
}

func TestOpenMemory(t *testing.T) {
	a, err := Open(context.Background(), Config{HMACKey: strings.Repeat("k", 32), EvidenceDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.Persistent || a.Hasher == nil || a.Blobs == nil || a.Service == nil {
		t.Fatalf("app = %+v", a)
	}
	if _, err := Open(context.Background(), Config{HMACKey: "pendek"}); err == nil {
		t.Fatal("kunci HMAC pendek harus ditolak")
	}
}
