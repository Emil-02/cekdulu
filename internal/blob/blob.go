// Package blob stores evidence files (screenshots) outside the database.
package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotFound is returned when a key does not exist.
var ErrNotFound = errors.New("file tidak ditemukan")

// Store saves and loads blobs by key.
type Store interface {
	Put(ctx context.Context, key string, data []byte, mime string) error
	Get(ctx context.Context, key string) ([]byte, error)
}

func validKey(key string) error {
	if key == "" || strings.Contains(key, "..") || strings.HasPrefix(key, "/") || strings.ContainsAny(key, "\\\x00") {
		return fmt.Errorf("kunci file tidak valid")
	}
	return nil
}

// Dir stores blobs on the local filesystem.
type Dir struct{ Root string }

func (d Dir) Put(_ context.Context, key string, data []byte, _ string) error {
	if err := validKey(key); err != nil {
		return err
	}
	p := filepath.Join(d.Root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func (d Dir) Get(_ context.Context, key string) ([]byte, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(d.Root, filepath.FromSlash(key)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

// Supabase stores blobs in a private Supabase Storage bucket using the
// service role key. The key must never be exposed to browsers.
type Supabase struct {
	URL        string // e.g. https://xyz.supabase.co
	ServiceKey string
	Bucket     string
	HTTP       *http.Client
}

func (s Supabase) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (s Supabase) objectURL(key string) string {
	return strings.TrimRight(s.URL, "/") + "/storage/v1/object/" + url.PathEscape(s.Bucket) + "/" + key
}

func (s Supabase) Put(ctx context.Context, key string, data []byte, mime string) error {
	if err := validKey(key); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.objectURL(key), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.ServiceKey)
	req.Header.Set("apikey", s.ServiceKey)
	req.Header.Set("Content-Type", mime)
	req.Header.Set("x-upsert", "false")
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("supabase storage: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (s Supabase) Get(ctx context.Context, key string) ([]byte, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.URL, "/")+
		"/storage/v1/object/authenticated/"+url.PathEscape(s.Bucket)+"/"+key, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.ServiceKey)
	req.Header.Set("apikey", s.ServiceKey)
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest:
		return nil, ErrNotFound
	case resp.StatusCode/100 != 2:
		return nil, fmt.Errorf("supabase storage: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}
