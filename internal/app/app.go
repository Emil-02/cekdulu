// Package app reads the runtime configuration from environment variables and
// wires the report store, evidence storage and check service together. Both
// the API server and the CLI use it so they behave the same way.
package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/Emil-02/cekdulu/internal/blob"
	"github.com/Emil-02/cekdulu/internal/check"
	"github.com/Emil-02/cekdulu/internal/link"
	"github.com/Emil-02/cekdulu/internal/report"
	"github.com/Emil-02/cekdulu/internal/secret"
	"github.com/Emil-02/cekdulu/supabase"
)

// Config holds every setting that can come from the environment.
type Config struct {
	// DatabaseURL selects the Postgres store; empty means in-memory.
	DatabaseURL string
	// Migrate applies the embedded SQL migrations on start-up.
	Migrate bool
	// HMACKey hashes phone numbers, accounts, reporter contacts and IPs.
	HMACKey string
	// Online enables redirect following and RDAP lookups for links.
	Online bool

	// EvidenceDir stores evidence files on the local filesystem.
	EvidenceDir string
	// Supabase Storage for evidence (takes precedence over EvidenceDir).
	SupabaseURL        string
	SupabaseServiceKey string
	EvidenceBucket     string
}

// FromEnv builds a Config. onlineDefault is used when CEKDULU_ONLINE is unset.
func FromEnv(getenv func(string) string, onlineDefault bool) (Config, error) {
	c := Config{
		DatabaseURL:        strings.TrimSpace(getenv("DATABASE_URL")),
		HMACKey:            getenv("CEKDULU_HMAC_KEY"),
		EvidenceDir:        strings.TrimSpace(getenv("CEKDULU_EVIDENCE_DIR")),
		SupabaseURL:        strings.TrimSpace(getenv("SUPABASE_URL")),
		SupabaseServiceKey: strings.TrimSpace(getenv("SUPABASE_SERVICE_ROLE_KEY")),
		EvidenceBucket:     strings.TrimSpace(getenv("CEKDULU_EVIDENCE_BUCKET")),
	}
	var err error
	if c.Migrate, err = Bool(getenv("CEKDULU_MIGRATE"), false); err != nil {
		return c, fmt.Errorf("CEKDULU_MIGRATE: %w", err)
	}
	if c.Online, err = Bool(getenv("CEKDULU_ONLINE"), onlineDefault); err != nil {
		return c, fmt.Errorf("CEKDULU_ONLINE: %w", err)
	}
	if c.EvidenceBucket == "" {
		c.EvidenceBucket = "evidence"
	}
	if (c.SupabaseURL == "") != (c.SupabaseServiceKey == "") {
		return c, fmt.Errorf("SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY harus diisi bersamaan")
	}
	return c, nil
}

// Bool parses common boolean spellings; empty returns def.
func Bool(s string, def bool) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return def, nil
	case "1", "true", "yes", "on", "ya":
		return true, nil
	case "0", "false", "no", "off", "tidak":
		return false, nil
	}
	return false, fmt.Errorf("nilai boolean tidak valid: %q", s)
}

// App is the wired application.
type App struct {
	Config  Config
	Service *check.Service
	Store   report.Store
	// Hasher is nil when no HMAC key is configured.
	Hasher *secret.Hasher
	// Blobs is nil when evidence uploads are not configured.
	Blobs blob.Store
	// Persistent reports whether the store survives restarts.
	Persistent bool
}

// Open connects to the configured backends.
func Open(ctx context.Context, cfg Config) (*App, error) {
	a := &App{Config: cfg}
	if cfg.HMACKey != "" {
		h, err := secret.NewHasher([]byte(cfg.HMACKey))
		if err != nil {
			return nil, err
		}
		a.Hasher = h
	}

	if cfg.DatabaseURL != "" {
		pg, err := report.OpenPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, fmt.Errorf("menghubungkan Postgres: %w", err)
		}
		if cfg.Migrate {
			if err := pg.Migrate(ctx, supabase.Migrations); err != nil {
				_ = pg.Close()
				return nil, err
			}
		}
		a.Store, a.Persistent = pg, true
	} else {
		a.Store = report.NewMemory()
	}

	switch {
	case cfg.SupabaseURL != "":
		a.Blobs = blob.Supabase{URL: cfg.SupabaseURL, ServiceKey: cfg.SupabaseServiceKey, Bucket: cfg.EvidenceBucket}
	case cfg.EvidenceDir != "":
		a.Blobs = blob.Dir{Root: cfg.EvidenceDir}
	}

	svc, err := check.New(check.Config{
		Store:  a.Store,
		Hasher: a.Hasher,
		Link:   link.Options{Online: cfg.Online},
	})
	if err != nil {
		_ = a.Store.Close()
		return nil, err
	}
	a.Service = svc
	return a, nil
}

// Close releases the store.
func (a *App) Close() error { return a.Store.Close() }

// Migrate applies the embedded migrations to databaseURL.
func Migrate(ctx context.Context, databaseURL string) error {
	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL belum diatur")
	}
	pg, err := report.OpenPostgres(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("menghubungkan Postgres: %w", err)
	}
	defer pg.Close()
	return pg.Migrate(ctx, supabase.Migrations)
}
