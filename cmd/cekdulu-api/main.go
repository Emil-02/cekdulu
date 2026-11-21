// Command cekdulu-api serves the CekDulu HTTP API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Emil-02/cekdulu/internal/api"
	"github.com/Emil-02/cekdulu/internal/app"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := app.FromEnv(os.Getenv, true)
	if err != nil {
		return err
	}
	moderators, err := api.ParseModerators(os.Getenv("CEKDULU_MODERATORS"))
	if err != nil {
		return fmt.Errorf("CEKDULU_MODERATORS: %w", err)
	}
	trustProxy, err := app.Bool(os.Getenv("CEKDULU_TRUST_PROXY"), false)
	if err != nil {
		return fmt.Errorf("CEKDULU_TRUST_PROXY: %w", err)
	}

	openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	a, err := app.Open(openCtx, cfg)
	cancel()
	if err != nil {
		return err
	}
	defer a.Close()

	if !a.Persistent {
		log.Warn("DATABASE_URL belum diatur: laporan disimpan di memori dan hilang saat server berhenti")
	}
	if a.Hasher == nil {
		log.Warn("CEKDULU_HMAC_KEY belum diatur: laporan nomor HP dan rekening dinonaktifkan")
	}
	if len(moderators) == 0 {
		log.Warn("CEKDULU_MODERATORS belum diatur: endpoint moderasi dinonaktifkan")
	}

	port := os.Getenv("CEKDULU_PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr: ":" + port,
		Handler: api.New(api.Options{
			Service:    a.Service,
			Store:      a.Store,
			Hasher:     a.Hasher,
			Blobs:      a.Blobs,
			Moderators: moderators,
			TrustProxy: trustProxy,
			CheckRate:  api.DefaultCheckRate,
			SubmitRate: api.DefaultSubmitRate,
			Persistent: a.Persistent,
			Online:     cfg.Online,
			Logger:     log,
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("cekdulu API berjalan", "addr", srv.Addr, "persistent", a.Persistent, "online", cfg.Online,
			"moderators", len(moderators), "evidence", a.Blobs != nil)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("menghentikan server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	return nil
}
