// Command cekdulu-telegram runs the CekDulu Telegram bot (long polling).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Emil-02/cekdulu/internal/app"
	"github.com/Emil-02/cekdulu/internal/telegram"
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

	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	if token == "" {
		return fmt.Errorf("TELEGRAM_BOT_TOKEN belum diatur (buat bot lewat @BotFather)")
	}
	cfg, err := app.FromEnv(os.Getenv, true)
	if err != nil {
		return err
	}
	openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	a, err := app.Open(openCtx, cfg)
	cancel()
	if err != nil {
		return err
	}
	defer a.Close()

	if !a.Persistent {
		log.Warn("DATABASE_URL belum diatur: laporan dari bot disimpan di memori dan hilang saat bot berhenti")
	}
	if a.Hasher == nil {
		log.Warn("CEKDULU_HMAC_KEY belum diatur: laporan nomor HP dan rekening dinonaktifkan")
	}

	bot := telegram.New(telegram.Options{
		Client:     telegram.NewClient(token, os.Getenv("TELEGRAM_API_BASE"), nil),
		Service:    a.Service,
		Store:      a.Store,
		Hasher:     a.Hasher,
		CheckRate:  telegram.DefaultCheckRate,
		ReportRate: telegram.DefaultReportRate,
		Logger:     log,
	})
	return bot.Run(ctx)
}
