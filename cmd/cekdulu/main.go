package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Emil-02/cekdulu/internal/app"
	"github.com/Emil-02/cekdulu/internal/check"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	online := false
	var rest []string
	for _, a := range args {
		if a == "--online" || a == "-online" {
			online = true
			continue
		}
		rest = append(rest, a)
	}
	args = rest

	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printUsage(os.Stdout)
		return 0
	}

	if args[0] == "version" {
		fmt.Println("cekdulu dev")
		return 0
	}

	if args[0] == "migrate" {
		if err := app.Migrate(context.Background(), os.Getenv("DATABASE_URL")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("migrasi selesai")
		return 0
	}

	if args[0] != "check" {
		fmt.Fprintf(os.Stderr, "perintah tidak dikenal: %s\n", args[0])
		printUsage(os.Stderr)
		return 1
	}

	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "gunakan: cekdulu check <link|apk|phone|account> ...")
		return 1
	}

	a, err := openApp(online)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer a.Close()

	target := args[1]
	payload := strings.Join(args[2:], " ")
	result, err := executeCheck(a.Service, target, payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func openApp(online bool) (*app.App, error) {
	cfg, err := app.FromEnv(os.Getenv, false)
	if err != nil {
		return nil, err
	}
	cfg.Online = cfg.Online || online
	return app.Open(context.Background(), cfg)
}

func executeCheck(svc *check.Service, target, payload string) (any, error) {
	ctx := context.Background()
	switch target {
	case "link":
		return svc.Link(ctx, payload)
	case "apk":
		f, err := os.Open(payload)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return nil, err
		}
		return svc.APK(ctx, f, info.Size(), filepathName(payload))
	case "phone":
		return svc.Phone(ctx, payload)
	case "account":
		parts := strings.Fields(payload)
		if len(parts) < 2 {
			return nil, errors.New("format rekening: <provider> <nomor>")
		}
		return svc.Account(ctx, parts[0], strings.Join(parts[1:], " "))
	default:
		return nil, fmt.Errorf("jenis cek tidak didukung: %s", target)
	}
}

func filepathName(p string) string {
	if p == "" {
		return "unknown.apk"
	}
	return strings.TrimSpace(p)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Penggunaan:")
	fmt.Fprintln(w, "  cekdulu version")
	fmt.Fprintln(w, "  cekdulu migrate                       (terapkan skema ke DATABASE_URL)")
	fmt.Fprintln(w, "  cekdulu check [--online] link <url>   (--online: ikuti pengalihan & cek umur domain)")
	fmt.Fprintln(w, "  cekdulu check apk <path/to/file.apk>")
	fmt.Fprintln(w, "  cekdulu check phone <nomor>")
	fmt.Fprintln(w, "  cekdulu check account <provider> <nomor>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Variabel lingkungan:")
	fmt.Fprintln(w, "  DATABASE_URL      cocokkan dengan laporan masyarakat di Postgres")
	fmt.Fprintln(w, "  CEKDULU_HMAC_KEY  wajib untuk mencocokkan nomor HP dan rekening (sama dengan server)")
	fmt.Fprintln(w, "  CEKDULU_ONLINE=1  sama dengan --online")
}
