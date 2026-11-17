package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Emil-02/cekdulu/internal/check"
	"github.com/Emil-02/cekdulu/internal/report"
	"github.com/Emil-02/cekdulu/internal/secret"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printUsage(os.Stdout)
		return 0
	}

	if args[0] == "version" {
		fmt.Println("cekdulu dev")
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

	svc, err := newService()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	target := args[1]
	payload := strings.Join(args[2:], " ")
	result, err := executeCheck(svc, target, payload)
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

func newService() (*check.Service, error) {
	key := []byte(os.Getenv("CEKDULU_HMAC_KEY"))
	cfg := check.Config{Store: report.NewMemory()}
	if len(key) > 0 {
		h, err := secret.NewHasher(key)
		if err != nil {
			return nil, err
		}
		cfg.Hasher = h
	}
	return check.New(cfg)
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
	fmt.Fprintln(w, "  cekdulu check link <url>")
	fmt.Fprintln(w, "  cekdulu check apk <path/to/file.apk>")
	fmt.Fprintln(w, "  cekdulu check phone <nomor>")
	fmt.Fprintln(w, "  cekdulu check account <provider> <nomor>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Catatan: untuk menilai laporan masyarakat gunakan CEKDULU_HMAC_KEY.")
}
