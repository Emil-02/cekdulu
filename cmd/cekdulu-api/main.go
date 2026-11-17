package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Emil-02/cekdulu/internal/check"
	"github.com/Emil-02/cekdulu/internal/report"
	"github.com/Emil-02/cekdulu/internal/secret"
)

func main() {
	port := os.Getenv("CEKDULU_PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	svc, err := newService()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"service": "cekdulu",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/v1/check/link", makeHandler(svc, handleLink))
	mux.HandleFunc("/api/v1/check/phone", makeHandler(svc, handlePhone))
	mux.HandleFunc("/api/v1/check/account", makeHandler(svc, handleAccount))
	mux.HandleFunc("/api/v1/check/apk", makeHandler(svc, handleAPK))

	fmt.Printf("cekdulu API listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newService() (*check.Service, error) {
	cfg := check.Config{Store: report.NewMemory()}
	if key := os.Getenv("CEKDULU_HMAC_KEY"); key != "" {
		h, err := secret.NewHasher([]byte(key))
		if err != nil {
			return nil, err
		}
		cfg.Hasher = h
	}
	return check.New(cfg)
}

type handlerFunc func(*check.Service, http.ResponseWriter, *http.Request) error

func makeHandler(svc *check.Service, fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if err := fn(svc, w, r); err != nil {
			http.Error(w, `{"error":"`+strings.ReplaceAll(err.Error(), "\n", " ")+`"}`, http.StatusBadRequest)
			return
		}
	}
}

func handleLink(svc *check.Service, w http.ResponseWriter, r *http.Request) error {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !isEmptyBody(r.Body) {
		return err
	}
	if req.URL == "" {
		return fmt.Errorf("field url wajib diisi")
	}
	res, err := svc.Link(r.Context(), req.URL)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(res)
}

func handlePhone(svc *check.Service, w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !isEmptyBody(r.Body) {
		return err
	}
	if req.Phone == "" {
		return fmt.Errorf("field phone wajib diisi")
	}
	res, err := svc.Phone(r.Context(), req.Phone)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(res)
}

func handleAccount(svc *check.Service, w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Provider string `json:"provider"`
		Number   string `json:"number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !isEmptyBody(r.Body) {
		return err
	}
	if req.Provider == "" || req.Number == "" {
		return fmt.Errorf("field provider dan number wajib diisi")
	}
	res, err := svc.Account(r.Context(), req.Provider, req.Number)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(res)
}

func handleAPK(svc *check.Service, w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return fmt.Errorf("form upload APK tidak valid: %w", err)
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return fmt.Errorf("file APK wajib dikirim: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	name := header.Filename
	if name == "" {
		name = filepath.Base(r.FormValue("name"))
	}
	if name == "" {
		name = "upload.apk"
	}

	res, err := svc.APK(r.Context(), bytes.NewReader(data), int64(len(data)), name)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(res)
}

func isEmptyBody(r io.ReadCloser) bool {
	buf := make([]byte, 1)
	_, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return false
	}
	return true
}
