package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Emil-02/cekdulu/internal/check"
	"github.com/Emil-02/cekdulu/internal/report"
)

// Limits for uploads and free text.
const (
	MaxAPKSize       = 64 << 20
	MaxEvidenceFiles = 3
	MaxEvidenceSize  = 5 << 20
	MinTextLen       = 20
	MaxTextLen       = 2000
	MaxContactLen    = 200
	MaxNoteLen       = 1000
	MaxLossAmount    = int64(1e13)
	multipartMemory  = 1 << 20
	maxReportBody    = MaxEvidenceFiles*MaxEvidenceSize + 1<<20
	evidenceField    = "evidence"
)

var evidenceTypes = map[string]string{
	"image/jpeg":      ".jpg",
	"image/png":       ".png",
	"image/webp":      ".webp",
	"application/pdf": ".pdf",
}

func (s *Server) handleCheckLink(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.URL) == "" {
		return badRequest("field url wajib diisi")
	}
	res, err := s.opt.Service.Link(r.Context(), req.URL)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (s *Server) handleCheckPhone(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Phone string `json:"phone"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Phone) == "" {
		return badRequest("field phone wajib diisi")
	}
	res, err := s.opt.Service.Phone(r.Context(), req.Phone)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (s *Server) handleCheckAccount(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Provider string `json:"provider"`
		Number   string `json:"number"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Provider) == "" || strings.TrimSpace(req.Number) == "" {
		return badRequest("field provider dan number wajib diisi")
	}
	res, err := s.opt.Service.Account(r.Context(), req.Provider, req.Number)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (s *Server) handleCheckAPK(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxAPKSize+1<<20)
	if err := r.ParseMultipartForm(multipartMemory); err != nil {
		if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
			return err
		}
		return badRequest("form upload APK tidak valid: %v", err)
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	file, header, err := r.FormFile("file")
	if err != nil {
		return badRequest("file APK wajib dikirim di field \"file\"")
	}
	defer file.Close()

	name := filepath.Base(header.Filename)
	if name == "" || name == "." || name == "/" {
		name = "upload.apk"
	}
	res, err := s.opt.Service.APK(r.Context(), file, header.Size, name)
	if errors.Is(err, check.ErrInvalidAPK) {
		return badRequest("%v", err)
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

type category struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

func categories() []category {
	out := make([]category, 0, len(report.Categories))
	for id, label := range report.Categories {
		out = append(out, category{ID: id, Label: label})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) handleCategories(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"categories": categories()})
}

func (s *Server) handleRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": s.opt.Service.Engine().Rules()})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.wrap(func(w http.ResponseWriter, r *http.Request) error {
		st, err := s.opt.Store.Stats(r.Context())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, st)
		return nil
	})(w, r)
}

func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	s.wrap(func(w http.ResponseWriter, r *http.Request) error {
		kind := r.PathValue("kind")
		if kind == "link" {
			kind = report.KindDomain
		}
		if kind != report.KindDomain && kind != report.KindAPK {
			return notFound("blocklist hanya tersedia untuk domain atau apk")
		}
		items, err := s.opt.Store.Blocklist(r.Context(), kind)
		if err != nil {
			return err
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		if r.URL.Query().Get("format") == "txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			for _, it := range items {
				_, _ = io.WriteString(w, it+"\n")
			}
			return nil
		}
		writeJSON(w, http.StatusOK, map[string]any{"kind": kind, "count": len(items), "items": items})
		return nil
	})(w, r)
}

// reportInput is the body of POST /api/v1/reports.
type reportInput struct {
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	Provider    string `json:"provider"`
	Category    string `json:"category"`
	Description string `json:"description"`
	LossAmount  *int64 `json:"loss_amount"`
	Contact     string `json:"contact"`
}

type evidenceFile struct {
	data []byte
	ev   report.Evidence
	ext  string
}

func (s *Server) handleCreateReport(w http.ResponseWriter, r *http.Request) error {
	var in reportInput
	var files []evidenceFile
	if isMultipart(r) {
		r.Body = http.MaxBytesReader(w, r.Body, maxReportBody)
		if err := r.ParseMultipartForm(multipartMemory); err != nil {
			if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
				return err
			}
			return badRequest("form laporan tidak valid: %v", err)
		}
		defer func() { _ = r.MultipartForm.RemoveAll() }()
		in = reportInput{
			Kind: r.FormValue("kind"), Value: r.FormValue("value"), Provider: r.FormValue("provider"),
			Category: r.FormValue("category"), Description: r.FormValue("description"), Contact: r.FormValue("contact"),
		}
		if v := strings.TrimSpace(r.FormValue("loss_amount")); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return badRequest("loss_amount harus berupa angka bulat (rupiah)")
			}
			in.LossAmount = &n
		}
		var err error
		if files, err = s.readEvidence(r.MultipartForm.File[evidenceField]); err != nil {
			return err
		}
	} else if err := decodeJSON(w, r, &in); err != nil {
		return err
	}

	ind, err := s.indicator(in.Kind, in.Value, in.Provider)
	if err != nil {
		return err
	}
	in.Category = strings.TrimSpace(in.Category)
	if _, ok := report.Categories[in.Category]; !ok {
		return badRequest("kategori %q tidak dikenal; lihat GET /api/v1/categories", in.Category)
	}
	desc, err := text("description", in.Description, MinTextLen, MaxTextLen)
	if err != nil {
		return err
	}
	if in.LossAmount != nil && (*in.LossAmount < 0 || *in.LossAmount > MaxLossAmount) {
		return badRequest("loss_amount harus antara 0 dan %d", MaxLossAmount)
	}
	contact := strings.TrimSpace(in.Contact)
	if utf8.RuneCountInString(contact) > MaxContactLen {
		return badRequest("contact maksimal %d karakter", MaxContactLen)
	}

	nr := report.NewReport{
		Indicator:   ind,
		Category:    in.Category,
		Description: desc,
		LossAmount:  in.LossAmount,
		ContactHash: s.hash("contact", strings.ToLower(contact)),
		IPHash:      s.hash("ip", s.clientIP(r)),
	}
	month := s.opt.Now().UTC().Format("2006/01")
	for _, f := range files {
		f.ev.StorageKey = "evidence/" + month + "/" + report.NewID() + f.ext
		if err := s.opt.Blobs.Put(r.Context(), f.ev.StorageKey, f.data, f.ev.MIME); err != nil {
			return fmt.Errorf("menyimpan bukti: %w", err)
		}
		nr.Evidence = append(nr.Evidence, f.ev)
	}

	rep, err := s.opt.Store.CreateReport(r.Context(), nr)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":       rep.ID,
		"status":   rep.Status,
		"kind":     rep.Kind,
		"display":  rep.Display,
		"category": rep.Category,
		"evidence": len(rep.Evidence),
		"message":  "Terima kasih. Laporan akan ditampilkan setelah diperiksa moderator.",
	})
	return nil
}

func (s *Server) readEvidence(headers []*multipart.FileHeader) ([]evidenceFile, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	if s.opt.Blobs == nil {
		return nil, badRequest("unggah bukti belum diaktifkan di server ini")
	}
	if len(headers) > MaxEvidenceFiles {
		return nil, badRequest("maksimal %d file bukti", MaxEvidenceFiles)
	}
	var out []evidenceFile
	for _, h := range headers {
		if h.Size > MaxEvidenceSize {
			return nil, badRequest("file bukti %q melebihi %d MB", h.Filename, MaxEvidenceSize>>20)
		}
		f, err := h.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(f, MaxEvidenceSize+1))
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		if len(data) == 0 || len(data) > MaxEvidenceSize {
			return nil, badRequest("ukuran file bukti %q tidak valid", h.Filename)
		}
		mime := http.DetectContentType(data)
		ext, ok := evidenceTypes[mime]
		if !ok {
			return nil, badRequest("jenis file bukti %q tidak didukung (hanya JPG, PNG, WEBP, PDF)", h.Filename)
		}
		sum := sha256.Sum256(data)
		out = append(out, evidenceFile{
			data: data, ext: ext,
			ev: report.Evidence{SHA256: hex.EncodeToString(sum[:]), MIME: mime, Size: int64(len(data))},
		})
	}
	return out, nil
}

// indicator validates kind/value through the check service. "link" and
// "url" are accepted as aliases of "domain".
func (s *Server) indicator(kind, value, provider string) (report.Indicator, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "link" || kind == "url" {
		kind = report.KindDomain
	}
	if strings.TrimSpace(value) == "" {
		return report.Indicator{}, badRequest("field value wajib diisi")
	}
	ind, err := s.opt.Service.Indicator(kind, value, provider)
	if err != nil {
		return report.Indicator{}, badRequest("%v", err)
	}
	return ind, nil
}

func text(field, v string, minLen, maxLen int) (string, error) {
	v = strings.TrimSpace(v)
	n := utf8.RuneCountInString(v)
	if n < minLen || n > maxLen {
		return "", badRequest("%s harus %d-%d karakter (sekarang %d)", field, minLen, maxLen, n)
	}
	return v, nil
}

func isMultipart(r *http.Request) bool {
	return strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data")
}

func (s *Server) handleReportStatus(w http.ResponseWriter, r *http.Request) {
	s.wrap(func(w http.ResponseWriter, r *http.Request) error {
		rep, err := s.opt.Store.GetReport(r.Context(), r.PathValue("id"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, struct {
			ID         string     `json:"id"`
			Kind       string     `json:"kind"`
			Display    string     `json:"display"`
			Category   string     `json:"category"`
			Status     string     `json:"status"`
			CreatedAt  time.Time  `json:"created_at"`
			ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
		}{rep.ID, rep.Kind, rep.Display, rep.Category, rep.Status, rep.CreatedAt, rep.ReviewedAt})
		return nil
	})(w, r)
}

func (s *Server) handleCreateAppeal(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Kind     string `json:"kind"`
		Value    string `json:"value"`
		Provider string `json:"provider"`
		Contact  string `json:"contact"`
		Reason   string `json:"reason"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	ind, err := s.indicator(in.Kind, in.Value, in.Provider)
	if err != nil {
		return err
	}
	contact, err := text("contact", in.Contact, 3, MaxContactLen)
	if err != nil {
		return err
	}
	reason, err := text("reason", in.Reason, MinTextLen, MaxTextLen)
	if err != nil {
		return err
	}
	a, err := s.opt.Store.CreateAppeal(r.Context(), report.NewAppeal{
		Indicator: ind, Contact: contact, Reason: reason, IPHash: s.hash("ip", s.clientIP(r)),
	})
	if errors.Is(err, report.ErrNotFound) {
		return notFound("indikator ini tidak ada dalam daftar laporan terverifikasi")
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":      a.ID,
		"status":  a.Status,
		"kind":    a.Kind,
		"display": a.Display,
		"message": "Sanggahan diterima. Selama diperiksa, indikator ditandai sedang disanggah.",
	})
	return nil
}
