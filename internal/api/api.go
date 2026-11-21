// Package api exposes the check service, community reports, appeals and the
// moderation workflow over HTTP/JSON.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Emil-02/cekdulu/internal/blob"
	"github.com/Emil-02/cekdulu/internal/check"
	"github.com/Emil-02/cekdulu/internal/ratelimit"
	"github.com/Emil-02/cekdulu/internal/report"
	"github.com/Emil-02/cekdulu/internal/secret"
)

// Options configure a Server.
type Options struct {
	Service *check.Service
	Store   report.Store
	// Hasher hashes reporter contacts and IP addresses; optional.
	Hasher *secret.Hasher
	// Blobs stores evidence files; nil disables evidence uploads.
	Blobs blob.Store
	// Moderators maps bearer tokens to moderator names. Empty disables the
	// admin endpoints.
	Moderators map[string]string
	// TrustProxy uses the last X-Forwarded-For entry as the client IP. Only
	// enable it behind a reverse proxy that sets that header.
	TrustProxy bool
	// CheckRate limits /check requests per client IP.
	CheckRate ratelimit.Rate
	// SubmitRate limits new reports and appeals per client IP.
	SubmitRate ratelimit.Rate
	// Persistent and Online are reported by /health.
	Persistent bool
	Online     bool
	Logger     *slog.Logger
	Now        func() time.Time
}

// Defaults for Options.
var (
	DefaultCheckRate  = ratelimit.Rate{N: 60, Per: time.Minute}
	DefaultSubmitRate = ratelimit.Rate{N: 10, Per: time.Hour}
)

// Server is an http.Handler.
type Server struct {
	opt          Options
	mux          *http.ServeMux
	checkLimit   *ratelimit.Limiter
	submitLimit  *ratelimit.Limiter
	log          *slog.Logger
	moderatorIDs []moderator
}

type moderator struct {
	token []byte
	name  string
}

// New returns a server.
func New(opt Options) *Server {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	s := &Server{
		opt:         opt,
		mux:         http.NewServeMux(),
		checkLimit:  ratelimit.New(opt.CheckRate, opt.Now),
		submitLimit: ratelimit.New(opt.SubmitRate, opt.Now),
		log:         opt.Logger,
	}
	for tok, name := range opt.Moderators {
		s.moderatorIDs = append(s.moderatorIDs, moderator{token: []byte(tok), name: name})
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /health", s.handleHealth)

	m.HandleFunc("POST /api/v1/check/link", s.limited(s.checkLimit, s.handleCheckLink))
	m.HandleFunc("POST /api/v1/check/phone", s.limited(s.checkLimit, s.handleCheckPhone))
	m.HandleFunc("POST /api/v1/check/account", s.limited(s.checkLimit, s.handleCheckAccount))
	m.HandleFunc("POST /api/v1/check/apk", s.limited(s.checkLimit, s.handleCheckAPK))

	m.HandleFunc("GET /api/v1/categories", s.handleCategories)
	m.HandleFunc("GET /api/v1/rules", s.handleRules)
	m.HandleFunc("GET /api/v1/stats", s.handleStats)
	m.HandleFunc("GET /api/v1/blocklist/{kind}", s.handleBlocklist)

	m.HandleFunc("POST /api/v1/reports", s.limited(s.submitLimit, s.handleCreateReport))
	m.HandleFunc("GET /api/v1/reports/{id}", s.handleReportStatus)
	m.HandleFunc("POST /api/v1/appeals", s.limited(s.submitLimit, s.handleCreateAppeal))

	m.HandleFunc("GET /api/v1/admin/reports", s.admin(s.handleAdminListReports))
	m.HandleFunc("GET /api/v1/admin/reports/{id}", s.admin(s.handleAdminGetReport))
	m.HandleFunc("POST /api/v1/admin/reports/{id}/{action}", s.admin(s.handleAdminDecide))
	m.HandleFunc("GET /api/v1/admin/reports/{id}/evidence/{evidence}", s.admin(s.handleAdminEvidence))
	m.HandleFunc("GET /api/v1/admin/appeals", s.admin(s.handleAdminListAppeals))
	m.HandleFunc("POST /api/v1/admin/appeals/{id}/{action}", s.admin(s.handleAdminResolveAppeal))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"service":    "cekdulu",
		"time":       s.opt.Now().UTC().Format(time.RFC3339),
		"persistent": s.opt.Persistent,
		"online":     s.opt.Online,
		"moderation": len(s.moderatorIDs) > 0,
		"evidence":   s.opt.Blobs != nil,
	})
}

// httpError is an error with a status code and a message safe to show users.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func badRequest(format string, a ...any) error {
	return &httpError{status: http.StatusBadRequest, msg: fmt.Sprintf(format, a...)}
}

func notFound(msg string) error { return &httpError{status: http.StatusNotFound, msg: msg} }

type handler func(http.ResponseWriter, *http.Request) error

// wrap converts returned errors into JSON responses. Unknown errors are
// logged and hidden from the client.
func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}
		var he *httpError
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &he):
			writeError(w, he.status, he.msg)
		case errors.As(err, &mbe):
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("ukuran permintaan melebihi batas %d byte", mbe.Limit))
		case errors.Is(err, report.ErrNotFound):
			writeError(w, http.StatusNotFound, "data tidak ditemukan")
		case errors.Is(err, report.ErrConflict):
			writeError(w, http.StatusConflict, "status sudah diputuskan sebelumnya")
		default:
			s.log.Error("request gagal", "method", r.Method, "path", r.URL.Path, "err", err)
			writeError(w, http.StatusInternalServerError, "terjadi kesalahan pada server")
		}
	}
}

func (s *Server) limited(l *ratelimit.Limiter, h handler) http.HandlerFunc {
	wrapped := s.wrap(h)
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", fmt.Sprint(int(l.Rate().Per.Seconds())))
			writeError(w, http.StatusTooManyRequests, "terlalu banyak permintaan, coba lagi nanti")
			return
		}
		wrapped(w, r)
	}
}

// admin requires a moderator bearer token and passes the moderator name.
func (s *Server) admin(h func(http.ResponseWriter, *http.Request, string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if len(s.moderatorIDs) == 0 {
			writeError(w, http.StatusServiceUnavailable, "moderasi belum diaktifkan (atur CEKDULU_MODERATORS)")
			return
		}
		name, ok := s.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cekdulu-admin"`)
			writeError(w, http.StatusUnauthorized, "token moderator tidak valid")
			return
		}
		s.wrap(func(w http.ResponseWriter, r *http.Request) error { return h(w, r, name) })(w, r)
	}
}

func (s *Server) authenticate(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || tok == "" {
		return "", false
	}
	name, found := "", 0
	for _, m := range s.moderatorIDs {
		if subtle.ConstantTimeCompare(m.token, []byte(tok)) == 1 {
			name, found = m.name, found+1
		}
	}
	return name, found == 1
}

func (s *Server) clientIP(r *http.Request) string {
	if s.opt.TrustProxy {
		if vals := r.Header.Values("X-Forwarded-For"); len(vals) > 0 {
			parts := strings.Split(vals[len(vals)-1], ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// hash returns an HMAC of value, or "" without a hasher.
func (s *Server) hash(kind, value string) string {
	if s.opt.Hasher == nil || value == "" {
		return ""
	}
	return s.opt.Hasher.Hash(kind, value)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

const maxJSONBody = 64 << 10

// decodeJSON reads a JSON object into v. An empty body leaves v unchanged.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case errors.As(err, &mbe):
			return err
		}
		return badRequest("JSON tidak valid: %v", err)
	}
	if dec.More() {
		return badRequest("JSON tidak valid: hanya boleh satu objek")
	}
	return nil
}

var moderatorName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,40}$`)

// MinTokenLen is the minimum moderator token length.
const MinTokenLen = 24

// ParseModerators parses "name:token,name2:token2" into a token->name map.
func ParseModerators(s string) (map[string]string, error) {
	out := map[string]string{}
	for entry := range strings.SplitSeq(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, tok, ok := strings.Cut(entry, ":")
		name, tok = strings.TrimSpace(name), strings.TrimSpace(tok)
		switch {
		case !ok || !moderatorName.MatchString(name):
			return nil, fmt.Errorf("format moderator harus nama:token (nama hanya huruf, angka, _ . -)")
		case len(tok) < MinTokenLen:
			return nil, fmt.Errorf("token moderator %s minimal %d karakter", name, MinTokenLen)
		}
		if _, dup := out[tok]; dup {
			return nil, fmt.Errorf("token moderator %s dipakai lebih dari sekali", name)
		}
		out[tok] = name
	}
	return out, nil
}
