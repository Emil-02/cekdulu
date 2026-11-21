// Package check ties the analyzers, the community report database and the
// scoring engine together. Both the API server and the CLI use it.
package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Emil-02/cekdulu/internal/account"
	"github.com/Emil-02/cekdulu/internal/apk"
	"github.com/Emil-02/cekdulu/internal/link"
	"github.com/Emil-02/cekdulu/internal/phone"
	"github.com/Emil-02/cekdulu/internal/refdata"
	"github.com/Emil-02/cekdulu/internal/report"
	"github.com/Emil-02/cekdulu/internal/score"
	"github.com/Emil-02/cekdulu/internal/secret"
	"github.com/Emil-02/cekdulu/rules"
)

// Disclaimer is attached to every result.
const Disclaimer = "Hasil ini adalah penilaian otomatis berdasarkan aturan terbuka dan laporan masyarakat yang " +
	"sudah dimoderasi, bukan tuduhan hukum. Skor rendah tidak menjamin aman."

// Result is the response for any check.
type Result struct {
	Target     string                `json:"target"`
	Input      string                `json:"input"`
	Score      int                   `json:"score"`
	Level      string                `json:"level"`
	Reasons    []score.Reason        `json:"reasons"`
	Details    any                   `json:"details"`
	Reported   *report.IndicatorStat `json:"reported,omitempty"`
	CheckedAt  time.Time             `json:"checked_at"`
	Disclaimer string                `json:"disclaimer"`
}

// ErrInvalidAPK wraps errors caused by an unreadable or malformed APK.
var ErrInvalidAPK = errors.New("APK tidak valid")

// Config configures a Service.
type Config struct {
	// Store is optional; without it, community reports are not consulted.
	Store report.Store
	// Hasher is required to look up phone numbers and accounts in Store.
	Hasher *secret.Hasher
	Link   link.Options
	APK    apk.Options
}

// Service runs checks. It is safe for concurrent use.
type Service struct {
	cfg        Config
	engine     *score.Engine
	data       *refdata.Data
	link       *link.Analyzer
	staticLink *link.Analyzer
	apk        *apk.Analyzer
}

// New loads the embedded rules and reference data.
func New(cfg Config) (*Service, error) {
	engine, err := score.LoadFS(rules.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("memuat aturan: %w", err)
	}
	data, err := refdata.Load(rules.FS)
	if err != nil {
		return nil, fmt.Errorf("memuat data referensi: %w", err)
	}
	return &Service{
		cfg:        cfg,
		engine:     engine,
		data:       data,
		link:       link.New(data, cfg.Link),
		staticLink: link.New(data, link.Options{}),
		apk:        apk.New(data, cfg.APK),
	}, nil
}

// Engine exposes the rule engine (e.g. to list rules).
func (s *Service) Engine() *score.Engine { return s.engine }

func (s *Service) finish(target, input string, details any, sigs []score.Signal, rep *report.IndicatorStat) Result {
	res := s.engine.Evaluate(target, sigs)
	return Result{
		Target: target, Input: input, Score: res.Score, Level: res.Level, Reasons: res.Reasons,
		Details: details, Reported: rep, CheckedAt: time.Now().UTC(), Disclaimer: Disclaimer,
	}
}

func (s *Service) lookup(ctx context.Context, kind, hash string) (*report.IndicatorStat, error) {
	if s.cfg.Store == nil || hash == "" {
		return nil, nil
	}
	st, err := s.cfg.Store.Lookup(ctx, kind, hash)
	if errors.Is(err, report.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &st, nil
}

func reportedSignals(prefix string, st *report.IndicatorStat) []score.Signal {
	if st == nil {
		return nil
	}
	detail := fmt.Sprintf("%d laporan, terakhir %s", st.ApprovedCount, st.LastSeen.Format("2 Jan 2006"))
	if st.Status == report.IndicatorDisputed {
		detail += ", sedang disanggah"
	}
	sigs := []score.Signal{{ID: prefix + ".reported", Detail: detail}}
	if st.ApprovedCount >= 3 {
		sigs = append(sigs, score.Signal{ID: prefix + ".reported_many"})
	}
	return sigs
}

// Link checks a URL.
func (s *Service) Link(ctx context.Context, raw string) (Result, error) {
	rep, sigs := s.link.Analyze(ctx, raw)
	var st *report.IndicatorStat
	if rep.Domain != "" {
		var err error
		if st, err = s.lookup(ctx, report.KindDomain, rep.Domain); err != nil {
			return Result{}, err
		}
		sigs = append(sigs, reportedSignals("link", st)...)
	}
	return s.finish(score.TargetLink, raw, rep, sigs, st), nil
}

// APK checks an Android package.
func (s *Service) APK(ctx context.Context, r io.ReaderAt, size int64, name string) (Result, error) {
	rep, sigs, err := s.apk.Analyze(r, size, name)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInvalidAPK, err)
	}
	st, err := s.lookup(ctx, report.KindAPK, rep.SHA256)
	if err != nil {
		return Result{}, err
	}
	if st != nil {
		sigs = append(sigs, score.Signal{ID: "apk.blocklisted", Detail: fmt.Sprintf("%d laporan terverifikasi", st.ApprovedCount)})
	}
	return s.finish(score.TargetAPK, name, rep, sigs, st), nil
}

// PhoneDetails is returned for phone checks.
type PhoneDetails struct {
	phone.Number
	Valid bool `json:"valid"`
}

// Phone checks a phone number. The input is never echoed back unmasked.
func (s *Service) Phone(ctx context.Context, raw string) (Result, error) {
	n, perr := phone.Parse(raw)
	sigs := phone.Signals(n, perr)
	var st *report.IndicatorStat
	if perr == nil && s.cfg.Hasher != nil {
		var err error
		if st, err = s.lookup(ctx, report.KindPhone, s.cfg.Hasher.Hash(report.KindPhone, n.E164)); err != nil {
			return Result{}, err
		}
		sigs = append(sigs, reportedSignals("phone", st)...)
	}
	return s.finish(score.TargetPhone, n.Masked, PhoneDetails{Number: n, Valid: perr == nil}, sigs, st), nil
}

// AccountDetails is returned for account checks.
type AccountDetails struct {
	account.Account
	Valid bool `json:"valid"`
}

// Account checks a bank account or e-wallet.
func (s *Service) Account(ctx context.Context, provider, number string) (Result, error) {
	a, aerr := account.Parse(provider, number)
	var sigs []score.Signal
	var st *report.IndicatorStat
	if aerr != nil {
		sigs = append(sigs, score.Signal{ID: "account.invalid", Detail: aerr.Error()})
	} else if s.cfg.Hasher != nil {
		var err error
		if st, err = s.lookup(ctx, report.KindAccount, s.cfg.Hasher.Hash(report.KindAccount, a.Canonical)); err != nil {
			return Result{}, err
		}
		sigs = append(sigs, reportedSignals("account", st)...)
	}
	return s.finish(score.TargetAccount, a.Masked, AccountDetails{Account: a, Valid: aerr == nil}, sigs, st), nil
}

// Indicator builds a storable indicator for a report or appeal.
func (s *Service) Indicator(kind, value, provider string) (report.Indicator, error) {
	value = strings.TrimSpace(value)
	switch kind {
	case report.KindDomain:
		rep, sigs := s.staticLink.Analyze(context.Background(), value)
		for _, sg := range sigs {
			if sg.ID == "link.invalid_url" {
				return report.Indicator{}, fmt.Errorf("tautan tidak valid: %s", sg.Detail)
			}
		}
		if _, ok := s.data.OfficialBrand(rep.Host); ok {
			return report.Indicator{}, fmt.Errorf("%s adalah domain resmi; laporkan langsung ke pemilik layanan", rep.Domain)
		}
		for _, sh := range s.data.Shorteners {
			if refdata.MatchesDomain(rep.Domain, sh) {
				return report.Indicator{}, fmt.Errorf("%s adalah layanan pemendek tautan; cek dulu tautannya untuk melihat tujuan aslinya lalu laporkan domain tujuan", rep.Domain)
			}
		}
		return report.Indicator{Kind: kind, Hash: rep.Domain, Display: rep.Domain}, nil
	case report.KindAPK:
		v := strings.ToLower(value)
		if !isSHA256(v) {
			return report.Indicator{}, fmt.Errorf("SHA-256 APK harus 64 karakter heksadesimal")
		}
		return report.Indicator{Kind: kind, Hash: v, Display: v}, nil
	case report.KindPhone:
		if s.cfg.Hasher == nil {
			return report.Indicator{}, fmt.Errorf("server belum dikonfigurasi untuk nomor HP")
		}
		n, err := phone.Parse(value)
		if err != nil {
			return report.Indicator{}, err
		}
		return report.Indicator{Kind: kind, Hash: s.cfg.Hasher.Hash(kind, n.E164), Display: n.Masked}, nil
	case report.KindAccount:
		if s.cfg.Hasher == nil {
			return report.Indicator{}, fmt.Errorf("server belum dikonfigurasi untuk rekening")
		}
		a, err := account.Parse(provider, value)
		if err != nil {
			return report.Indicator{}, err
		}
		return report.Indicator{Kind: kind, Hash: s.cfg.Hasher.Hash(kind, a.Canonical), Display: a.Masked}, nil
	}
	return report.Indicator{}, fmt.Errorf("jenis %q tidak dikenal", kind)
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
