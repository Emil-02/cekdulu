// Package report stores community reports, their evidence, moderation
// decisions and appeals.
//
// Privacy model: phone numbers and bank accounts are only stored as HMAC
// hashes plus a masked display string. Domains and APK hashes are stored in
// plain text because they are public, non-personal indicators. Nothing is
// shown publicly until a moderator approves a report.
package report

import (
	"context"
	"errors"
	"time"
)

// Indicator kinds.
const (
	KindDomain  = "domain"
	KindAPK     = "apk"
	KindPhone   = "phone"
	KindAccount = "account"
)

// Report statuses.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
)

// Indicator statuses.
const (
	IndicatorActive   = "active"
	IndicatorDisputed = "disputed"
	IndicatorRemoved  = "removed"
)

// Appeal statuses.
const (
	AppealPending  = "pending"
	AppealAccepted = "accepted"
	AppealRejected = "rejected"
)

// Categories of scams.
var Categories = map[string]string{
	"phishing":      "Situs/tautan palsu (phishing)",
	"apk":           "APK palsu (undangan, kurir, tagihan, dll.)",
	"online_shop":   "Toko online / jual beli fiktif",
	"investment":    "Investasi bodong / trading / kripto",
	"loan":          "Pinjol ilegal / penagihan teror",
	"job":           "Lowongan kerja / kerja paruh waktu (task scam)",
	"impersonation": "Mengaku keluarga, kurir, CS bank, atau aparat",
	"prize":         "Hadiah / undian palsu",
	"romance":       "Asmara / love scam",
	"other":         "Lainnya",
}

// Errors.
var (
	ErrNotFound = errors.New("tidak ditemukan")
	ErrConflict = errors.New("status sudah berubah")
)

// Indicator identifies a scam artefact.
type Indicator struct {
	Kind string `json:"kind"`
	// Hash is HMAC(phone/account) or the plain value for domain/apk.
	Hash string `json:"-"`
	// Display is the masked or public value shown to users.
	Display string `json:"display"`
}

// IndicatorStat is the public, aggregated view of an indicator.
type IndicatorStat struct {
	Kind          string    `json:"kind"`
	Display       string    `json:"display"`
	ApprovedCount int       `json:"approved_count"`
	Status        string    `json:"status"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Categories    []string  `json:"categories"`
}

// NewReport is a report submitted by the public.
type NewReport struct {
	Indicator   Indicator
	Category    string
	Description string
	LossAmount  *int64
	// ContactHash is an optional HMAC of the reporter's contact; it is used
	// only to detect abuse (many reports from the same person).
	ContactHash string
	IPHash      string
	Evidence    []Evidence
}

// Evidence is an uploaded proof file. Content lives in blob storage.
type Evidence struct {
	ID         string    `json:"id"`
	StorageKey string    `json:"-"`
	SHA256     string    `json:"sha256"`
	MIME       string    `json:"mime"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"created_at"`
}

// Report is a stored report (moderator view).
type Report struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Display     string     `json:"display"`
	Category    string     `json:"category"`
	Description string     `json:"description"`
	LossAmount  *int64     `json:"loss_amount,omitempty"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy  string     `json:"reviewed_by,omitempty"`
	ReviewNote  string     `json:"review_note,omitempty"`
	Evidence    []Evidence `json:"evidence"`
	// SameReporterCount is the number of reports from the same contact or IP
	// hash in the last 24 hours (abuse signal for moderators).
	SameReporterCount int `json:"same_reporter_count"`
}

// NewAppeal is a dispute filed by someone who believes an indicator is wrong.
type NewAppeal struct {
	Indicator Indicator
	Contact   string
	Reason    string
	IPHash    string
}

// Appeal is a stored appeal.
type Appeal struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Display    string     `json:"display"`
	Contact    string     `json:"contact"`
	Reason     string     `json:"reason"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy string     `json:"resolved_by,omitempty"`
	Note       string     `json:"note,omitempty"`
}

// Stats are public aggregate numbers.
type Stats struct {
	ApprovedReports int            `json:"approved_reports"`
	PendingReports  int            `json:"pending_reports"`
	Indicators      map[string]int `json:"indicators"`
	Categories      map[string]int `json:"categories"`
	TotalLoss       int64          `json:"total_loss"`
}

// Store persists reports.
type Store interface {
	// Lookup returns the public stats of an indicator, or ErrNotFound when it
	// has no approved report or was removed after an appeal.
	Lookup(ctx context.Context, kind, hash string) (IndicatorStat, error)
	CreateReport(ctx context.Context, r NewReport) (Report, error)
	GetReport(ctx context.Context, id string) (Report, error)
	ListReports(ctx context.Context, status string, limit, offset int) ([]Report, error)
	// Decide approves or rejects a pending report.
	Decide(ctx context.Context, id string, approve bool, actor, note string) (Report, error)
	CreateAppeal(ctx context.Context, a NewAppeal) (Appeal, error)
	ListAppeals(ctx context.Context, status string, limit, offset int) ([]Appeal, error)
	// ResolveAppeal accepts (indicator removed) or rejects an appeal.
	ResolveAppeal(ctx context.Context, id string, accept bool, actor, note string) (Appeal, error)
	Stats(ctx context.Context) (Stats, error)
	// Blocklist returns public values of active domain or apk indicators.
	Blocklist(ctx context.Context, kind string) ([]string, error)
	Close() error
}

// MaxListLimit caps list sizes.
const MaxListLimit = 200

func clampLimit(limit int) int {
	if limit <= 0 || limit > MaxListLimit {
		return 50
	}
	return limit
}
