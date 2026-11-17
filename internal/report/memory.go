package report

import (
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Memory is an in-memory Store for tests and local development. Data is
// lost when the process exits.
type Memory struct {
	mu         sync.Mutex
	now        func() time.Time
	indicators map[string]*memIndicator
	reports    map[string]*memReport
	appeals    map[string]*memAppeal
}

type memIndicator struct {
	Indicator
	approved  int
	status    string
	firstSeen time.Time
	lastSeen  time.Time
}

type memReport struct {
	Report
	key         string
	contactHash string
	ipHash      string
}

type memAppeal struct {
	Appeal
	key string
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		now:        time.Now,
		indicators: map[string]*memIndicator{},
		reports:    map[string]*memReport{},
		appeals:    map[string]*memAppeal{},
	}
}

func key(kind, hash string) string { return kind + "\x00" + hash }

// NewID returns a random UUIDv4 string.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (m *Memory) Lookup(_ context.Context, kind, hash string) (IndicatorStat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ind, ok := m.indicators[key(kind, hash)]
	if !ok || ind.approved == 0 || ind.status == IndicatorRemoved {
		return IndicatorStat{}, ErrNotFound
	}
	cats := map[string]bool{}
	for _, r := range m.reports {
		if r.key == key(kind, hash) && r.Status == StatusApproved {
			cats[r.Category] = true
		}
	}
	return IndicatorStat{
		Kind: kind, Display: ind.Display, ApprovedCount: ind.approved, Status: ind.status,
		FirstSeen: ind.firstSeen, LastSeen: ind.lastSeen, Categories: sortedKeys(cats),
	}, nil
}

func (m *Memory) CreateReport(_ context.Context, nr NewReport) (Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	k := key(nr.Indicator.Kind, nr.Indicator.Hash)
	if _, ok := m.indicators[k]; !ok {
		m.indicators[k] = &memIndicator{Indicator: nr.Indicator, status: IndicatorActive, firstSeen: now, lastSeen: now}
	}
	r := &memReport{
		Report: Report{
			ID: NewID(), Kind: nr.Indicator.Kind, Display: nr.Indicator.Display, Category: nr.Category,
			Description: nr.Description, LossAmount: nr.LossAmount, Status: StatusPending, CreatedAt: now,
			Evidence: []Evidence{},
		},
		key: k, contactHash: nr.ContactHash, ipHash: nr.IPHash,
	}
	for _, e := range nr.Evidence {
		if e.ID == "" {
			e.ID = NewID()
		}
		e.CreatedAt = now
		r.Evidence = append(r.Evidence, e)
	}
	m.reports[r.ID] = r
	return m.view(r), nil
}

func (m *Memory) view(r *memReport) Report {
	out := r.Report
	out.Evidence = append([]Evidence{}, r.Evidence...)
	since := m.now().Add(-24 * time.Hour)
	for _, o := range m.reports {
		if o.CreatedAt.Before(since) {
			continue
		}
		if (r.contactHash != "" && o.contactHash == r.contactHash) || (r.ipHash != "" && o.ipHash == r.ipHash) {
			out.SameReporterCount++
		}
	}
	return out
}

func (m *Memory) GetReport(_ context.Context, id string) (Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reports[id]
	if !ok {
		return Report{}, ErrNotFound
	}
	return m.view(r), nil
}

func (m *Memory) ListReports(_ context.Context, status string, limit, offset int) ([]Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []*memReport
	for _, r := range m.reports {
		if status == "" || r.Status == status {
			all = append(all, r)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.Before(all[j].CreatedAt) })
	out := []Report{}
	for i := offset; i < len(all) && len(out) < clampLimit(limit); i++ {
		out = append(out, m.view(all[i]))
	}
	return out, nil
}

func (m *Memory) Decide(_ context.Context, id string, approve bool, actor, note string) (Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reports[id]
	if !ok {
		return Report{}, ErrNotFound
	}
	if r.Status != StatusPending {
		return Report{}, ErrConflict
	}
	now := m.now().UTC()
	r.ReviewedAt, r.ReviewedBy, r.ReviewNote = &now, actor, note
	if approve {
		r.Status = StatusApproved
		ind := m.indicators[r.key]
		ind.approved++
		ind.lastSeen = now
		ind.status = IndicatorActive
	} else {
		r.Status = StatusRejected
	}
	return m.view(r), nil
}

func (m *Memory) CreateAppeal(_ context.Context, na NewAppeal) (Appeal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(na.Indicator.Kind, na.Indicator.Hash)
	ind, ok := m.indicators[k]
	if !ok || ind.approved == 0 || ind.status == IndicatorRemoved {
		return Appeal{}, ErrNotFound
	}
	ind.status = IndicatorDisputed
	a := &memAppeal{
		Appeal: Appeal{
			ID: NewID(), Kind: ind.Kind, Display: ind.Display, Contact: na.Contact, Reason: na.Reason,
			Status: AppealPending, CreatedAt: m.now().UTC(),
		},
		key: k,
	}
	m.appeals[a.ID] = a
	return a.Appeal, nil
}

func (m *Memory) ListAppeals(_ context.Context, status string, limit, offset int) ([]Appeal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []*memAppeal
	for _, a := range m.appeals {
		if status == "" || a.Status == status {
			all = append(all, a)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.Before(all[j].CreatedAt) })
	out := []Appeal{}
	for i := offset; i < len(all) && len(out) < clampLimit(limit); i++ {
		out = append(out, all[i].Appeal)
	}
	return out, nil
}

func (m *Memory) ResolveAppeal(_ context.Context, id string, accept bool, actor, note string) (Appeal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.appeals[id]
	if !ok {
		return Appeal{}, ErrNotFound
	}
	if a.Status != AppealPending {
		return Appeal{}, ErrConflict
	}
	now := m.now().UTC()
	a.ResolvedAt, a.ResolvedBy, a.Note = &now, actor, note
	ind := m.indicators[a.key]
	if accept {
		a.Status = AppealAccepted
		ind.status = IndicatorRemoved
		return a.Appeal, nil
	}
	a.Status = AppealRejected
	if ind.status == IndicatorDisputed {
		pending := false
		for _, o := range m.appeals {
			if o.key == a.key && o.Status == AppealPending {
				pending = true
			}
		}
		if !pending {
			ind.status = IndicatorActive
		}
	}
	return a.Appeal, nil
}

func (m *Memory) Stats(_ context.Context) (Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Stats{Indicators: map[string]int{}, Categories: map[string]int{}}
	for _, r := range m.reports {
		switch r.Status {
		case StatusApproved:
			s.ApprovedReports++
			s.Categories[r.Category]++
			if r.LossAmount != nil {
				s.TotalLoss += *r.LossAmount
			}
		case StatusPending:
			s.PendingReports++
		}
	}
	for _, ind := range m.indicators {
		if ind.approved > 0 && ind.status != IndicatorRemoved {
			s.Indicators[ind.Kind]++
		}
	}
	return s, nil
}

func (m *Memory) Blocklist(_ context.Context, kind string) ([]string, error) {
	if kind != KindDomain && kind != KindAPK {
		return nil, fmt.Errorf("blocklist hanya untuk domain atau apk")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for _, ind := range m.indicators {
		if ind.Kind == kind && ind.approved > 0 && ind.status != IndicatorRemoved {
			out = append(out, ind.Hash)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *Memory) Close() error { return nil }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
