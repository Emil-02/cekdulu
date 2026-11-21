package telegram

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Emil-02/cekdulu/internal/link"
	"github.com/Emil-02/cekdulu/internal/report"
)

// Steps of the /lapor conversation.
const (
	stepTarget = iota
	stepCategory
	stepDescription
	stepLoss
	stepDone
)

// Report text limits, matching the database constraints.
const (
	MinDescription = 20
	MaxDescription = 2000
	MaxLoss        = int64(1e13)
)

// categoryOrder is the order of the category buttons.
var categoryOrder = []string{"phishing", "apk", "online_shop", "investment", "loan", "job", "impersonation", "prize", "romance", "other"}

type session struct {
	// mu serialises messages from the same user within a conversation.
	mu       sync.Mutex
	step     int
	ind      report.Indicator
	category string
	desc     string
	expires  time.Time
}

func (b *Bot) session(userID int64) *session {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[userID]
	if !ok {
		return nil
	}
	if b.opt.Now().After(s.expires) {
		delete(b.sessions, userID)
		return nil
	}
	s.expires = b.opt.Now().Add(SessionTTL)
	return s
}

func (b *Bot) dropSession(userID int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.sessions[userID]
	delete(b.sessions, userID)
	return ok
}

func (b *Bot) startReport(ctx context.Context, m *Message, args string) {
	if b.opt.Store == nil {
		b.reply(ctx, m, "Fitur laporan belum diaktifkan di bot ini.", nil)
		return
	}
	now := b.opt.Now()
	s := &session{step: stepTarget, expires: now.Add(SessionTTL)}
	b.mu.Lock()
	for id, o := range b.sessions {
		if now.After(o.expires) {
			delete(b.sessions, id)
		}
	}
	b.sessions[m.From.ID] = s
	b.mu.Unlock()

	if strings.TrimSpace(args) != "" {
		s.mu.Lock()
		defer s.mu.Unlock()
		text, ents := m.Content()
		b.setTarget(ctx, m, s, text, ents, args)
		return
	}
	b.reply(ctx, m, "📝 <b>Lapor penipuan</b>\n\nApa yang mau dilaporkan? Kirim salah satu:\n"+
		"• link, mis. <code>https://bca-hadiah.xyz</code>\n• nomor HP, mis. <code>0812xxxx7890</code>\n"+
		"• rekening, mis. <code>bca 1234567890</code> atau <code>dana 0812xxxx7890</code>\n"+
		"• SHA-256 file APK\n\nKetik /batal untuk membatalkan.", nil)
}

func (b *Bot) continueReport(ctx context.Context, m *Message, s *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	text, ents := m.Content()
	switch s.step {
	case stepTarget:
		b.setTarget(ctx, m, s, text, ents, text)
	case stepCategory:
		b.reply(ctx, m, "Pilih jenis penipuan dengan menekan salah satu tombol di atas, atau /batal.", nil)
	case stepDescription:
		desc := strings.TrimSpace(text)
		n := utf8.RuneCountInString(desc)
		if n < MinDescription || n > MaxDescription {
			b.reply(ctx, m, fmt.Sprintf("Ceritakan kronologinya dalam %d–%d karakter (sekarang %d).", MinDescription, MaxDescription, n), nil)
			return
		}
		s.desc = desc
		s.step = stepLoss
		b.reply(ctx, m, "Berapa kerugianmu dalam rupiah? Contoh: <code>250000</code>, <code>1,5jt</code>, atau <code>0</code> jika tidak ada.", nil)
	case stepLoss:
		loss, err := parseRupiah(text)
		if err != nil {
			b.reply(ctx, m, "Tulis angka saja, mis. <code>250000</code> atau <code>1,5jt</code>. Kirim <code>0</code> jika tidak ada kerugian.", nil)
			return
		}
		b.submitReport(ctx, m, s, loss)
	}
}

// setTarget picks what is being reported. value is the user's input without
// the command; a single bare word like "toko-palsu.xyz" is read as a domain.
func (b *Bot) setTarget(ctx context.Context, m *Message, s *session, text string, ents []Entity, value string) {
	var kind, provider string
	value = strings.TrimSpace(value)
	if v := strings.ToLower(value); len(v) == 64 && strings.Trim(v, "0123456789abcdef") == "" {
		kind, value = report.KindAPK, v
	} else {
		items := Extract(text, ents)
		if len(items) == 0 && !strings.ContainsAny(value, " \n") {
			if _, err := link.Normalize(value); err == nil {
				items = []Item{{Kind: ItemLink, Value: value}}
			}
		}
		if len(items) == 0 {
			b.reply(ctx, m, "Saya tidak mengenali link, nomor HP, atau rekening di pesan itu. Coba lagi, atau /batal.", nil)
			return
		}
		it := items[0]
		value, provider = it.Value, it.Provider
		kind = map[string]string{ItemLink: report.KindDomain, ItemPhone: report.KindPhone, ItemAccount: report.KindAccount}[it.Kind]
	}
	ind, err := b.opt.Service.Indicator(kind, value, provider)
	if err != nil {
		b.reply(ctx, m, "Tidak bisa dilaporkan: "+esc(err.Error())+"\n\nKirim yang lain, atau /batal.", nil)
		return
	}
	s.ind = ind
	s.step = stepCategory
	kb := &InlineKeyboard{}
	for _, id := range categoryOrder {
		kb.Rows = append(kb.Rows, []InlineButton{{Text: report.Categories[id], CallbackData: "cat:" + id}})
	}
	b.reply(ctx, m, fmt.Sprintf("Yang dilaporkan: %s <code>%s</code>\n\nJenis penipuannya apa?",
		kindIcon[kindTarget(ind.Kind)], esc(ind.Display)), kb)
}

func (b *Bot) handleCallback(ctx context.Context, q *CallbackQuery) {
	id, ok := strings.CutPrefix(q.Data, "cat:")
	_, known := report.Categories[id]
	s := b.session(q.From.ID)
	if s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	if !ok || !known || s == nil || s.step != stepCategory || q.Message == nil {
		_ = b.tg.AnswerCallback(ctx, q.ID, "Sesi laporan sudah berakhir. Kirim /lapor untuk mulai lagi.")
		return
	}
	s.category = id
	s.step = stepDescription
	_ = b.tg.AnswerCallback(ctx, q.ID, report.Categories[id])
	b.reply(ctx, q.Message, fmt.Sprintf("Kategori: <b>%s</b>\n\nCeritakan kronologinya: bagaimana pelaku menghubungimu, apa yang diminta, "+
		"dan apa yang terjadi. Jangan tulis PIN, OTP, atau password.", esc(report.Categories[id])), nil)
}

func (b *Bot) submitReport(ctx context.Context, m *Message, s *session, loss *int64) {
	s.step = stepDone
	b.mu.Lock()
	if b.sessions[m.From.ID] == s {
		delete(b.sessions, m.From.ID)
	}
	b.mu.Unlock()
	if !b.reportLimit.Allow(userKey(m.From)) {
		b.reply(ctx, m, "Kamu sudah mengirim banyak laporan hari ini. Coba lagi besok ya.", nil)
		return
	}
	nr := report.NewReport{Indicator: s.ind, Category: s.category, Description: s.desc, LossAmount: loss}
	if b.opt.Hasher != nil {
		nr.ContactHash = b.opt.Hasher.Hash("contact", "telegram:"+userKey(m.From))
	}
	r, err := b.opt.Store.CreateReport(ctx, nr)
	if err != nil {
		b.log.Error("menyimpan laporan gagal", "err", err)
		b.reply(ctx, m, "Maaf, laporan gagal disimpan. Coba lagi nanti.", nil)
		return
	}
	b.reply(ctx, m, fmt.Sprintf("✅ <b>Laporan terkirim.</b> Terima kasih sudah membantu orang lain.\n\n"+
		"ID: <code>%s</code>\nLaporan akan diperiksa moderator sebelum dipakai dalam hasil cek. "+
		"Cek statusnya dengan /status %s\n\nJika uang sudah ditransfer, segera hubungi bank-mu dan laporkan ke "+
		"Indonesia Anti-Scam Centre (iasc.ojk.go.id) agar dana bisa diblokir secepatnya.", esc(r.ID), esc(r.ID)), nil)
}

// parseRupiah accepts "250000", "Rp 250.000", "1,5jt", "300rb" or "0".
// "-", "tidak" and "lewati" mean unknown (nil).
func parseRupiah(s string) (*int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "-", "tidak", "tidak ada", "lewati", "skip":
		return nil, nil
	}
	s = strings.TrimPrefix(s, "rp")
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	mult := 1.0
	for _, suf := range []struct {
		s string
		m float64
	}{{"juta", 1e6}, {"jt", 1e6}, {"ribu", 1e3}, {"rb", 1e3}, {"k", 1e3}} {
		if v, ok := strings.CutSuffix(s, suf.s); ok {
			s, mult = v, suf.m
			break
		}
	}
	var n int64
	if mult > 1 {
		f, err := strconv.ParseFloat(strings.ReplaceAll(s, ",", "."), 64)
		if err != nil || f < 0 {
			return nil, fmt.Errorf("angka tidak valid")
		}
		n = int64(f * mult)
	} else {
		// Indonesian format: "." groups thousands, "," starts the cents.
		if i := strings.LastIndex(s, ","); i >= 0 && len(s)-i <= 3 {
			s = s[:i]
		}
		v, err := strconv.ParseInt(strings.NewReplacer(".", "", ",", "").Replace(s), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("angka tidak valid")
		}
		n = v
	}
	if n < 0 || n > MaxLoss {
		return nil, fmt.Errorf("di luar batas")
	}
	return &n, nil
}
