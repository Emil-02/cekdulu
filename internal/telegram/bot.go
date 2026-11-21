package telegram

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Emil-02/cekdulu/internal/check"
	"github.com/Emil-02/cekdulu/internal/ratelimit"
	"github.com/Emil-02/cekdulu/internal/report"
	"github.com/Emil-02/cekdulu/internal/secret"
)

// Options configure a Bot.
type Options struct {
	Client  *Client
	Service *check.Service
	// Store receives reports filed with /lapor; nil disables reporting.
	Store report.Store
	// Hasher hashes reporter Telegram IDs; optional.
	Hasher *secret.Hasher
	// CheckRate limits checks per Telegram user.
	CheckRate ratelimit.Rate
	// ReportRate limits submitted reports per Telegram user.
	ReportRate ratelimit.Rate
	// Workers is the number of updates handled concurrently.
	Workers int
	Logger  *slog.Logger
	Now     func() time.Time
}

// Defaults for Options.
var (
	DefaultCheckRate  = ratelimit.Rate{N: 20, Per: time.Minute}
	DefaultReportRate = ratelimit.Rate{N: 5, Per: 24 * time.Hour}
)

// SessionTTL is how long an unfinished /lapor conversation is kept.
const SessionTTL = 30 * time.Minute

// Bot handles Telegram updates.
type Bot struct {
	opt         Options
	tg          *Client
	log         *slog.Logger
	checkLimit  *ratelimit.Limiter
	reportLimit *ratelimit.Limiter

	mu       sync.Mutex
	sessions map[int64]*session
	username string
}

// New returns a bot.
func New(opt Options) *Bot {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Workers <= 0 {
		opt.Workers = 8
	}
	return &Bot{
		opt:         opt,
		tg:          opt.Client,
		log:         opt.Logger,
		checkLimit:  ratelimit.New(opt.CheckRate, opt.Now),
		reportLimit: ratelimit.New(opt.ReportRate, opt.Now),
		sessions:    map[int64]*session{},
	}
}

var commands = []map[string]string{
	{"command": "cek", "description": "Cek link, nomor HP, atau rekening"},
	{"command": "rekening", "description": "Cek rekening atau e-wallet: /rekening bca 1234567890"},
	{"command": "lapor", "description": "Laporkan penipuan"},
	{"command": "status", "description": "Cek status laporan"},
	{"command": "privasi", "description": "Data apa yang disimpan"},
	{"command": "bantuan", "description": "Cara memakai bot"},
	{"command": "batal", "description": "Batalkan laporan"},
}

// Run long-polls Telegram until ctx is cancelled.
func (b *Bot) Run(ctx context.Context) error {
	var me User
	if err := b.tg.Call(ctx, "getMe", struct{}{}, &me); err != nil {
		return fmt.Errorf("token bot tidak valid atau Telegram tidak bisa dihubungi: %w", err)
	}
	b.mu.Lock()
	b.username = me.Username
	b.mu.Unlock()
	if err := b.tg.Call(ctx, "deleteWebhook", map[string]bool{"drop_pending_updates": false}, nil); err != nil {
		b.log.Warn("gagal menghapus webhook", "err", err)
	}
	if err := b.tg.Call(ctx, "setMyCommands", map[string]any{"commands": commands}, nil); err != nil {
		b.log.Warn("gagal mendaftarkan perintah", "err", err)
	}
	b.log.Info("bot Telegram berjalan", "username", me.Username)

	sem := make(chan struct{}, b.opt.Workers)
	var wg sync.WaitGroup
	defer wg.Wait()
	var offset int64
	backoff := time.Second
	for {
		updates, err := b.tg.GetUpdates(ctx, offset, 50)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			wait := backoff
			var ae *APIError
			if errors.As(err, &ae) && ae.RetryAfter > 0 {
				wait = time.Duration(ae.RetryAfter) * time.Second
			}
			b.log.Warn("getUpdates gagal", "err", err, "retry_in", wait)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		for _, u := range updates {
			offset = u.UpdateID + 1
			sem <- struct{}{}
			wg.Add(1)
			go func(u Update) {
				defer wg.Done()
				defer func() { <-sem }()
				hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
				defer cancel()
				b.Handle(hctx, u)
			}(u)
		}
	}
}

// Handle processes one update synchronously.
func (b *Bot) Handle(ctx context.Context, u Update) {
	defer func() {
		if r := recover(); r != nil {
			b.log.Error("panic saat menangani update", "update", u.UpdateID, "panic", r)
		}
	}()
	switch {
	case u.Message != nil:
		b.handleMessage(ctx, u.Message)
	case u.CallbackQuery != nil:
		b.handleCallback(ctx, u.CallbackQuery)
	}
}

func (b *Bot) reply(ctx context.Context, m *Message, text string, kb *InlineKeyboard) {
	out := Outgoing{ChatID: m.Chat.ID, Text: text, ReplyMarkup: kb}
	out.ReplyTo = &struct {
		MessageID                int64 `json:"message_id"`
		AllowSendingWithoutReply bool  `json:"allow_sending_without_reply"`
	}{m.MessageID, true}
	if err := b.tg.Send(ctx, out); err != nil {
		b.log.Warn("gagal mengirim pesan", "chat_type", m.Chat.Type, "err", err)
	}
}

// parseCommand splits "/cmd@bot args". Commands addressed to another bot
// return an empty command.
func parseCommand(text, username string) (cmd, args string) {
	if !strings.HasPrefix(text, "/") {
		return "", ""
	}
	first, rest, _ := strings.Cut(text, " ")
	if i := strings.IndexAny(first, "\n"); i >= 0 {
		first, rest = first[:i], first[i+1:]+" "+rest
	}
	cmd = strings.TrimPrefix(first, "/")
	if name, target, ok := strings.Cut(cmd, "@"); ok {
		if username != "" && !strings.EqualFold(target, username) {
			return "", ""
		}
		cmd = name
	}
	return strings.ToLower(cmd), strings.TrimSpace(rest)
}

func userKey(u *User) string { return strconv.FormatInt(u.ID, 10) }

func (b *Bot) handleMessage(ctx context.Context, m *Message) {
	if m.From == nil || m.From.IsBot {
		return
	}
	text, ents := m.Content()
	b.mu.Lock()
	username := b.username
	b.mu.Unlock()
	cmd, args := parseCommand(text, username)
	private := m.Chat.Private()

	if cmd != "" {
		b.handleCommand(ctx, m, cmd, args, text, ents)
		return
	}
	if !private {
		return
	}
	if s := b.session(m.From.ID); s != nil {
		b.continueReport(ctx, m, s)
		return
	}
	if m.Document != nil {
		b.checkDocument(ctx, m, m.Document)
		return
	}
	items := Extract(text, ents)
	if len(items) == 0 {
		b.reply(ctx, m, "Saya tidak menemukan link, nomor HP, atau rekening di pesan ini.\n\n"+
			"Contoh yang bisa dicek:\n• <code>https://bca-hadiah.xyz</code>\n• <code>0812 3456 7890</code>\n"+
			"• <code>bca 1234567890</code>\n\nKetik /bantuan untuk panduan.", nil)
		return
	}
	b.checkItems(ctx, m, items)
}

func (b *Bot) handleCommand(ctx context.Context, m *Message, cmd, args, text string, ents []Entity) {
	private := m.Chat.Private()
	switch cmd {
	case "start", "help", "bantuan":
		if cmd == "start" {
			b.dropSession(m.From.ID)
		}
		b.reply(ctx, m, helpText, nil)
	case "privasi":
		b.reply(ctx, m, privacyText, nil)
	case "cek":
		items := Extract(text, ents)
		if r := m.ReplyToMessage; r != nil {
			if r.Document != nil {
				b.checkDocument(ctx, m, r.Document)
				return
			}
			rt, re := r.Content()
			items = append(items, Extract(rt, re)...)
		}
		if len(items) == 0 {
			b.reply(ctx, m, "Tulis yang mau dicek setelah /cek, mis. <code>/cek https://contoh.xyz</code>, "+
				"atau balas pesan mencurigakan dengan /cek.", nil)
			return
		}
		b.checkItems(ctx, m, items[:min(len(items), MaxItems)])
	case "rekening":
		provider, number, _ := strings.Cut(args, " ")
		if strings.TrimSpace(number) == "" {
			b.reply(ctx, m, "Format: <code>/rekening bank nomor</code>\nContoh: <code>/rekening bca 1234567890</code> "+
				"atau <code>/rekening dana 0812xxxx7890</code>", nil)
			return
		}
		b.checkItems(ctx, m, []Item{{Kind: ItemAccount, Provider: provider, Value: number}})
	case "lapor":
		if !private {
			b.reply(ctx, m, "Untuk melapor, kirim /lapor lewat chat pribadi dengan saya supaya datamu tidak terlihat anggota grup.", nil)
			return
		}
		b.startReport(ctx, m, args)
	case "batal":
		if b.dropSession(m.From.ID) {
			b.reply(ctx, m, "Laporan dibatalkan.", nil)
		} else if private {
			b.reply(ctx, m, "Tidak ada laporan yang sedang dibuat.", nil)
		}
	case "status":
		b.reportStatus(ctx, m, args)
	default:
		if private {
			b.reply(ctx, m, "Perintah tidak dikenal. Ketik /bantuan.", nil)
		}
	}
}

func (b *Bot) allowCheck(ctx context.Context, m *Message) bool {
	if b.checkLimit.Allow(userKey(m.From)) {
		return true
	}
	b.reply(ctx, m, "⏳ Terlalu banyak pengecekan. Tunggu sebentar lalu coba lagi.", nil)
	return false
}

func (b *Bot) checkItems(ctx context.Context, m *Message, items []Item) {
	if !b.allowCheck(ctx, m) {
		return
	}
	_ = b.tg.Typing(ctx, m.Chat.ID)
	var results []check.Result
	for _, it := range items {
		var res check.Result
		var err error
		switch it.Kind {
		case ItemLink:
			res, err = b.opt.Service.Link(ctx, it.Value)
		case ItemPhone:
			res, err = b.opt.Service.Phone(ctx, it.Value)
		case ItemAccount:
			res, err = b.opt.Service.Account(ctx, it.Provider, it.Value)
		}
		if err != nil {
			b.log.Error("pengecekan gagal", "kind", it.Kind, "err", err)
			b.reply(ctx, m, "Maaf, terjadi kesalahan saat mengecek. Coba lagi nanti.", nil)
			return
		}
		results = append(results, res)
	}
	b.reply(ctx, m, FormatResults(results), nil)
}

func isAPK(d *Document) bool {
	return strings.HasSuffix(strings.ToLower(d.FileName), ".apk") || d.MimeType == "application/vnd.android.package-archive"
}

func (b *Bot) checkDocument(ctx context.Context, m *Message, d *Document) {
	if !isAPK(d) {
		b.reply(ctx, m, "Saat ini saya hanya bisa memeriksa file <b>APK</b>. Untuk tangkapan layar, kirim link atau nomornya sebagai teks.", nil)
		return
	}
	if d.FileSize > MaxDownloadSize {
		b.reply(ctx, m, fmt.Sprintf("File ini lebih dari %d MB, batas Telegram untuk bot. APK penipuan biasanya kecil (di bawah 10 MB); "+
			"aplikasi sebesar ini lebih mungkin aplikasi biasa, tapi tetap install hanya dari Play Store.", MaxDownloadSize>>20), nil)
		return
	}
	if !b.allowCheck(ctx, m) {
		return
	}
	_ = b.tg.Typing(ctx, m.Chat.ID)
	data, err := b.tg.Download(ctx, d.FileID)
	if err != nil {
		b.log.Warn("gagal mengunduh APK", "err", err)
		b.reply(ctx, m, "Maaf, file tidak bisa diunduh dari Telegram. Coba kirim ulang.", nil)
		return
	}
	name := d.FileName
	if name == "" {
		name = "file.apk"
	}
	res, err := b.opt.Service.APK(ctx, bytes.NewReader(data), int64(len(data)), name)
	if errors.Is(err, check.ErrInvalidAPK) {
		b.reply(ctx, m, "File ini tidak bisa dibaca sebagai APK: "+esc(err.Error()), nil)
		return
	}
	if err != nil {
		b.log.Error("pengecekan APK gagal", "err", err)
		b.reply(ctx, m, "Maaf, terjadi kesalahan saat memeriksa APK. Coba lagi nanti.", nil)
		return
	}
	b.reply(ctx, m, FormatResults([]check.Result{res}), nil)
}

func (b *Bot) reportStatus(ctx context.Context, m *Message, id string) {
	if b.opt.Store == nil {
		b.reply(ctx, m, "Fitur laporan belum diaktifkan di bot ini.", nil)
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		b.reply(ctx, m, "Format: <code>/status ID-laporan</code>", nil)
		return
	}
	r, err := b.opt.Store.GetReport(ctx, id)
	if errors.Is(err, report.ErrNotFound) {
		b.reply(ctx, m, "Laporan dengan ID itu tidak ditemukan.", nil)
		return
	}
	if err != nil {
		b.log.Error("membaca laporan gagal", "err", err)
		b.reply(ctx, m, "Maaf, terjadi kesalahan. Coba lagi nanti.", nil)
		return
	}
	status := map[string]string{
		report.StatusPending:  "⏳ menunggu pemeriksaan moderator",
		report.StatusApproved: "✅ disetujui dan sudah dipakai dalam hasil cek",
		report.StatusRejected: "❌ tidak disetujui moderator",
	}[r.Status]
	b.reply(ctx, m, fmt.Sprintf("Laporan <code>%s</code>\n%s <code>%s</code>\nStatus: %s",
		esc(r.ID), kindIcon[kindTarget(r.Kind)], esc(r.Display), status), nil)
}

func kindTarget(kind string) string {
	if kind == report.KindDomain {
		return "link"
	}
	return kind
}
