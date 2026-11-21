package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Emil-02/cekdulu/internal/apk/apktest"
	"github.com/Emil-02/cekdulu/internal/check"
	"github.com/Emil-02/cekdulu/internal/ratelimit"
	"github.com/Emil-02/cekdulu/internal/report"
	"github.com/Emil-02/cekdulu/internal/secret"
)

const testToken = "123456:TEST-token-rahasia"

// fakeTelegram imitates the Bot API.
type fakeTelegram struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	sent    []map[string]any
	answers []map[string]any
	files   map[string][]byte
	updates chan Update
}

func newFake(t *testing.T) *fakeTelegram {
	f := &fakeTelegram{t: t, files: map[string][]byte{}, updates: make(chan Update, 10)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTelegram) serve(w http.ResponseWriter, r *http.Request) {
	if p, ok := strings.CutPrefix(r.URL.Path, "/file/bot"+testToken+"/"); ok {
		f.mu.Lock()
		data, found := f.files[p]
		f.mu.Unlock()
		if !found {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
		return
	}
	method, ok := strings.CutPrefix(r.URL.Path, "/bot"+testToken+"/")
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
		return
	}
	var params map[string]any
	_ = json.NewDecoder(r.Body).Decode(&params)
	ok200 := func(result any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
	}
	switch method {
	case "getMe":
		ok200(User{ID: 1, IsBot: true, Username: "CekDuluBot"})
	case "getUpdates":
		select {
		case u := <-f.updates:
			ok200([]Update{u})
		case <-time.After(20 * time.Millisecond):
			ok200([]Update{})
		}
	case "sendMessage":
		f.mu.Lock()
		f.sent = append(f.sent, params)
		f.mu.Unlock()
		ok200(map[string]any{"message_id": 99})
	case "answerCallbackQuery":
		f.mu.Lock()
		f.answers = append(f.answers, params)
		f.mu.Unlock()
		ok200(true)
	case "getFile":
		id := params["file_id"].(string)
		f.mu.Lock()
		data := f.files[id]
		f.mu.Unlock()
		ok200(map[string]any{"file_id": id, "file_path": id, "file_size": len(data)})
	default:
		ok200(true)
	}
}

// last returns the text of the latest sent message and clears the log.
func (f *fakeTelegram) last() (string, map[string]any) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		f.t.Fatal("bot tidak mengirim pesan")
	}
	m := f.sent[len(f.sent)-1]
	f.sent = nil
	return m["text"].(string), m
}

func (f *fakeTelegram) none() {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) != 0 {
		f.t.Fatalf("bot tidak boleh membalas, tapi mengirim: %v", f.sent)
	}
}

type env struct {
	*fakeTelegram
	bot   *Bot
	store *report.Memory
	ctx   context.Context
	msgID int64
}

func newEnv(t *testing.T, mod func(*Options)) *env {
	t.Helper()
	f := newFake(t)
	h, err := secret.NewHasher(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	store := report.NewMemory()
	svc, err := check.New(check.Config{Store: store, Hasher: h})
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{Client: NewClient(testToken, f.srv.URL, nil), Service: svc, Store: store, Hasher: h}
	if mod != nil {
		mod(&opt)
	}
	bot := New(opt)
	bot.username = "CekDuluBot"
	return &env{fakeTelegram: f, bot: bot, store: store, ctx: context.Background()}
}

var alice = &User{ID: 42, FirstName: "Alice"}

func (e *env) send(chat Chat, m Message) {
	e.msgID++
	m.MessageID = e.msgID
	m.Chat = chat
	if m.From == nil {
		m.From = alice
	}
	e.bot.Handle(e.ctx, Update{UpdateID: e.msgID, Message: &m})
}

func (e *env) private(text string) { e.send(Chat{ID: 42, Type: "private"}, Message{Text: text}) }

var group = Chat{ID: -100, Type: "supergroup"}

func TestPrivateLinkCheck(t *testing.T) {
	e := newEnv(t, nil)
	e.private("Selamat! Klaim hadiah di http://bca-klikbca-verifikasi.xyz/login sekarang")
	text, raw := e.last()
	for _, want := range []string{"BAHAYA", "bca-klikbca-verifikasi[.]xyz", "BCA", "Pernah tertipu"} {
		if !strings.Contains(text, want) {
			t.Errorf("balasan tidak memuat %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "bca-klikbca-verifikasi.xyz") {
		t.Error("tautan berbahaya harus ditampilkan dalam bentuk yang tidak bisa diklik")
	}
	if raw["parse_mode"] != "HTML" || raw["reply_parameters"] == nil {
		t.Errorf("parameter pesan: %v", raw)
	}
	if lp, _ := raw["link_preview_options"].(map[string]any); lp["is_disabled"] != true {
		t.Error("pratinjau tautan harus dimatikan")
	}

	e.private("halo apa kabar")
	if text, _ := e.last(); !strings.Contains(text, "tidak menemukan") {
		t.Errorf("pesan tanpa indikator: %s", text)
	}
}

func TestGroupBehaviour(t *testing.T) {
	e := newEnv(t, nil)
	suspicious := Message{Text: "Cek resi paket kamu: http://jnt-resi.xyz/apk", From: &User{ID: 7}}
	e.send(group, suspicious)
	e.none()

	e.send(group, Message{Text: "/cek@LainBot http://jnt-resi.xyz"})
	e.none()

	e.send(group, Message{Text: "/cek", ReplyToMessage: &suspicious})
	if text, _ := e.last(); !strings.Contains(text, "jnt-resi[.]xyz") {
		t.Fatalf("/cek sebagai balasan: %s", text)
	}

	e.send(group, Message{Text: "/lapor"})
	if text, _ := e.last(); !strings.Contains(text, "chat pribadi") {
		t.Fatalf("/lapor di grup: %s", text)
	}
}

func TestReportConversation(t *testing.T) {
	e := newEnv(t, nil)
	e.private("/lapor")
	if text, _ := e.last(); !strings.Contains(text, "Apa yang mau dilaporkan") {
		t.Fatalf("awal laporan: %s", text)
	}
	e.private("halo")
	if text, _ := e.last(); !strings.Contains(text, "tidak mengenali") {
		t.Fatalf("input tidak dikenal: %s", text)
	}
	e.private("https://www.klikbca.com")
	if text, _ := e.last(); !strings.Contains(text, "domain resmi") {
		t.Fatalf("domain resmi harus ditolak: %s", text)
	}
	e.private("Nomornya +62 812-3456-7890")
	text, raw := e.last()
	if !strings.Contains(text, "0812") || strings.Contains(text, "3456") {
		t.Fatalf("nomor harus disamarkan: %s", text)
	}
	kb := raw["reply_markup"].(map[string]any)["inline_keyboard"].([]any)
	if len(kb) != len(report.Categories) {
		t.Fatalf("tombol kategori = %d", len(kb))
	}

	e.private("teks bebas")
	if text, _ := e.last(); !strings.Contains(text, "tombol") {
		t.Fatalf("teks saat memilih kategori: %s", text)
	}
	cb := &CallbackQuery{ID: "cb1", From: *alice, Data: "cat:job", Message: &Message{MessageID: 5, Chat: Chat{ID: 42, Type: "private"}}}
	e.bot.Handle(e.ctx, Update{UpdateID: 100, CallbackQuery: cb})
	if text, _ := e.last(); !strings.Contains(text, "kronologi") {
		t.Fatalf("setelah kategori: %s", text)
	}
	e.private("pendek")
	if text, _ := e.last(); !strings.Contains(text, "20") {
		t.Fatalf("kronologi pendek: %s", text)
	}
	e.private("Ditawari kerja paruh waktu like video, lalu diminta deposit untuk tugas VIP.")
	e.last()
	e.private("abc")
	if text, _ := e.last(); !strings.Contains(text, "angka") {
		t.Fatalf("kerugian tidak valid: %s", text)
	}
	e.private("1,5jt")
	text, _ = e.last()
	if !strings.Contains(text, "Laporan terkirim") {
		t.Fatalf("laporan terkirim: %s", text)
	}

	reps, _ := e.store.ListReports(e.ctx, report.StatusPending, 10, 0)
	if len(reps) != 1 || reps[0].Category != "job" || *reps[0].LossAmount != 1_500_000 || reps[0].Kind != report.KindPhone {
		t.Fatalf("laporan tersimpan: %+v", reps)
	}
	id := reps[0].ID
	if !strings.Contains(text, id) {
		t.Fatal("ID laporan harus ditampilkan")
	}

	// Stale button presses after the conversation are rejected politely.
	e.bot.Handle(e.ctx, Update{UpdateID: 101, CallbackQuery: cb})
	if len(e.answers) != 2 || !strings.Contains(e.answers[1]["text"].(string), "berakhir") {
		t.Fatalf("callback basi: %v", e.answers)
	}

	e.private("/status " + id)
	if text, _ := e.last(); !strings.Contains(text, "menunggu") {
		t.Fatalf("status pending: %s", text)
	}
	if _, err := e.store.Decide(e.ctx, id, true, "emil", ""); err != nil {
		t.Fatal(err)
	}
	e.private("/status " + id)
	if text, _ := e.last(); !strings.Contains(text, "disetujui") {
		t.Fatalf("status disetujui: %s", text)
	}

	e.private("ada yang telpon dari 081234567890 ngaku kurir")
	if text, _ := e.last(); !strings.Contains(text, "BAHAYA") || !strings.Contains(text, "sudah dilaporkan") {
		t.Fatalf("nomor yang dilaporkan: %s", text)
	}
}

func TestReportShortcutAndCancel(t *testing.T) {
	e := newEnv(t, nil)
	e.private("/lapor bca 1234567890")
	if text, raw := e.last(); !strings.Contains(text, "******7890") || raw["reply_markup"] == nil {
		t.Fatalf("/lapor dengan argumen: %s", text)
	}
	e.private("/batal")
	if text, _ := e.last(); !strings.Contains(text, "dibatalkan") {
		t.Fatalf("/batal: %s", text)
	}
	e.private("bca 1234567890")
	if text, _ := e.last(); !strings.Contains(text, "RISIKO RENDAH") {
		t.Fatalf("setelah batal pesan harus dicek biasa: %s", text)
	}
}

func TestReportRateLimit(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.ReportRate = ratelimit.Rate{N: 1, Per: time.Hour} })
	file := func() {
		e.private("/lapor penipu-shop.xyz")
		e.bot.Handle(e.ctx, Update{CallbackQuery: &CallbackQuery{ID: "x", From: *alice, Data: "cat:online_shop",
			Message: &Message{Chat: Chat{ID: 42, Type: "private"}}}})
		e.private("Barang tidak pernah dikirim setelah saya transfer ke penjual.")
		e.private("0")
	}
	file()
	if text, _ := e.last(); !strings.Contains(text, "terkirim") {
		t.Fatalf("laporan pertama: %s", text)
	}
	file()
	if text, _ := e.last(); !strings.Contains(text, "banyak laporan") {
		t.Fatalf("laporan kedua harus dibatasi: %s", text)
	}
}

func TestCheckRateLimit(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.CheckRate = ratelimit.Rate{N: 1, Per: time.Minute} })
	e.private("081234567890")
	e.last()
	e.private("081234567890")
	if text, _ := e.last(); !strings.Contains(text, "Terlalu banyak") {
		t.Fatalf("batas cek: %s", text)
	}
}

var scamAPK = apktest.Spec{
	Package:     "com.example.myapplication",
	Label:       "Undangan Pernikahan",
	MinSDK:      21,
	TargetSDK:   22,
	Permissions: []string{"android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.SEND_SMS"},
	Receivers:   []apktest.Component{{Name: ".SmsReceiver", Actions: []string{"android.provider.Telephony.SMS_RECEIVED"}}},
	DexStrings:  []string{"https://api.telegram.org/bot1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ/sendMessage"},
	CertCN:      "Android Debug",
}

func TestAPKDocument(t *testing.T) {
	e := newEnv(t, nil)
	data := apktest.Build(scamAPK)
	e.files["apk1"] = data
	e.send(Chat{ID: 42, Type: "private"}, Message{Document: &Document{FileID: "apk1", FileName: "Undangan Pernikahan.apk", FileSize: int64(len(data))}})
	text, _ := e.last()
	if !strings.Contains(text, "BAHAYA") || !strings.Contains(text, "SMS") {
		t.Fatalf("APK penipuan: %s", text)
	}

	e.files["junk"] = []byte("bukan apk")
	e.send(Chat{ID: 42, Type: "private"}, Message{Document: &Document{FileID: "junk", FileName: "x.apk", FileSize: 9}})
	if text, _ := e.last(); !strings.Contains(text, "APK") {
		t.Fatalf("APK rusak: %s", text)
	}

	e.send(Chat{ID: 42, Type: "private"}, Message{Document: &Document{FileID: "pdf", FileName: "tagihan.pdf", FileSize: 10}})
	if text, _ := e.last(); !strings.Contains(text, "hanya bisa memeriksa file") {
		t.Fatalf("bukan APK: %s", text)
	}
	e.send(Chat{ID: 42, Type: "private"}, Message{Document: &Document{FileID: "big", FileName: "game.apk", FileSize: MaxDownloadSize + 1}})
	if text, _ := e.last(); !strings.Contains(text, "lebih dari 20 MB") {
		t.Fatalf("APK besar: %s", text)
	}
}

func TestCommands(t *testing.T) {
	e := newEnv(t, nil)
	for cmd, want := range map[string]string{
		"/start":                     "CekDulu",
		"/bantuan":                   "/lapor",
		"/privasi":                   "hash",
		"/rekening":                  "Format",
		"/rekening dana 500000":      "tidak valid",
		"/rekening jago 10293847566": "Bank Jago",
		"/cek":                       "Tulis yang mau dicek",
		"/status":                    "Format",
		"/status 123":                "tidak ditemukan",
		"/batal":                     "Tidak ada laporan",
		"/apaini":                    "tidak dikenal",
	} {
		e.private(cmd)
		if text, _ := e.last(); !strings.Contains(text, want) {
			t.Errorf("%s: balasan tidak memuat %q:\n%s", cmd, want, text)
		}
	}
}

func TestRunLoop(t *testing.T) {
	e := newEnv(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.bot.Run(ctx) }()
	e.updates <- Update{UpdateID: 10, Message: &Message{MessageID: 1, From: alice, Chat: Chat{ID: 42, Type: "private"}, Text: "/start"}}

	deadline := time.Now().Add(3 * time.Second)
	for {
		e.mu.Lock()
		n := len(e.sent)
		e.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bot tidak membalas update dari getUpdates")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run tidak berhenti setelah dibatalkan")
	}

	bad := New(Options{Client: NewClient("salah", e.srv.URL, nil)})
	if err := bad.Run(context.Background()); err == nil || strings.Contains(err.Error(), "salah") {
		t.Fatalf("token salah: %v", err)
	}
}

func TestClientNeverLeaksToken(t *testing.T) {
	c := NewClient(testToken, "http://127.0.0.1:1", &http.Client{Timeout: time.Second})
	err := c.Call(context.Background(), "getMe", struct{}{}, nil)
	if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "TEST-token") {
		t.Fatalf("error membocorkan token: %v", err)
	}
	if _, err := c.Download(context.Background(), "x"); err == nil || strings.Contains(err.Error(), "TEST-token") {
		t.Fatalf("error unduh membocorkan token: %v", err)
	}
}

func TestParseRupiah(t *testing.T) {
	for in, want := range map[string]int64{
		"250000": 250000, "Rp 250.000": 250000, "1,5jt": 1500000, "2 juta": 2000000,
		"300rb": 300000, "50k": 50000, "0": 0, "Rp 250.000,00": 250000, "1.250.000,5": 1250000, "1,000,000": 1000000,
	} {
		got, err := parseRupiah(in)
		if err != nil || got == nil || *got != want {
			t.Errorf("parseRupiah(%q) = %v, %v; ingin %d", in, got, err, want)
		}
	}
	for _, in := range []string{"-", "lewati", "tidak"} {
		if got, err := parseRupiah(in); err != nil || got != nil {
			t.Errorf("parseRupiah(%q) = %v, %v; ingin nil", in, got, err)
		}
	}
	for _, in := range []string{"abc", "-5", "99999999999999999"} {
		if _, err := parseRupiah(in); err == nil {
			t.Errorf("parseRupiah(%q) harus gagal", in)
		}
	}
}

func TestParseCommand(t *testing.T) {
	cases := []struct{ in, cmd, args string }{
		{"/cek https://a.xyz", "cek", "https://a.xyz"},
		{"/Cek@CekDuluBot halo", "cek", "halo"},
		{"/cek@LainBot halo", "", ""},
		{"/cek\nhttps://a.xyz", "cek", "https://a.xyz"},
		{"bukan perintah", "", ""},
	}
	for _, c := range cases {
		cmd, args := parseCommand(c.in, "CekDuluBot")
		if cmd != c.cmd || args != c.args {
			t.Errorf("parseCommand(%q) = %q, %q", c.in, cmd, args)
		}
	}
}
