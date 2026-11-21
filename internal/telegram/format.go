package telegram

import (
	"fmt"
	"html"
	"strings"
	"unicode/utf8"

	"github.com/Emil-02/cekdulu/internal/check"
	"github.com/Emil-02/cekdulu/internal/link"
	"github.com/Emil-02/cekdulu/internal/score"
)

// MaxMessageLen keeps replies below Telegram's 4096 character limit.
const MaxMessageLen = 4000

const helpText = `👋 Halo! Saya <b>CekDulu</b>, teman untuk <i>cek dulu</i> sebelum percaya.

Kirim atau <i>forward</i> ke saya:
🔗 link mencurigakan
📱 nomor HP yang menghubungimu
🏦 rekening, contoh: <code>bca 1234567890</code>
📦 file APK (mis. "Undangan.apk"). <b>Jangan dibuka</b>, kirim saja ke sini.

Perintah:
/cek <i>teks</i> – cek link, nomor, atau rekening di teks
/rekening <i>bank nomor</i> – cek rekening atau e-wallet
/lapor – laporkan penipuan yang kamu alami
/status <i>id</i> – cek status laporanmu
/privasi – data apa yang disimpan
/batal – batalkan laporan

Di grup: balas pesan mencurigakan dengan /cek.`

const privacyText = `🔒 <b>Privasi CekDulu</b>

• Pesan yang kamu kirim <b>tidak disimpan</b>. Bot hanya mengambil link, nomor HP, rekening, atau APK di dalamnya untuk dicek.
• Saat kamu melapor, nomor HP dan rekening disimpan sebagai <b>hash</b> (tidak bisa dibaca) dan versi tersamar, mis. 0812****890.
• ID Telegram-mu hanya disimpan sebagai hash untuk mencegah laporan spam.
• Laporan baru dipakai setelah diperiksa moderator. Pihak yang merasa keliru dilaporkan bisa mengajukan sanggahan.`

const footer = "\n\n<i>Penilaian otomatis, bukan tuduhan hukum. Skor rendah tidak menjamin aman.</i>\nPernah tertipu? Kirim /lapor."

var kindIcon = map[string]string{
	score.TargetLink:    "🔗",
	score.TargetPhone:   "📱",
	score.TargetAccount: "🏦",
	score.TargetAPK:     "📦",
}

func badge(level string) string {
	switch level {
	case score.LevelDanger:
		return "🔴 <b>BAHAYA</b>"
	case score.LevelWarning:
		return "🟡 <b>WASPADA</b>"
	}
	return "🟢 <b>RISIKO RENDAH</b>"
}

// defang makes a URL or domain non-clickable, e.g. hxxps://bca-hadiah[.]xyz.
func defang(s string) string {
	s = truncate(s, 80)
	s = strings.Replace(s, "http", "hxxp", 1)
	return strings.ReplaceAll(s, ".", "[.]")
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func esc(s string) string { return html.EscapeString(s) }

// FormatResult renders one check result as Telegram HTML.
func FormatResult(res check.Result) string {
	var b strings.Builder
	label := res.Input
	var final string
	if res.Target == score.TargetLink {
		if rep, ok := res.Details.(link.Report); ok {
			if rep.Domain != "" {
				label = rep.Host
			}
			if rep.FinalURL != "" {
				final = rep.Domain
			}
		}
		label = defang(label)
	}
	fmt.Fprintf(&b, "%s <code>%s</code>\n%s (skor %d/100)", kindIcon[res.Target], esc(truncate(label, 80)), badge(res.Level), res.Score)
	if final != "" {
		fmt.Fprintf(&b, "\n↪️ Ternyata mengarah ke <code>%s</code>", esc(defang(final)))
	}

	var shown []score.Reason
	for _, r := range res.Reasons {
		if r.Score > 0 {
			shown = append(shown, r)
		}
	}
	if len(shown) == 0 {
		shown = res.Reasons
	}
	if len(shown) > 4 {
		shown = shown[:4]
	}
	for _, r := range shown {
		fmt.Fprintf(&b, "\n• %s", esc(truncate(r.Message, 300)))
	}
	if len(shown) == 0 {
		switch res.Target {
		case score.TargetPhone, score.TargetAccount:
			b.WriteString("\n• Belum ada laporan terverifikasi. Penipu sering berganti nomor, jadi tetap waspada.")
		default:
			b.WriteString("\n• Tidak ditemukan tanda bahaya pada pemeriksaan ini.")
		}
	}
	for _, r := range shown {
		if r.Advice != "" && r.Score > 0 {
			fmt.Fprintf(&b, "\n💡 %s", esc(truncate(r.Advice, 300)))
			break
		}
	}
	return b.String()
}

// FormatResults joins several results and adds the disclaimer. Results that
// would exceed Telegram's message limit are summarised instead.
func FormatResults(results []check.Result) string {
	var b strings.Builder
	for i, r := range results {
		part := FormatResult(r)
		if i > 0 {
			part = "\n\n" + part
		}
		if utf8.RuneCountInString(b.String()+part+footer) > MaxMessageLen-100 {
			fmt.Fprintf(&b, "\n\n…%d hasil lain tidak ditampilkan. Kirim satu per satu.", len(results)-i)
			break
		}
		b.WriteString(part)
	}
	b.WriteString(footer)
	return b.String()
}
