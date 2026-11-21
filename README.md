# CekDulu

[![jaga](https://jaga-card.vercel.app/api/badge?owner=Emil-02&repo=cekdulu)](https://jaga-card.vercel.app/r/Emil-02/cekdulu)

[![CI](https://github.com/Emil-02/cekdulu/actions/workflows/ci.yml/badge.svg)](https://github.com/Emil-02/cekdulu/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![spruce](https://gh-spruce.vercel.app/api/badge?repo=Emil-02/cekdulu)](https://gh-spruce.vercel.app/u/Emil-02)

CekDulu adalah proyek open source untuk membantu developer dan masyarakat mengecek potensi penipuan sebelum mempercayai tautan, APK, nomor ponsel, atau rekening yang mencurigakan.

Tujuan proyek ini bukan untuk menuduh seseorang, melainkan memberikan penilaian otomatis yang dibangun dari aturan terbuka, data referensi, dan laporan masyarakat yang telah dimoderasi.

## Fitur utama

- Analisis URL dan domain untuk deteksi phishing, shortener, domain mirip, dan indikator berbahaya.
- Pemeriksaan APK secara statis tanpa mengeksekusi file.
- Normalisasi dan masking nomor HP serta nomor rekening.
- Skor risiko yang dijelaskan dengan alasan manusiawi.
- Laporan masyarakat (dengan bukti foto/PDF), antrean moderasi, dan jalur sanggahan.
- Penyimpanan Postgres/Supabase dengan migrasi otomatis, atau memori untuk uji lokal.
- Mode online: mengikuti pengalihan tautan (membuka shortener) dan mengecek umur domain via RDAP, dengan klien yang aman dari SSRF.
- Bot Telegram: forward pesan mencurigakan atau kirim APK, langsung dapat hasil; bisa melapor lewat percakapan.
- Dukungan CLI dan REST API untuk integrasi internal atau produk lokal.

## Struktur proyek

- `cmd/cekdulu` — CLI untuk pengecekan cepat.
- `cmd/cekdulu-api` — API HTTP untuk integrasi.
- `cmd/cekdulu-telegram` — bot Telegram.
- `internal/api` — handler HTTP: cek, laporan, sanggahan, moderasi, rate limit.
- `internal/telegram` — bot Telegram: ekstraksi link/nomor/rekening dari pesan, format hasil, alur /lapor.
- `internal/ratelimit` — pembatas permintaan per IP/pengguna.
- `internal/app` — membaca konfigurasi dari environment dan merangkai store, bukti, dan service.
- `internal/check` — service layer yang menggabungkan analisis dan pengecekan.
- `internal/link` — analyzer URL.
- `internal/apk` — analyzer APK statis.
- `internal/phone` — normalisasi nomor HP.
- `internal/account` — normalisasi rekening.
- `internal/report` — model laporan dan moderasi (store memori & Postgres).
- `internal/blob` — penyimpanan file bukti (folder lokal atau Supabase Storage).
- `internal/score` — rule engine untuk skor risiko.
- `rules/` — aturan YAML yang dapat dikustomisasi.
- `supabase/` — migration schema pendukung backend.

## Quick start

### 1) Jalankan tes

```bash
go test ./...

# tes store Postgres (database akan dikosongkan)
CEKDULU_TEST_DATABASE_URL="postgres://<user>:<password>@localhost:5432/cekdulu_test" go test ./internal/report/
```

### 2) Gunakan CLI

```bash
go run ./cmd/cekdulu check link https://example.com

# ikuti pengalihan (mis. bit.ly) dan cek umur domain
go run ./cmd/cekdulu check --online link https://bit.ly/contoh

go run ./cmd/cekdulu check phone 0812xxxx7890

go run ./cmd/cekdulu check account bca 1234567890
```

Jika `DATABASE_URL` dan `CEKDULU_HMAC_KEY` diatur (sama dengan server), CLI juga mencocokkan input dengan laporan masyarakat yang sudah disetujui.

### 3) Jalankan API lokal

Tanpa database (data laporan hilang saat server berhenti):

```bash
CEKDULU_PORT=8080 go run ./cmd/cekdulu-api
curl http://localhost:8080/health
```

Dengan Postgres/Supabase:

```bash
export DATABASE_URL="postgres://<user>:<password>@<host>:5432/<db>"
export CEKDULU_HMAC_KEY="$(openssl rand -hex 32)"          # simpan baik-baik, jangan diganti
export CEKDULU_MODERATORS="emil:$(openssl rand -hex 24)"   # nama:token, pisahkan dengan koma
export CEKDULU_EVIDENCE_DIR=./data/bukti
go run ./cmd/cekdulu migrate                               # atau CEKDULU_MIGRATE=1 saat start
go run ./cmd/cekdulu-api
```

### 4) Jalankan bot Telegram

1. Buat bot lewat [@BotFather](https://t.me/BotFather) (`/newbot`) dan salin token-nya.
2. Jalankan dengan konfigurasi yang sama seperti API (database dan kunci HMAC harus sama agar laporan dari bot muncul di antrean moderator API):

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC..."
go run ./cmd/cekdulu-telegram
```

Bot memakai *long polling*, jadi tidak perlu domain publik atau HTTPS. Cara pakai:

- Kirim atau *forward* pesan berisi link, nomor HP, atau rekening (`bca 1234567890`), maksimal 5 per pesan.
- Kirim file APK (maks. 20 MB, batas Telegram) untuk diperiksa tanpa dijalankan.
- `/lapor` memandu pelaporan: apa yang dilaporkan → kategori (tombol) → kronologi → kerugian. `/status <id>` untuk cek status.
- Di grup, bot hanya merespons perintah: balas pesan mencurigakan dengan `/cek`. Dengan *privacy mode* bawaan Telegram, `/cek` tanpa nama bot bisa tidak sampai bila ada bot lain di grup; pakai `/cek@NamaBot` atau matikan lewat @BotFather → `/setprivacy` (bot tetap mengabaikan pesan selain perintah).

Bot tidak menyimpan isi pesan. Laporan dari bot menyimpan hash ID Telegram pelapor (untuk deteksi spam), bukan ID aslinya. Batas: 20 cek per menit dan 5 laporan per hari per pengguna.

### 5) Docker

```bash
docker build -t cekdulu .
docker run -p 8080:8080 --env-file .env cekdulu                  # API
docker run --env-file .env cekdulu cekdulu-telegram              # bot Telegram
```

## Konfigurasi

| Variabel | Keterangan |
|---|---|
| `CEKDULU_PORT` | Port API (default `8080`). |
| `DATABASE_URL` | Koneksi Postgres/Supabase. Kosong = penyimpanan memori. |
| `CEKDULU_MIGRATE` | `1` untuk menerapkan migrasi `supabase/migrations` saat start. |
| `CEKDULU_HMAC_KEY` | Minimal 32 karakter. Wajib untuk laporan nomor HP/rekening; juga dipakai untuk hash kontak pelapor dan IP. Mengganti kunci membuat laporan lama tidak bisa dicocokkan. |
| `CEKDULU_MODERATORS` | Daftar `nama:token` (token minimal 24 karakter). Kosong = endpoint moderasi nonaktif. |
| `CEKDULU_ONLINE` | Mode online untuk cek tautan. Default aktif di API dan bot, nonaktif di CLI (pakai `--online`). |
| `CEKDULU_EVIDENCE_DIR` | Folder penyimpanan file bukti. |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `CEKDULU_EVIDENCE_BUCKET` | Simpan bukti di bucket privat Supabase Storage (default bucket `evidence`). Diutamakan daripada `CEKDULU_EVIDENCE_DIR`. |
| `TELEGRAM_BOT_TOKEN` | Token bot dari @BotFather (hanya untuk `cekdulu-telegram`). |
| `CEKDULU_TRUST_PROXY` | `1` jika API berada di belakang reverse proxy yang mengisi `X-Forwarded-For`. |

Tanpa penyimpanan bukti, laporan tetap bisa dikirim tetapi tanpa lampiran.

## API

Semua respons berbentuk JSON. Error: `{"error": "pesan"}`.

| Metode & path | Keterangan |
|---|---|
| `GET /health` | Status server dan fitur yang aktif. |
| `POST /api/v1/check/link` | `{"url": "..."}` |
| `POST /api/v1/check/phone` | `{"phone": "..."}` |
| `POST /api/v1/check/account` | `{"provider": "bca", "number": "..."}` |
| `POST /api/v1/check/apk` | multipart, field `file` (maks. 64 MB). |
| `POST /api/v1/reports` | Kirim laporan (JSON atau multipart dengan file `evidence`, maks. 3 × 5 MB JPG/PNG/WEBP/PDF). |
| `GET /api/v1/reports/{id}` | Status laporan untuk pelapor. |
| `POST /api/v1/appeals` | Sanggah indikator yang sudah tampil. |
| `GET /api/v1/categories` | Daftar kategori penipuan. |
| `GET /api/v1/rules` | Aturan penilaian yang sedang dipakai. |
| `GET /api/v1/stats` | Statistik laporan terverifikasi. |
| `GET /api/v1/blocklist/{domain\|apk}` | Indikator aktif; tambah `?format=txt` untuk teks per baris. |

Endpoint moderator (header `Authorization: Bearer <token>`):

| Metode & path | Keterangan |
|---|---|
| `GET /api/v1/admin/reports?status=pending` | Antrean laporan (`pending`, `approved`, `rejected`, `all`; `limit`, `offset`). |
| `GET /api/v1/admin/reports/{id}` | Detail laporan, termasuk jumlah laporan dari pelapor yang sama dalam 24 jam. |
| `POST /api/v1/admin/reports/{id}/approve` atau `/reject` | Body opsional `{"note": "..."}`. |
| `GET /api/v1/admin/reports/{id}/evidence/{evidence_id}` | Unduh file bukti. |
| `GET /api/v1/admin/appeals?status=pending` | Antrean sanggahan. |
| `POST /api/v1/admin/appeals/{id}/accept` atau `/reject` | Diterima = indikator dihapus dari hasil cek. |

Contoh mengirim laporan:

```bash
curl -X POST http://localhost:8080/api/v1/reports \
  -F kind=phone -F value=0812xxxx7890 -F category=impersonation \
  -F "description=Mengaku kurir dan mengirim APK undangan lewat WhatsApp." \
  -F loss_amount=250000 -F evidence=@tangkapan-layar.png
```

`kind` bisa `phone`, `account` (tambah `provider`), `domain`/`link` (isi tautan atau domain), atau `apk` (SHA-256). Laporan baru memengaruhi skor setelah disetujui moderator. Kirim laporan dan sanggahan dibatasi 10 per jam per IP, cek dibatasi 60 per menit per IP.

## Privacy dan etika

- Nomor HP dan rekening diproses dengan HMAC dan ditampilkan dalam bentuk yang sudah dimasking.
- Domain dan hash APK bisa menjadi indikator publik, tetapi tetap di bawah proses moderasi sebelum ditampilkan ke publik luas.
- Proyek ini dibuat untuk membantu verifikasi, bukan untuk menyalahkan atau menebar stigma.

## Roadmap

- Menyempurnakan data referensi domain dan APK yang sering dipakai scam.
- Panel moderator berbasis web di atas endpoint admin.
- Bot WhatsApp dan ekstensi browser.
- Notifikasi laporan baru ke moderator lewat Telegram.
- Menambahkan dashboard komunitas dan pencarian laporan.

## Lisensi

[MIT](LICENSE) © 2026 Emil Rahmat
