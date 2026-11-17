# CekDulu

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
- Model laporan masyarakat dengan moderasi untuk indikator berbahaya.
- Dukungan CLI dan REST API untuk integrasi internal atau produk lokal.

## Struktur proyek

- `cmd/cekdulu` — CLI untuk pengecekan cepat.
- `cmd/cekdulu-api` — API HTTP untuk integrasi.
- `internal/check` — service layer yang menggabungkan analisis dan pengecekan.
- `internal/link` — analyzer URL.
- `internal/apk` — analyzer APK statis.
- `internal/phone` — normalisasi nomor HP.
- `internal/account` — normalisasi rekening.
- `internal/report` — model laporan dan moderasi.
- `internal/score` — rule engine untuk skor risiko.
- `rules/` — aturan YAML yang dapat dikustomisasi.
- `supabase/` — migration schema pendukung backend.

## Quick start

### 1) Jalankan tes

```bash
go test ./...
```

### 2) Gunakan CLI

```bash
go run ./cmd/cekdulu check link https://example.com

go run ./cmd/cekdulu check phone 081234567890

go run ./cmd/cekdulu check account bca 1234567890
```

### 3) Jalankan API lokal

```bash
CEKDULU_PORT=8080 go run ./cmd/cekdulu-api
```

Lalu cek:

```bash
curl http://localhost:8080/health
```

## Privacy dan etika

- Nomor HP dan rekening diproses dengan HMAC dan ditampilkan dalam bentuk yang sudah dimasking.
- Domain dan hash APK bisa menjadi indikator publik, tetapi tetap di bawah proses moderasi sebelum ditampilkan ke publik luas.
- Proyek ini dibuat untuk membantu verifikasi, bukan untuk menyalahkan atau menebar stigma.

## Roadmap

- Menyempurnakan data referensi domain dan APK yang sering dipakai scam.
- Menambahkan autentikasi dan panel moderator.
- Menyiapkan backend Postgres/Supabase untuk produksi.
- Menambahkan dashboard komunitas dan pencarian laporan.

## Lisensi

[MIT](LICENSE) © 2026 Emil Rahmat
