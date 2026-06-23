# Perbaikan False-Positive: `auth_bypass` melaporkan `/administrator` (soft-404)

- **Tanggal:** 2026-06-23
- **Modul terdampak:** `cyberloka/active/auth_bypass.py` → `_probe_admin_paths`
- **Versi:** v0.10.6
- **Klasifikasi internal:** False-Positive (akurasi validasi engine).
- **Laporan keliru:** "Halaman admin/internal dapat diakses publik: /administrator",
  SEDANG, confidence `firm`, CWE-284, A07:2021 — padahal `/administrator`
  sebenarnya **404** saat di-cek manual.

## Ringkasan

`_probe_admin_paths` melaporkan path admin hanya dari **HTTP 200 + body memuat
substring generik** (`admin`/`login`/`username`/`password`/`dashboard`).
Pendekatan ini *content-blind*. Situs SPA (Next.js/Nuxt) membalas **200 berisi
beranda** — atau halaman **"404" yang dirender klien** — untuk path APA PUN, dan
beranda biasanya memuat tautan "Admin Login". Akibatnya `/administrator`
dilaporkan `firm` meski status HTTP sebenarnya 404 (soft-404 di dalam 200).

## Akar masalah

1. **Tidak ada deteksi soft-404 / catch-all.** Tidak ada perbandingan dengan
   path random maupun beranda `/`.
2. **Tidak ada deteksi marker not-found** ("404", "halaman tidak ditemukan")
   di dalam body 200.
3. **Sinyal terlalu lemah.** Substring "admin" pada shell SPA generik dianggap
   bukti halaman admin.

## Perbaikan (secure-by-design)

`_probe_admin_paths` kini hanya melaporkan bila path **lolos seluruh** gerbang:

1. **Soft-404 guard** — response tidak identik dengan path random kontrol
   (`cyberloka_<rand>_noexist`).
2. **Homepage guard** — response tidak identik dengan beranda `/`.
3. **Not-found guard** — body tidak memuat marker `404 / not found /
   halaman tidak ditemukan` (regex `NOTFOUND_MARKERS`).
4. **Genuine-signal** — wajib salah satu: FORM `type=password` sungguhan,
   signature software admin dikenal (wp-login, joomla, phpMyAdmin, grafana,
   kibana, django, dll.), atau `<title>` admin/login DAN bukan shell SPA.
5. **Double-confirm** — request ke-2 harus tetap konsisten (tetap 200, tetap
   bukan soft-404/echo).

### Klasifikasi severity baru
- Konten panel terlihat tanpa login (`logout`/menu admin, tanpa form password)
  → **HIGH `confirmed`** (akses publik nyata).
- Form login admin terjangkau → **LOW `firm`** (endpoint ada, informational).
- Indikasi software/title admin → **MEDIUM `firm`**.
- Soft-404 / echo beranda / shell SPA generik → **tidak ada finding**.

## Pencegahan regresi

`tests/test_auth_bypass_admin.py`:
- `test_spa_catchall_no_admin_finding` — beranda SPA catch-all → tidak dilaporkan.
- `test_soft_404_rejected` — 200 berisi "halaman tidak ditemukan" → ditolak.
- `test_real_admin_login_flagged_low` — login admin asli tetap terdeteksi (LOW/firm).

Suite penuh hijau: **24 passed, 1 skipped**.

## Catatan pola lintas-modul

Akar yang sama (HTTP 200 / refleksi nama-path dianggap bukti tanpa memverifikasi
konten/eksploitabilitas) berpotensi ada di modul lain. Standar emas proyek:
selalu (a) bandingkan dengan kontrol negatif, (b) verifikasi tanda-tangan konten
atau bukti eksekusi, (c) double-confirm. Rujuk juga
`2026-06-23-sensitive-files-false-positive.md`.
