# Perbaikan False-Positive: `sensitive_files` melaporkan `/.env` HTML sebagai KRITIS

- **Tanggal:** 2026-06-23
- **Modul terdampak:** `cyberloka/passive/sensitive_files.py`
- **Helper terdampak:** `cyberloka/core/validation.py` → `looks_like_html_shell()`
- **Versi:** v0.10.6
- **Klasifikasi internal:** False-Positive (bukan kerentanan pada CyberLoka itu sendiri,
  melainkan cacat akurasi/validasi pada engine pemindai).
- **OWASP (laporan keliru):** A05:2021 Security Misconfiguration — yang seharusnya
  TIDAK dipicu untuk target seperti `https://simkopdes.go.id/.env`.

## Ringkasan

Modul `sensitive_files` menandai sebuah path sebagai "file sensitif ter-ekspos"
hanya berdasarkan **HTTP 200 + kecocokan nama path** (mis. path mengandung `.env`).
Pendekatan ini *content-blind*. Banyak aplikasi modern (Next.js App Router, Nuxt,
Remix, Angular) membalas **halaman HTML/SPA** untuk path apa pun (catch-all 200),
sehingga `GET /.env` mengembalikan beranda HTML — **tanpa isi `.env` sama sekali** —
namun tetap dilaporkan **KRITIS + `confirmed` (TERVALIDASI AKTIF)**.

### Evidence dari laporan keliru
- `GET /.env` → 200, body berupa HTML website (Next.js).
- Tidak ada isi `.env`, tidak ada kredensial bocor, tidak ada file sensitif nyata.
- Tetap dilaporkan `Risk Score 97/100`, `confirmed - TERVALIDASI AKTIF`.

## Akar masalah

1. **Severity & confidence ditentukan dari nama path**, bukan dari isi response.
   Path mengandung `.env`/`.git/` → otomatis `Severity.CRITICAL`.
2. **`looks_like_html_shell()` terlalu sempit** — hanya mengenali marker
   `<div id="__next">`, `<div id="root">`, `<noscript>`. Next.js App Router tidak
   selalu menulis marker tsb., sehingga halaman HTML lolos → `is_html_shell=False`
   → `confidence="confirmed"` → label "TERVALIDASI AKTIF".
3. **Control-diff lemah** — hanya aktif jika path random *juga* membalas 200.
   Jika server membalas 404 untuk path random tapi 200 untuk `/.env`, guard dilewati.

## Perbaikan (secure-by-design)

Mengikuti standar emas proyek (`git_repo_dump.py` yang mem-*parse* `.git/HEAD`),
modul kini **wajib membuktikan tanda-tangan konten** sebelum melaporkan:

1. **Catch-all guard** dipertahankan (bandingkan dengan path random).
2. **Validator konten per tipe file** (`_content_matches`):
   - `.env*` → ≥2 baris `KEY=VALUE` **dan bukan HTML**.
   - private key → blok `-----BEGIN ... PRIVATE KEY-----`.
   - `.git/*` → `ref: refs/` / 40-hex / `[core]`.
   - `.aws/credentials`, `.htpasswd`, dump SQL/arsip, `phpinfo`, panel admin,
     JSON/YAML/log, dll. — masing-masing punya signature.
3. **`looks_like_html_shell()` diperkuat**: mengenali `<!doctype html`, `<html`,
   marker hidrasi SPA (`/_next/`, `self.__next_f`, `__NUXT__`, `data-reactroot`,
   `ng-version`), serta heuristik ≥2 tag struktur HTML.
4. **Matriks keputusan baru:**
   - Konten cocok signature → severity penuh, `confirmed`.
   - Body HTML/SPA & tidak cocok → **DITOLAK** (tidak ada finding). ← perbaikan inti.
   - Non-HTML tapi tak dikenali → **INFO `tentative`** (verifikasi manual),
     tidak pernah CRITICAL-confirmed.
5. **File publik wajar** (`robots.txt`, `sitemap.xml`, `.well-known/security.txt`)
   tidak lagi dilaporkan sebagai sensitif (mengurangi noise).

## Pencegahan regresi

`tests/test_sensitive_files.py` (mandiri, hanya `http.server` stdlib):
- `test_spa_catchall_env_not_flagged` — SPA catch-all `/.env` tidak dilaporkan.
- `test_spa_catchall_no_confirmed_critical` — tidak ada CRITICAL+confirmed palsu.
- `test_env_returns_html_homepage_rejected` — `/.env` berisi HTML ditolak.
- `test_real_env_is_confirmed_critical` — `/.env` KEY=VALUE asli → CRITICAL confirmed.
- `test_real_private_key_confirmed` / `test_real_sql_dump_confirmed` — true-positive tetap terdeteksi.
- `test_robots_not_flagged` — file publik wajar tidak di-flag.

Semua test lama tetap lulus (21 passed, 1 skipped).
