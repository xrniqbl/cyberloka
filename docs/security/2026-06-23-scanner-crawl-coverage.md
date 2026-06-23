# Scanner injeksi: uji SELURUH permukaan hasil crawl, bukan hanya `base_url`

- **Tanggal:** 2026-06-23
- **Modul terdampak:** `cyberloka/active/_helpers.py`, `sqli.py`, `xss.py`,
  `lfi.py`, `cmdi.py`, `ssti.py`, `redirect.py`, `csti_template.py`, `forms.py`
- **Versi:** v0.10.7

## Pertanyaan yang dijawab
"Buat semua scanner lebih pintar mencari celah pada suatu website, dan mencari
yang benar-benar celah, bukan hanya prediksi."

## Akar masalah (coverage gap)
Tujuh scanner injeksi inti — `sqli`, `xss`, `lfi`, `cmdi`, `ssti`, `redirect`,
`csti_template` — **hanya menguji `target.base_url`** dengan satu parameter
sintetis (mis. `?id=1`, `?q=test`). Crawler (`recon/crawler.py`) sebenarnya
sudah menemukan `param_urls` dan `forms` nyata dan menyimpannya di
`CrawlState`, tetapi tujuh scanner ini **tidak pernah membacanya**.

Akibatnya, di website nyata yang punya banyak endpoint berparameter
(`/cari?q=`, `/produk?id=`, `/profil?user=`, `/view?file=`), scanner praktis
tidak menyentuh permukaan serang yang sebenarnya. Logika validasi tiap modul
sangat kuat (double-confirm, control-fetch, oracle acak) — tapi tidak ada
gunanya kalau tidak pernah mencapai parameter yang rentan.

Bukti empiris (lab in-process, 3 endpoint rentan yang hanya bisa ditemukan via
crawling):

| Scanner | Sebelum (hanya base_url) | Sesudah (konsumsi crawler) |
|---------|--------------------------|----------------------------|
| sqli    | 0                        | 1 CRITICAL `/item?id=`     |
| xss     | 0                        | 3 HIGH (`q`,`id`,`file`)   |
| lfi     | 0                        | 1 CRITICAL `/view?file=`   |

## Perbaikan (secure-by-design)

### 1. Smart targeting engine (`active/_helpers.py`)
- `candidate_urls(target, config, fallback_param=…)` — menggabungkan `base_url`
  dengan **seluruh** `param_urls` hasil crawler, dedup berbasis **bentuk URL**
  (scheme+host+path+set nama parameter) supaya endpoint serupa
  (`/produk?id=1` vs `/produk?id=2`) hanya diuji sekali, lalu dibatasi `limit`
  agar scan tetap cepat.
- `candidate_forms`, `form_fuzz_fields`, `build_form_data`, `submit_form` —
  utilitas form untuk fuzzing field POST/GET dengan nilai benign pada field
  lain (termasuk hidden/csrf) agar request tidak ditolak.

### 2. Refactor tujuh scanner
Setiap scanner di-extract menjadi fungsi `_scan_url(client, url, …)` (logika
per-URL **identik** dengan sebelumnya — semua guard false-positive tetap utuh),
lalu `run()` me-loop atas `candidate_urls(...)`. `redirect` memakai
`fallback_param=None` karena open-redirect hanya relevan pada parameter nyata.
Hasil di-dedup lintas-URL berbasis path agar laporan tidak ganda.

### 3. `csti_template` — oracle diperkuat
Oracle lama `{{7*7}}→49` mudah muncul kebetulan (49/64 angka umum). Diganti
oracle **aritmetika acak** (produk dua bilangan 113..9973 → 4-7 digit) plus
**baseline guard**: bila marker sudah ada di halaman dasar, oracle dibatalkan.

### 4. `forms.py` — dari heuristik ke terverifikasi
Versi lama: lapor XSS dari sekadar payload terpantul, SQLi dari sekadar kata
"error SQL" — tanpa control/double-confirm (sumber false-positive). Sekarang:
- **XSS form:** baseline-reflektif → raw reflection di konteks eksekutif →
  double-confirm token berbeda → anti-echo.
- **SQLi form:** control benign **bersih** dari signature DB-error → payload
  quote memunculkan signature. Hanya laporkan bila kedua syarat terpenuhi.

## Prinsip yang dijaga
Cakupan deteksi naik drastis **tanpa** menurunkan kualitas validasi: tiap titik
suntik tetap melewati guard yang sama (soft-404, control-fetch, double-confirm,
oracle unik). "Lebih pintar mencari celah" + "hanya celah nyata, bukan prediksi"
tercapai bersamaan.

## Pencegahan regresi
`tests/test_injection_coverage.py` menjalankan server rentan in-process dengan
endpoint yang **hanya** bisa ditemukan via crawling (`/search?q=`, `/item?id=`,
`/view?file=`) plus form POST `/comment`, lalu memastikan crawler menemukannya
dan `sqli`/`xss`/`lfi`/`forms` melaporkan temuan terkonfirmasi. Bila ada yang
mengembalikan scanner ke "hanya base_url", test ini gagal.
