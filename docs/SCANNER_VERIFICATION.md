# Panduan Penulisan Modul Scanner — *Verification-First*

> Tujuan dokumen ini: setiap modul scanner Cyberloka **membuktikan** sebuah celah,
> bukan **menebak**. Sebuah temuan hanya layak dilaporkan kalau bisa dipertahankan
> di depan pemilik aplikasi — "ini buktinya, ini cara reproduksinya" — bukan
> "kemungkinan ada karena polanya mirip".

Dua prinsip inti, dan kapan memakainya:

1. **Verification-first** — untuk modul *aktif* (injeksi): buktikan input benar-benar dieksekusi.
2. **Negative baseline** — untuk modul *cek-keberadaan* (file/endpoint): buktikan resource benar-benar ada & unik, bukan halaman fallback.

---

## 1. Akar penyebab false positive

Dua pola yang menghasilkan hampir semua false positive di scanner web:

| Pola keliru | Contoh nyata | Kenapa salah |
|---|---|---|
| **Pencocokan pola di satu respons** | cmdi cari string `cyberlokaCMD` yang ada di payload-nya sendiri | Aplikasi yang sekadar **memantulkan input** memicu match tanpa eksekusi |
| **`HTTP 200` = ada/terekspos** | `/.env` → 200 + ada karakter `=` → "env bocor" | SPA / catch-all mengembalikan `index.html` 200 untuk **path apa pun** |
| **Satu sampel sinyal lemah** | time-based 1 request, ambang longgar | Jitter jaringan / halaman lambat ikut lolos |
| **Beda ukuran/teks tanpa kontrol** | boolean SQLi beda panjang > 200 byte | Konten dinamis (iklan, token, jam) berubah secara alami |

Aturan emas: **sebuah respons tidak membuktikan apa pun sampai dibandingkan dengan sesuatu.**

---

## 2. Verification-first (modul aktif / injeksi)

Sebelum melaporkan, susun perbandingan **diferensial**: baseline + payload + kontrol.
Lapor hanya bila ketiganya berperilaku sesuai hipotesis injeksi, lalu set
`confidence="confirmed"`.

| Kelas | Bukti yang sah (bukan tebakan) |
|---|---|
| **Command injection** | Marker **aritmatika** `$((A+B))` — respons memuat HASIL (mis. `CLK1379291END`), bukan teks payload. Mustahil dari refleksi. Blind: *time-based diferensial* — delay berskala linear dengan `sleep N` vs `sleep 2N`, dikonfirmasi 2×. |
| **SQLi error-based** | Baseline bersih → petik tunggal **memunculkan** error → kontrol tanpa-quote **tetap bersih**. Pola muncul→hilang membuktikan quote memecah konteks SQL. |
| **SQLi boolean-based** | `1=1` ≈ baseline DAN `1=2` berbeda nyata, di ≥1 konteks (numerik & string). |
| **Reflected XSS** | Karakter pemecah markup dipantulkan **MENTAH** (tidak di-encode) DAN di konteks yang **dieksekusi** (bukan `<textarea>`/komentar/`<title>`). |
| **LFI / Path Traversal** | ≥2 baris berformat `user:x:uid:gid:` dari `/etc/passwd` (atau signature `win.ini`) yang **TIDAK ada di baseline**. |
| **Open Redirect** | Server benar-benar balas **3xx** ke host attacker (uji absolut & protocol-relative `//host`). |

Helper bersama: `cyberloka/active/_helpers.py` → `fetch`, `similarity`,
`replace_param`, `baseline_timing`, `param_names`, `get_param_value`.

---

## 3. Negative baseline (modul cek-keberualan file/endpoint)

Gunakan `cyberloka/core/probe.py`. **Jangan pernah** percaya `HTTP 200` langsung.

```python
from cyberloka.core import probe

# Hanya kembalikan response bila: status OK, BUKAN catch-all/soft-404,
# DAN lolos validator konten spesifik tipe.
r = probe.verify_real(client, target, url, validator=lambda ctype, body: probe.is_dotenv(body))
if r is None:
    return  # SPA fallback / soft-404 / konten tak cocok → bukan temuan
```

Cara kerja `verify_real`:
1. Fetch `url`; buang bila status ≥ 400.
2. Bandingkan dengan **negative baseline** — 2 path acak yang pasti tak ada + homepage. Jika status & body mirip path-ngawur/homepage → **catch-all**, di-skip.
3. Jalankan **validator konten** (opsional) untuk tipe resource itu.

Validator yang tersedia:

| Validator | Untuk |
|---|---|
| `is_dotenv(body)` | File `.env` (≥2 baris `KEY=VALUE`, bukan HTML) |
| `is_json_doc(ctype, body)` | Spec OpenAPI/Swagger, manifest, endpoint JSON |
| `is_xml_doc(ctype, body)` | Listing S3, sitemap, manifest Joomla |
| `is_binaryish(ctype)` | heapdump, dump biner |
| `looks_like_html(body)` | Tolak fallback HTML untuk path file non-HTML |
| `body_has(body, marker)` | Marker teks khas (mis. `phpMyAdmin`, `Werkzeug`) |

Pakai `probe.negative_baseline(client, target)` langsung kalau perlu beberapa
pengecekan dalam satu modul (hasilnya di-cache per origin).

---

## 4. Checklist sebelum menambah / mengubah modul

- [ ] Apakah temuan ini bisa muncul dari **refleksi input** atau **halaman fallback**? Kalau ya, tambahkan kontrol/baseline.
- [ ] Apakah ada **negative baseline** atau **respons kontrol** yang dibandingkan?
- [ ] Untuk time-based: apakah diukur terhadap baseline DAN dikonfirmasi ulang (anti-jitter)?
- [ ] Untuk cek-keberadaan: apakah lewat `probe.verify_real` dengan validator konten yang tepat?
- [ ] Apakah `confidence` mencerminkan kenyataan? `confirmed` HANYA bila terverifikasi diferensial.
- [ ] Apakah ada test yang memasangkan **kasus AMAN/reflektif (harus 0 temuan)** vs **kasus benar-benar rentan (harus terdeteksi)**?

## 5. Pola test wajib

Setiap modul deteksi harus punya test bermatriks: endpoint aman + endpoint rentan.
Contoh acuan:

- `tests/test_verification.py` — matriks injeksi (aman vs rentan untuk 6 modul).
- `tests/test_softnotfound.py` — SPA catch-all (0 temuan) vs file asli terekspos (terdeteksi).

Sebuah modul dianggap "pintar" hanya jika lulus **kedua** sisi: tidak menandai yang
aman, dan tetap menangkap yang nyata.
