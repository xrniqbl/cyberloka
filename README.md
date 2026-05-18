# Cyberloka

**Cyberloka** adalah toolkit *web vulnerability scanner* berbasis Python yang dirancang untuk
membantu pemilik website / pentester yang sah mengidentifikasi celah keamanan, menjelaskan
penyebabnya, serta memberikan rekomendasi perbaikan.

> ⚠️ **PENTING — ETIKA & LEGALITAS**
>
> Cyberloka HANYA boleh digunakan terhadap target yang **Anda miliki sendiri** atau yang
> telah memberikan **izin tertulis (authorization)** kepada Anda. Penggunaan tanpa izin
> dapat melanggar UU ITE (Indonesia), Computer Fraud and Abuse Act (USA), atau hukum
> setara di yurisdiksi lain. Tanggung jawab penggunaan sepenuhnya ada di tangan pengguna.

---

## Fitur

### 1. Reconnaissance (Pengumpulan Informasi)
- Resolusi DNS (A, AAAA, MX, NS, TXT, CNAME, SOA)
- WHOIS lookup
- Port scanning (top common ports, TCP connect)
- Subdomain enumeration (wordlist-based)
- Technology fingerprinting (server, framework, CMS) dari header & body
- **WAF / CDN detection** (Cloudflare, Akamai, Imperva, AWS, F5, Fastly, ModSecurity, dll.)
- **Subdomain takeover** check (CNAME dangling ke S3/Heroku/GitHub Pages/Azure/Netlify, dst.)

### 2. Passive Vulnerability Checks
- Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- TLS/SSL audit (versi protokol, expiry sertifikat, weak ciphers, hostname mismatch)
- Cookie audit (Secure, HttpOnly, SameSite)
- CORS misconfiguration
- Clickjacking exposure
- HTTP method enumeration (TRACE, PUT, DELETE, OPTIONS)
- Sensitive file exposure (`.git/`, `.env`, `backup.zip`, `phpinfo.php`, dll.)
- **API discovery** (Swagger/OpenAPI/Spring Actuator/Tomcat manager/H2 console/pprof/metrics)
- **GraphQL** endpoint detection + introspection check
- **CSRF** form audit (POST tanpa token anti-CSRF)
- **JWT audit** (`alg=none`, expired, weak HMAC)
- **Secret scanning** di body & JS (AWS/Google/Stripe/GitHub/Slack/PEM/JDBC/Mongo URI)
- **Mixed content** (HTTPS halaman me-load HTTP resource)
- **Information disclosure** (HTML comment sensitif, stack trace, debug page)
- **Cache audit** untuk halaman terotentikasi (`Cache-Control` permisif)

### 3. Active Vulnerability Checks
- SQL Injection (error-based & boolean-based, payload aman)
- Cross-Site Scripting (Reflected XSS)
- Open Redirect
- Local File Inclusion (LFI) / Path Traversal
- Command Injection (time-based & marker)
- Directory Listing exposure
- Inspeksi `robots.txt` & `sitemap.xml`
- **Host Header Injection** / cache poisoning probe
- **SSRF** probe (parameter URL/callback/webhook, safe non-destructive)

### 4. Attack Simulation (Safe Mode)
- Rate-limit & brute-force resistance test pada endpoint login
- Burst request test untuk melihat respons WAF / rate limiter
- *Tidak* melakukan DoS sungguhan: dibatasi durasi & jumlah request.

### 5. Reporting
- Output CLI berwarna (severity-coded) menggunakan `rich`
- Export JSON terstruktur
- Export HTML report (rapi, lengkap dengan remediasi per finding)
- **Export PDF report (Bahasa Indonesia, otomatis dinamai sesuai host target)** — berisi
  cover page, ringkasan eksekutif, grafik distribusi severity, **flowchart alur serangan**,
  bagian khusus *"Akses Yang Dapat / Berhasil Ditembus"*, **daftar Link Bug & endpoint
  bermasalah** (clickable), detail per-finding (Apa Celahnya / Bagaimana Hacker
  Membobolnya / Dampak Bisnis / Bukti / Link Bug / Cara Reproduksi Manual / Cara
  Menanggulangi / Referensi), pemetaan **OWASP Top 10 2021** & **MITRE ATT&CK**,
  glossary istilah, serta roadmap hardening.

---

## Instalasi

```bash
git clone https://github.com/xrniqbl/cyberloka.git
cd cyberloka
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -e .
```

Atau tanpa install:

```bash
pip install -r requirements.txt
python -m cyberloka --help
```

## Penggunaan

### Scan dasar (passive only — paling aman)
```bash
cyberloka -t https://example.com --mode passive
```

### Scan penuh (recon + passive + active)
```bash
cyberloka -t https://example.com --mode full --authorized
```

### Pilih modul tertentu
```bash
cyberloka -t https://example.com --modules headers,tls,xss,sqli
```

### Simpan laporan
```bash
cyberloka -t https://example.com --mode full --authorized \
          --json report.json --html report.html
```

### PDF report (default ON, otomatis dinamai sesuai host target)
PDF dihasilkan otomatis tanpa flag tambahan. File disimpan dengan format
`cyberloka-report-<host>-<YYYYMMDD-HHMMSS>.pdf`:

```bash
# Auto-naming, tersimpan di working directory:
cyberloka -t https://example.com --mode full --authorized

# Auto-naming ke folder tertentu:
cyberloka -t https://example.com --mode full --authorized --report-dir ./reports

# Override path PDF secara eksplisit:
cyberloka -t https://example.com --mode full --authorized --pdf laporan.pdf

# Matikan PDF:
cyberloka -t https://example.com --no-pdf
```

Isi PDF (Bahasa Indonesia):
- Cover page (target, mode, timestamp, total finding, severity tertinggi).
- Bab 1: Ringkasan Eksekutif + grafik distribusi severity + 5 temuan paling krusial.
- Bab 2: **Flowchart alur serangan** (Recon -> Probe -> Exploit -> Post-Exploit -> Impact).
- Bab 3: **Akses Yang Dapat / Berhasil Ditembus** — daftar akses (mis. database via SQLi,
  source code via `.git/`, account takeover via host header) lengkap dengan endpoint
  yang ter-tested.
- Bab 4: Detail per-finding lengkap dengan:
  - **Apa Celahnya** (akar masalah teknis)
  - **Bagaimana Hacker Membobolnya** (skenario eksploitasi)
  - **Dampak Bisnis** (bukan hanya teknis - kerugian operasional / regulasi)
  - **Bukti / Evidence** dari hasil scan
  - **Link Bug / Endpoint Terkait** (clickable; tim dev langsung bisa verifikasi)
  - **Cara Reproduksi (Manual)** - perintah `curl`/`dig`/`openssl` siap copy-paste,
    dengan placeholder URL otomatis terisi
  - **Cara Menanggulangi** (langkah perbaikan konkret)
  - **Referensi** (OWASP cheat sheet, dokumentasi vendor)
  - Meta: CWE, OWASP Top 10 2021, MITRE ATT&CK, Bug ID (jika ada)
- Bab 5: Roadmap hardening berdasar prioritas severity.
- **Bab 6: Daftar Link Bug & Endpoint Bermasalah** - tabel ringkas seluruh URL
  vulnerable di satu halaman, urut severity. Cocok dishare ke tim dev/QA.
- Lampiran A: Modul yang dijalankan.
- Lampiran B: **Glossary** istilah keamanan (CSP, HSTS, SSRF, BOLA, dll.).
- Lampiran C: **Pemetaan OWASP Top 10 & MITRE ATT&CK** per modul (untuk integrasi
  ke kerangka risiko enterprise / ISO 27001 / NIST 800-53).

### Attack simulation (butuh konfirmasi)
```bash
cyberloka -t https://example.com --simulate-attack \
          --login-url https://example.com/login \
          --authorized
```

### Opsi CLI (ringkas)

| Opsi | Deskripsi |
|------|-----------|
| `-t, --target` | URL atau IP target (wajib) |
| `--mode` | `passive`, `active`, `full` (default: `passive`) |
| `--modules` | Daftar modul (comma-separated) |
| `--authorized` | Konfirmasi bahwa Anda berwenang men-scan target |
| `--threads` | Jumlah worker untuk modul paralel |
| `--timeout` | Timeout HTTP per request (detik) |
| `--rate` | Maks request per detik |
| `--user-agent` | UA custom |
| `--cookies` | Cookies tambahan (`k=v;k2=v2`) |
| `--json` | Path output JSON |
| `--html` | Path output HTML |
| `--pdf` | Path output PDF (kosong = auto-naming `cyberloka-report-<host>-<ts>.pdf`) |
| `--no-pdf` | Matikan generate PDF (default: aktif) |
| `--report-dir` | Folder output untuk auto-named PDF (default: working dir) |
| `--quiet` | Tekan log non-finding |

---

## Struktur Project

```
cyberloka/
├── cyberloka/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── core/                   # config, http client, model, logger, util
│   ├── recon/                  # dns, whois, ports, subdomain, fingerprint
│   ├── passive/                # headers, tls, cookies, cors, methods, files
│   ├── active/                 # sqli, xss, redirect, lfi, cmdi, dirlist
│   ├── simulate/               # rate_limit, burst
│   └── reporting/              # console, json_report, html_report
├── data/
│   ├── subdomains.txt
│   ├── sensitive_paths.txt
│   └── common_passwords.txt
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Severity

| Level | Warna | Arti |
|-------|-------|------|
| `critical` | merah | Segera perbaiki — eksploitasi mudah, dampak besar |
| `high`     | merah muda | Risiko tinggi, perlu perbaikan dalam waktu dekat |
| `medium`   | kuning | Penting, perbaiki saat siklus rilis berikutnya |
| `low`      | biru | Best-practice / hardening |
| `info`     | abu-abu | Informasi (tidak selalu kerentanan) |

## Lisensi

MIT — lihat [LICENSE](LICENSE).



## Quick launcher Windows (`cek.bat`)

Untuk pengguna Windows tersedia menu interaktif `cek.bat` (versi v0.9.0):

```
APA YANG MAU DICOBA?  (pilih nomor)
----------------------------------------------------------------------
   1. Buka menu interaktif Cyberloka     [RECOMMENDED]
   2. Quick Scan         - passive, paling aman
   3. Full Scan          - recon + passive + active, butuh izin
   4. Buka folder laporan
   5. Lihat laporan PDF terakhir
   6. Tampilkan --help
   7. Daftar semua module deteksi
   8. Update Cyberloka (git pull + pip install)
   0. Keluar
```

Jalankan dari root folder repo:

```bat
cek.bat
```

### Cara Update Cyberloka (PENTING)

> Jika menu `cek.bat` Anda tidak sama dengan dokumentasi (mis. masih menampilkan
> menu lama), itu berarti file lokal Anda **belum di-pull** dari GitHub. Update
> dengan salah satu cara berikut:

**Cara 1 (paling mudah):** Buka `cek.bat` lalu pilih **8** (Update).
Script akan otomatis:
1. `git fetch --all --prune`
2. `git pull --ff-only` (auto-stash perubahan lokal jika ada)
3. `pip install -r requirements.txt` + `pip install -e .`

**Cara 2 (shortcut):** Double-click **`update.bat`** di root folder. Sama
dengan menu nomor 8 tetapi langsung jalan tanpa lewat menu.

**Cara 3 (manual via terminal):**
```bat
cd path\to\cyberloka
git pull
pip install -r requirements.txt
pip install -e .
```

### Auto-check update saat startup

Setiap kali `cek.bat` dijalankan, ia melakukan `git fetch` lalu menghitung
berapa commit yang tertinggal dari `origin`. Jika ada update tersedia, Anda
akan diminta konfirmasi (Y/N) untuk update sebelum menu utama tampil.
