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

### 2. Passive Vulnerability Checks
- Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- TLS/SSL audit (versi protokol, expiry sertifikat, weak ciphers, hostname mismatch)
- Cookie audit (Secure, HttpOnly, SameSite)
- CORS misconfiguration
- Clickjacking exposure
- HTTP method enumeration (TRACE, PUT, DELETE, OPTIONS)
- Sensitive file exposure (`.git/`, `.env`, `backup.zip`, `phpinfo.php`, dll.)

### 3. Active Vulnerability Checks
- SQL Injection (error-based & boolean-based, payload aman)
- Cross-Site Scripting (Reflected XSS)
- Open Redirect
- Local File Inclusion (LFI) / Path Traversal
- Command Injection (time-based & marker)
- Directory Listing exposure
- Inspeksi `robots.txt` & `sitemap.xml`

### 4. Attack Simulation (Safe Mode)
- Rate-limit & brute-force resistance test pada endpoint login
- Burst request test untuk melihat respons WAF / rate limiter
- *Tidak* melakukan DoS sungguhan: dibatasi durasi & jumlah request.

### 5. Pengecekan Tambahan (v0.2)
- **Crawler in-scope** — menyusuri link, form, parameter untuk fuzz lebih dalam
- **CSRF posture** (token form + SameSite cookie)
- **JWT inspection** (alg=none, missing exp, HMAC weak hint)
- **API discovery** (`/swagger.json`, `/openapi.json`, GraphQL introspection, `.well-known/`)
- **Subdomain takeover** (dangling CNAME → fingerprint provider)
- **Outdated JS libs** (jQuery, AngularJS, Bootstrap, lodash, Vue)
- **SSRF probe** (parameter URL-shaped)
- **SSTI probe** (Jinja/Twig/ERB/Velocity)
- **Mixed content + Subresource Integrity**
- **Form-aware fuzzing** untuk SQLi/XSS pada form yang ditemukan crawler

### 6. Reporting & Dashboard
- Output CLI berwarna (severity-coded) menggunakan `rich`
- Export JSON terstruktur (dengan risk_score, OWASP mapping)
- Export HTML report self-contained: dark/light theme, donut chart severity,
  filter & search, mode print/PDF
- **Web dashboard** (FastAPI + HTMX + Tailwind):
  - Manajemen target & history scan
  - Live progress per modul (HTMX polling)
  - Severity heatmap & risk score per target
  - Drill-down per finding dengan evidence + remediasi

---

## Instalasi

```bash
git clone https://github.com/xrniqbl/cyberloka.git
cd cyberloka
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -e '.[web]'             # tambahkan [web] untuk dashboard
```

Atau tanpa install (CLI saja):

```bash
pip install -r requirements.txt
python -m cyberloka --help
```

## Web Dashboard

```bash
cyberloka-web --host 127.0.0.1 --port 8765
```

Buka `http://127.0.0.1:8765` di browser. Fitur:

- Tambah target & jalankan scan dari UI
- Live progress per modul (status, current module, progress bar)
- Halaman scan detail dengan filter severity + search + drill-down per finding
- Halaman finding detail dengan evidence + remediasi + referensi
- API JSON (`/api/scans/{id}`, `/api/health`, `/api/docs`)

Database SQLite default disimpan di `~/.cyberloka/dashboard.db`.

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
