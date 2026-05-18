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



## Quick launcher Windows (`cek.bat`)

Untuk pengguna Windows tersedia menu interaktif `cek.bat`:

```
1. Scan PASSIVE
2. Scan ACTIVE
3. Scan FULL
4. Scan modul tertentu
5. Recon saja
6. Subdomain takeover check
7. Simulate attack
8. Update repo (git pull)
9. Tampilkan daftar modul
0. Keluar
```

Jalankan dari root folder repo:

```bat
cek.bat
```

Pilih `8` untuk menarik update terbaru dari remote (`git fetch --prune` + `git pull --ff-only`).
