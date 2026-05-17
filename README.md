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

### 5. Reporting
- Output CLI berwarna (severity-coded) menggunakan `rich`
- **Risk score CVSS-like (0.0-10.0)** per finding + **overall grade A+/A/B/C/D/F**
- **Executive Summary** satu halaman: postur, distribusi risk, dan **Top 5 prioritas** perbaikan
- **Compliance mapping** otomatis ke OWASP Top 10 2021, PCI-DSS v4.0, ISO/IEC 27001:2022, NIST CSF 2.0, CIS Controls v8, dan UU PDP Indonesia (UU 27/2022)
- Export JSON terstruktur (lengkap dengan score + compliance) dan HTML responsive (mobile + print/PDF)

### 6. Web Dashboard
- Flask web UI untuk melihat history scan, trend grade per host, dan filter findings
- Compare dua scan side-by-side (resolved / new / unchanged)
- Filter interaktif: severity, module, full-text search, klik clause compliance untuk drill-down
- API JSON sederhana di `/api/scans`, `/api/host/<host>/trend`, `/api/scan/<id>`

---

## Instalasi

```bash
git clone https://github.com/xrniqbl/cyberloka.git
cd cyberloka
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -e .                    # core scanner + reporters
pip install -e ".[dashboard]"       # tambah web dashboard (Flask)
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

### Simpan ke folder reports/ (otomatis untuk dashboard)
```bash
cyberloka -t https://example.com --mode full --authorized \
          --reports-dir reports
# menulis reports/example.com-20260101T120000Z.json + .html
```

### Jalankan Web Dashboard
```bash
pip install -e ".[dashboard]"
cyberloka-dashboard --reports-dir reports
# buka http://127.0.0.1:5005
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
| `--reports-dir` | Folder output: tulis JSON+HTML otomatis (kompatibel dashboard) |
| `--no-compliance` | Sembunyikan tabel compliance di console |
| `--quiet` | Tekan log non-finding |

---

## Struktur Project

```
cyberloka/
├── cyberloka/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── core/                   # config, http client, model, logger, util,
│   │                            # risk scoring, compliance mapping, bundle builder
│   ├── recon/                  # dns, whois, ports, subdomain, fingerprint
│   ├── passive/                # headers, tls, cookies, cors, methods, files
│   ├── active/                 # sqli, xss, redirect, lfi, cmdi, dirlist
│   ├── simulate/               # rate_limit, burst
│   ├── reporting/              # console, json_report, html_report (+ template)
│   └── dashboard/              # Flask web UI (+ templates, static, helpers)
├── data/
│   ├── subdomains.txt
│   ├── sensitive_paths.txt
│   └── common_passwords.txt
├── scripts/
│   └── smoke_test.py           # offline test untuk risk + compliance + reporting
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Severity & Risk Score

| Level | Warna | Risk Score | Arti |
|-------|-------|------------|------|
| `critical` | merah        | 9.0 - 10.0 | Segera perbaiki - eksploitasi mudah, dampak besar |
| `high`     | merah muda   | 7.0 - 8.9  | Risiko tinggi, perlu perbaikan dalam waktu dekat |
| `medium`   | kuning       | 4.0 - 6.9  | Penting, perbaiki saat siklus rilis berikutnya |
| `low`      | biru         | 0.1 - 3.9  | Best-practice / hardening |
| `info`     | abu-abu      | 0.0        | Informasi (tidak selalu kerentanan) |

### Overall Grade

Score 0-100 (dengan diminishing-returns penalty per severity) dipetakan ke huruf
mirip SSL Labs:

| Score    | Grade | Label     |
|----------|:-----:|-----------|
| 95 - 100 | A+    | Excellent |
| 85 - 94  | A     | Strong    |
| 75 - 84  | B     | Good      |
| 60 - 74  | C     | Adequate  |
| 40 - 59  | D     | Weak      |
| 0 - 39   | F     | Failing   |

## Compliance Mapping

Setiap finding di-map otomatis ke clause dari standar berikut (rule book ada di
`cyberloka/core/compliance.py`):

- **OWASP Top 10 2021** (A01-A10)
- **PCI-DSS v4.0** (requirement IDs)
- **ISO/IEC 27001:2022** (Annex A controls)
- **NIST Cybersecurity Framework 2.0** (Function.Category)
- **CIS Controls v8** (control IDs)
- **UU PDP Indonesia** (UU 27/2022) - pasal yang relevan

Mapping muncul di console, JSON, HTML report, dan dashboard. Anda bisa drill-down
finding berdasarkan clause langsung dari halaman scan di dashboard.

## Lisensi

MIT — lihat [LICENSE](LICENSE).
