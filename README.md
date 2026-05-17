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

### 1. Reconnaissance
- Resolusi DNS (A, AAAA, MX, NS, TXT, CNAME, SOA) + cek SPF/DMARC
- WHOIS lookup
- Port scanning (top common ports, TCP connect)
- Subdomain enumeration (wordlist-based)
- Technology fingerprinting (server, framework, CMS) dari header & body
- **Crawler / Spider** in-scope untuk auto-discover endpoint, form, JS file, dan parameter
- **OpenAPI/Swagger importer** — auto-discover spec di `/openapi.json`, `/swagger.json`, dll. dan import endpoint sebagai target tambahan

### 2. Passive Vulnerability Checks
- Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- TLS/SSL audit (versi protokol, expiry sertifikat, weak ciphers, hostname mismatch)
- Cookie audit (Secure, HttpOnly, SameSite)
- CORS misconfiguration
- Clickjacking exposure
- HTTP method enumeration (TRACE, PUT, DELETE, OPTIONS)
- Sensitive file exposure (`.git/`, `.env`, `backup.zip`, `phpinfo.php`, dll.)
- robots.txt / sitemap.xml inspection
- **CSRF audit** — form state-changing tanpa anti-CSRF token (memakai data crawler)

### 3. Active Vulnerability Checks
- SQL Injection (error-based & boolean-based)
- Cross-Site Scripting (Reflected XSS)
- Open Redirect
- Local File Inclusion (LFI) / Path Traversal
- Command Injection (time-based & marker)
- Directory Listing exposure
- **Server-Side Request Forgery (SSRF)** — termasuk deteksi cloud metadata (AWS IMDS, GCP, Azure)
- **JWT auditor** — alg=none, weak HMAC secret (offline dictionary), expiry, kid/jku/jwk attacks
- **XXE** (XML External Entity) — read-only, file:// signature
- **SSTI** (Server-Side Template Injection) — Jinja2/Twig/Freemarker/Velocity/ERB
- **NoSQL Injection** (MongoDB) — operator probe + JSON body
- **GraphQL audit** — introspection, batching, alias overload, GET-method
- **WebSocket scanner** — handshake, cross-origin, ws:// vs wss://, token in URL

### 4. Authenticated Scan
- Form login dengan **CSRF token auto-extract**
- Bearer token (`--auth-method bearer --auth-token ...`)
- Cookies/headers manual (`--cookies`, `--header`)
- Marker validation (success/failure regex)

### 5. Attack Simulation (Safe Mode)
- Rate-limit & brute-force resistance test pada endpoint login
- Burst request test untuk melihat respons WAF / rate limiter
- *Tidak* melakukan DoS sungguhan: dibatasi durasi & jumlah request.

### 6. Reporting
- Output CLI berwarna (severity-coded) menggunakan `rich`
- Export JSON terstruktur
- Export HTML report (rapi, lengkap dengan remediasi per finding)
- **Diff scan** — bandingkan dua report JSON untuk track regresi:
  ```bash
  cyberloka diff old.json new.json --json diff.json --fail-on-new
  ```

### 7. Test Lab
- Direktori [`lab/`](lab/README.md) berisi `docker-compose.yml` dengan
  Juice Shop, DVWA, bWAPP, dan VAmPI untuk berlatih scan secara legal.

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

### Crawler + scan aktif
```bash
cyberloka -t https://example.com --mode active --authorized --crawl
```

### Scan penuh (recon + crawler + passive + active)
```bash
cyberloka -t https://example.com --mode full --authorized \
          --json report.json --html report.html
```

### Authenticated scan (form login)
```bash
cyberloka -t https://example.com --mode active --authorized \
          --auth-method form \
          --auth-login-url https://example.com/login \
          --auth-user admin --auth-pass 'secret' \
          --auth-success-marker "Welcome|Dashboard" \
          --crawl
```

### Authenticated scan (bearer token / API)
```bash
cyberloka -t https://api.example.com --mode active --authorized \
          --auth-method bearer --auth-token "$TOKEN" \
          --modules crawler,jwt,ssrf,headers,cors,cookies
```

### Pilih modul tertentu
```bash
cyberloka -t https://example.com --modules headers,tls,xss,sqli,jwt,ssrf
```

### Attack simulation
```bash
cyberloka -t https://example.com --simulate-attack \
          --login-url https://example.com/login \
          --authorized
```

### Lihat semua opsi
```bash
cyberloka --help
```

---

## Struktur Project

```
cyberloka/
├── cyberloka/
│   ├── core/           # config, http client, model, logger, util, auth
│   ├── recon/          # dns, whois, ports, subdomain, fingerprint, crawler
│   ├── passive/        # headers, tls, cookies, cors, methods, files, robots
│   ├── active/         # sqli, xss, redirect, lfi, cmdi, dirlist, ssrf, jwt
│   ├── simulate/       # rate_limit, burst
│   ├── reporting/      # console, json, html
│   ├── cli.py
│   └── scanner.py
├── data/               # subdomains.txt, sensitive_paths.txt, common_passwords.txt
├── lab/                # docker-compose.yml + README — vulnerable apps untuk testing
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
