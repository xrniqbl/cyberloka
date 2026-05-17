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

## Quick Start (paling mudah)

```bash
pip install -e ".[all]"
cyberloka                  # buka menu interaktif - tinggal pilih
```

Menu memberi pilihan:
1. **Quick Scan** (passive, paling aman)
2. **Full Scan** (recon + passive + active, butuh izin)
3. **Verify** finding dari scan sebelumnya
4. **Buka Web Dashboard**
5. **Lihat laporan HTML terakhir**
6. **Setup login session** (untuk scan di balik authentication)

---

## Fitur

### 1. Reconnaissance
DNS, WHOIS, port scan, subdomain enumeration, technology fingerprinting.

### 2. Passive checks
Security headers (CSP/HSTS/XFO/etc), TLS audit, cookie flags, CORS,
clickjacking, HTTP methods, sensitive file exposure.

### 3. Active checks
SQL Injection, XSS, Open Redirect, LFI / Path Traversal, Command Injection,
Directory Listing, robots.txt / sitemap.xml inspection.

### 4. Authenticated session scanning *(baru)*
Scan halaman di balik login. Tiga metode auth didukung:
- **form** — POST credentials, capture cookie (default)
- **header** — kirim header statis (Bearer token, dll.) di setiap request
- **cookie** — pakai cookie session yang sudah ada (mis. di-export dari browser)

Optional: pre-fetch CSRF token, success/failure indicator, logout-URL avoidance.

```bash
# Buat config interaktif lewat menu (pilihan 6) atau tulis manual:
cat > login.json <<'EOF'
{
  "method": "form",
  "url": "https://app.example.com/login",
  "username": "alice",
  "password": "secret",
  "user_field": "email",
  "pass_field": "password",
  "success_indicator": "Welcome,",
  "csrf_url": "https://app.example.com/login",
  "csrf_field": "csrf_token",
  "logout_url": "https://app.example.com/logout"
}
EOF
chmod 600 login.json

cyberloka -t https://app.example.com --mode full --authorized \
          --login-config login.json --reports-dir reports
```

### 5. Attack simulation
Rate-limit & brute-force resistance test (login endpoint), burst test.
Tidak melakukan DoS sungguhan.

### 6. Risk Scoring & Executive Summary
- **Risk score CVSS-like (0.0 – 10.0)** per finding
- **Overall grade A+/A/B/C/D/F** (mirip SSL Labs), score 0–100
- **Executive Summary** untuk manajemen non-teknis: postur, distribusi risk,
  Top 5 prioritas perbaikan

### 7. Compliance Mapping
Setiap finding di-map ke OWASP Top 10 2021, PCI-DSS v4.0, ISO/IEC 27001:2022,
NIST CSF 2.0, CIS Controls v8, dan UU PDP Indonesia (UU 27/2022).

### 8. Verification — Deep Re-Test
Re-test finding pakai teknik berbeda dari deteksi awal untuk memisahkan
real-vuln dari false-positive. Hasil: `confirmed`/`firm`/`tentative`/`false_positive`,
plus PoC `curl` command yang reproducible.

```bash
# Mode A: scan + verify dalam satu run
cyberloka -t https://example.com --mode full --authorized --verify-after-scan

# Mode B: re-test bundle JSON dari scan sebelumnya
cyberloka --verify reports/example.com-20260101T120000Z.json --authorized
```

### 9. Threat Intelligence — Penjelasan Celah & Cara Hacker Eksploitasi *(baru)*
Setiap finding di laporan & dashboard sekarang dilengkapi block penjelasan:

- **Apa itu kelemahan ini?** — bahasa awam untuk non-teknis
- **Mengapa berbahaya?** — dampak kalau tidak diperbaiki
- **Skenario serangan** — cara hacker eksploitasi (3-5 contoh teknis)
- **Kill chain** — step-by-step urutan attacker
- **Dampak di dunia nyata** — contoh insiden besar (TalkTalk, Equifax, dll.)
- **Siapa yang biasa jadi korban** — profil target umum
- **MITRE ATT&CK** — mapping ke technique IDs (T1190, T1539, dll.)

Cocok untuk: laporan ke manajemen (mereka tahu "kenapa ini penting"),
training awareness (developer paham dampaknya), atau bukti audit (link
ke MITRE ATT&CK).

### 10. Module Execution Visibility *(baru)*
Setelah scan, sebuah tabel "Module Execution" menunjukkan setiap modul:
status (OK/ERROR/SKIPPED), berapa finding yang ditemukan, dan durasi.

Kalau hasil scan kelihatan sedikit, tabel ini menjelaskan **kenapa**:
- `OK + 0 findings` → modulnya jalan tapi target memang aman untuk
  kategori itu (good news!)
- `ERROR` → ada bug atau dependency missing — info di kolom Note
- `SKIPPED` → modul tidak terdaftar atau tidak dipanggil di mode tersebut

Lihat semua module dengan: `cyberloka --list-modules`.

### 11. Reporting (4 format)

| Format | Use case | Flag |
|--------|----------|------|
| **JSON** | CI pipeline, dashboard, scripting | `--json` |
| **HTML** | Print-to-PDF, sharing via browser | `--html` |
| **TXT** | Plain text untuk email/ticket/diff | `--txt` |
| **PDF** | Laporan formal ke management/audit | `--pdf` (butuh `pip install 'cyberloka[pdf]'`) |

`--reports-dir reports/` otomatis menulis JSON+HTML; tambah `--txt`/`--pdf`
untuk format ekstra (file akan diberi nama bertanggal otomatis).

### 12. Web Dashboard
- Flask web UI: history scan, trend grade per host, filter findings interaktif
- Compare dua scan side-by-side (resolved / new / unchanged)
- Filter: severity, module, full-text, status verifikasi, drill-down clause compliance
- API JSON di `/api/scans`, `/api/host/<host>/trend`, `/api/scan/<id>`

```bash
cyberloka-dashboard --reports-dir reports --open    # auto-buka browser
```

Atau dari hasil scan langsung:

```bash
cyberloka -t https://example.com --mode full --authorized \
          --reports-dir reports --open-dashboard
```

---

## Instalasi

```bash
git clone https://github.com/xrniqbl/cyberloka.git
cd cyberloka
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate

# pilih satu:
pip install -e .                    # core (JSON + HTML + TXT)
pip install -e ".[dashboard]"       # + Web Dashboard
pip install -e ".[pdf]"             # + PDF report
pip install -e ".[all]"             # semua fitur (rekomendasi)
```

## Penggunaan CLI

### Menu interaktif (paling mudah)
```bash
cyberloka                 # buka menu
cyberloka --menu          # eksplisit
```

### Scan dasar (passive)
```bash
cyberloka -t https://example.com --mode passive
```

### Scan penuh + verify + semua format laporan
```bash
cyberloka -t https://example.com --mode full --authorized \
          --reports-dir reports \
          --txt --pdf \
          --verify-after-scan \
          --open-dashboard
```

### Pilih modul tertentu
```bash
cyberloka -t https://example.com --modules headers,tls,xss,sqli
```

### Authenticated scan
```bash
cyberloka -t https://app.example.com --mode full --authorized \
          --login-config login.json --reports-dir reports
```

### Verify finding lama
```bash
cyberloka --verify reports/example.com-20260101T120000Z.json --authorized
```

### Buka Dashboard
```bash
cyberloka-dashboard --reports-dir reports --open
# Default port: 5005, atau --port 8080
```

### Opsi CLI (ringkas)

| Opsi | Deskripsi |
|------|-----------|
| `--menu` | Buka menu interaktif |
| `-t, --target` | URL/IP target |
| `--mode` | `passive`, `active`, `full` |
| `--modules` | Daftar modul (comma-separated) |
| `--authorized` | Konfirmasi izin men-scan |
| `--login-config FILE` | Path ke JSON config untuk authenticated session |
| `--json / --html / --txt / --pdf` | Format laporan output |
| `--reports-dir DIR` | Folder output otomatis bertanggal |
| `--open-dashboard` | Buka dashboard setelah scan selesai |
| `--verify FILE.json` | Re-test bundle dari scan sebelumnya |
| `--verify-after-scan` | Auto-verify setelah scan |
| `--no-compliance` | Sembunyikan tabel compliance di console |
| `--quiet` | Tekan log non-finding |
| `--yes` | Lewati prompt konfirmasi (untuk CI) |

---

## Login Config Format

```json
{
  "method": "form",
  "url": "https://example.com/login",
  "username": "alice",
  "password": "secret",
  "user_field": "username",
  "pass_field": "password",
  "extra_fields": { "remember": "1" },
  "success_indicator": "Welcome,",
  "failure_indicator": "Invalid credentials",
  "success_url_pattern": "/dashboard",
  "csrf_url": "https://example.com/login",
  "csrf_field": "csrf_token",
  "logout_url": "https://example.com/logout"
}
```

Untuk Bearer token / API:
```json
{
  "method": "header",
  "headers": { "Authorization": "Bearer eyJhbGc..." }
}
```

Untuk session cookie yang sudah ada:
```json
{
  "method": "cookie",
  "cookies": { "session": "abc123", "csrf": "xyz" }
}
```

> **Tip:** simpan dengan `chmod 600 login.json` agar credential tidak terbaca user lain.

---

## Severity & Risk Score

| Severity | Score band | Grade impact | Arti |
|----------|-----------|--------------|------|
| `critical` | 9.0 – 10.0 | -35 / finding | Eksploitasi mudah, dampak besar — segera perbaiki |
| `high`     | 7.0 – 8.9  | -18 / finding | Risiko tinggi, perbaiki dalam waktu dekat |
| `medium`   | 4.0 – 6.9  | -7  / finding | Penting, perbaiki saat siklus rilis berikutnya |
| `low`      | 0.1 – 3.9  | -2  / finding | Best-practice / hardening |
| `info`     | 0.0        | none          | Informasi (tidak selalu kerentanan) |

## Lisensi

MIT — lihat [LICENSE](LICENSE).
