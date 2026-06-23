# Audit lintas-modul: pola false-positive "HTTP 200 / refleksi tanpa bukti"

- **Tanggal:** 2026-06-23
- **Versi:** v0.10.6
- **Pemicu:** Setelah `sensitive_files` (`/.env`) dan `auth_bypass` (`/administrator`)
  terbukti melaporkan false-positive dari `HTTP 200` + nama-path/keyword generik,
  dilakukan audit menyeluruh ke **131 modul** scanner untuk pola yang sama.

## Metodologi

Skrip audit menandai modul yang (a) menerbitkan finding `confirmed`/`firm`,
(b) memutuskan dari `status_code == 200` atau substring keyword, dan (c) TANPA
kontrol-negatif/soft-404 guard. 25 modul ter-flag, lalu **ditinjau manual**.

## Hasil klasifikasi

### AMAN — sudah memakai signature unik / bukti eksekusi (tidak diubah)
Modul ini mustahil dipicu beranda SPA generik karena menuntut bukti spesifik:

| Modul | Bukti yang diwajibkan |
|---|---|
| `git_repo_dump` | `.git/HEAD` regex + `[core]` + DIRC binary |
| `spring_actuator_rce` | JSON `propertySources`/HPROF biner ter-anchor |
| `elasticsearch_unauth` | JSON `name`+`version.number` |
| `kibana_unauth` | JSON `/api/status` `name`/`status`/`version` |
| `grafana_default` / `grafana_default_login` | `/api/health` JSON + cookie sesi |
| `apache_path_confusion` / `nginx_off_by_slash` | `root:x:0:0:` (isi /etc/passwd) |
| `phpunit_rce` | marker echo ter-inject (bukti RCE) |
| `prometheus_unauth` / `prometheus_metrics_leak` | format `# HELP`/`# TYPE` / expvar JSON |
| `tomcat_manager_default` | 401/403 → basic-auth → 200 + marker |
| `adminer_exposed` | regex `Adminer \d+\.\d+` / title |
| `saml_metadata_exposed` | XML + `EntityDescriptor` |
| `swagger_walker` | spec valid + `json.loads()` sukses (HTML gagal parse) |
| `private_profile_bypass` | JSON `is_private:true` + field PII |
| `dirlist` | kontrol `/random/` + title `Index of` + anchor≥3 |
| `wp_xmlrpc*`, `wp_user_enum`, `grpc_reflection`, `oauth_redirect_bypass`, `url_preview_ssrf` | konten/protokol spesifik |

### DIPERBAIKI (v0.10.6) — validasi lemah, rawan soft-404/catch-all

1. **`bypass_403`** — `_is_bypass` dulu menganggap *setiap* status `<400` yang
   berbeda dari baseline (401/403) sebagai bypass. Server SPA yang membalas
   beranda `200` untuk path/header mutasi → "403 bypass" palsu. **Fix:** tolak
   bila response 2xx adalah soft-404/SPA shell atau sama dengan kontrol catch-all;
   3xx ke `/login`/`/auth`/root tidak dihitung bypass.
2. **`phpmyadmin_exposed`** — dulu cocok substring lowercase `"phpmyadmin"` di
   body (bisa muncul di JS/tautan situs lain). **Fix:** wajib signature KUAT
   (`pma_password`, `PMA_VERSION`, `<title>phpMyAdmin`, dll.) + tolak
   soft-404/catch-all.
3. **`jenkins_unauth_console`** — tambah guard soft-404/catch-all; endpoint
   `/api/json` kini wajib benar-benar JSON (Content-Type / body diawali `{`/`[`).

### Sebelumnya diperbaiki (lihat dok terpisah)
- `passive/sensitive_files.py` → `2026-06-23-sensitive-files-false-positive.md`
- `active/auth_bypass.py` → `2026-06-23-auth-bypass-admin-soft404.md`

## Infrastruktur bersama (core/validation.py)

Helper terpusat agar modul probe-path konsisten menolak catch-all:
- `is_soft_200(resp)` — deteksi 200 yang sebetulnya halaman 404/SPA shell.
- `catch_all_control(client, base)` — ambil body path acak (kontrol negatif).
- `is_catch_all_response(body, control_body)` — bandingkan via `body_similarity`.
- `looks_like_html_shell(body)` — diperkuat (Next.js/Nuxt/Remix/Angular markers).

## Pencegahan regresi

- `tests/test_soft404_guards.py` — SPA catch-all tidak memicu
  `phpmyadmin_exposed`/`jenkins_unauth_console`/`bypass_403`; layanan asli tetap
  terdeteksi.
- Suite penuh: **29 passed, 1 skipped**.

## Prinsip (standar validasi proyek)

Setiap finding harus didukung minimal salah satu:
1. **Signature konten unik** layanan/file (bukan keyword generik).
2. **Bukti eksekusi/eksploitasi** (marker ter-inject, isi `/etc/passwd`, dll.).
3. **Kontrol-negatif + diff** (path acak / baseline) untuk menyingkirkan
   catch-all/soft-404.
Idealnya dikombinasikan dengan **double-confirm**.
