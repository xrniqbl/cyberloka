# Perbaikan False-Positive: `framework_default` (`/_ignition` & `/.env` catch-all)

- **Tanggal:** 2026-06-23
- **Modul terdampak:** `cyberloka/recon/framework_default.py`
- **Versi:** v0.10.6
- **Kasus nyata:** `ods.kop.go.id` membalas HTML identik (1569 byte) untuk
  `GET /.env` DAN `GET /_ignition/execute-solution` — halaman catch-all yang
  sama untuk URL apa pun.

## Akar masalah

`framework_default` adalah recon ringan yang menandai path dari `HTTP < 400` +
marker substring. Beberapa entri punya marker **kosong** atau **terlalu lemah**:

- `/_ignition/execute-solution` → marker `""` → **setiap** 200 = CRITICAL.
- `/.env` → marker `"="` → setiap HTML (selalu punya `=` di atribut) = CRITICAL.
- `/actuator/heapdump`, `/admin/` → marker `""`.

Tidak ada guard soft-404/catch-all. Server SPA/catch-all 200 → endpoint yang
sebenarnya tidak ada dilaporkan sebagai celah CRITICAL.

## Bukti yang ditunjukkan pengguna
```
GET /.env                          -> 200, text/html, 1569 byte
GET /_ignition/execute-solution    -> 200, text/html, 1569 byte (identik)
```
`.env` asli seharusnya `text/plain` berisi `APP_KEY=`, `DB_PASSWORD=`, dst.

## Perbaikan (secure-by-design)

Setiap path kini wajib lolos guard + validasi spesifik:

1. **Soft-404 / SPA guard** (`is_soft_200`) dan **catch-all guard**
   (`catch_all_control` + `is_catch_all_response`) untuk SEMUA path.
2. **Marker spesifik** (tidak ada lagi marker kosong/`"="`). Marker lemah
   diperketat (mis. actuator/health → `"status"`, jolokia → `"agent"`,
   tomcat → `Apache Tomcat`, phpMyAdmin → `pma_password`).
3. **`/.env`** → validator khusus: wajib >=2 baris `KEY=VALUE` dan **bukan HTML**
   (selaras `passive/sensitive_files`). Confidence `confirmed`.
4. **`/_ignition/execute-solution`** (CVE-2021-3129) → **probe POST aman**:
   kirim `{"solution":"<class tak ada>","parameters":{}}`. Ignition asli membalas
   error khas (mis. `... does not exist`, `Facade\\Ignition`, `Illuminate\\`) —
   BUKAN halaman catch-all. Hanya dilaporkan bila tanda-tangan Ignition muncul.
   Confidence `firm` + catatan: RCE penuh butuh Ignition <= 2.5.1 + APP_DEBUG;
   rantai eksploitasi destruktif **tidak dijalankan**.
5. **`/actuator/heapdump`** → wajib signature biner HPROF/gzip ter-anchor.

## Pencegahan regresi

`tests/test_framework_default.py`:
- `test_catchall_no_findings` — semua path balas HTML catch-all identik →
  NOL temuan (mereplikasi `ods.kop.go.id`).
- `test_real_ignition_flagged` — Ignition asli (error khas saat POST) → CRITICAL/firm.
- `test_real_env_flagged` — `.env` KEY=VALUE asli → CRITICAL/confirmed.

Suite penuh: **32 passed, 1 skipped**.

## Catatan

Modul ini melengkapi perbaikan sebelumnya (`sensitive_files`, `auth_bypass`,
`bypass_403`, `phpmyadmin_exposed`, `jenkins_unauth_console`). Jawaban atas
pertanyaan "apakah ini benar-benar celah atau hanya akses terbuka": scanner kini
**membuktikan** endpoint adalah handler nyata (signature konten / respons
eksploit-spesifik), bukan sekadar HTTP 200.
