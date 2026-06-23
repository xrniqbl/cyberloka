# CORS severity & re-verifier catch-all guard (prioritas #1–#3, #7)

- **Tanggal:** 2026-06-23
- **Versi:** v0.10.6

## Konteks
Setelah audit, modul prioritas tinggi ternyata SEBAGIAN BESAR sudah tervalidasi
dengan baik — tidak diubah agar tidak menimbulkan regresi:

| Modul | Status | Mekanisme |
|---|---|---|
| `active/redirect.py` | ✅ baik | dual-host exact-match + negative-baseline + status 30x |
| `passive/cors.py` | ✅ baik | exact-origin reflect + tier severity benar |
| `active/cors_null_origin.py` | ✅ baik | ACAO==origin + ACAC=true |
| `active/host_header.py` | ✅ baik | random-marker + baseline-diff |
| `active/cache_poison.py` | ✅ baik | cacheable + reflect + clean-replay |
| `active/cache_deception.py` | ✅ baik | konten privat + cache-HIT header |

## Yang diperbaiki

### 1. `passive/cors_advanced.py` — severity akurat
Dulu: reflect Origin attacker TANPA credentials = **HIGH** (dan dengan creds =
CRITICAL). Tanpa `Allow-Credentials: true`, attacker hanya bisa membaca data yang
toh non-credentialed — itu "akses terbuka", bukan pencurian data terotentikasi.
**Fix:** reflect+creds = **HIGH**, reflect tanpa creds = **MEDIUM** (selaras
`passive/cors.py` & PortSwigger).

### 2. `active/curl_active_verify.py` — guard catch-all terpusat (#7)
Re-verifier (post-processor yang men-cek ulang SEMUA finding CRITICAL/HIGH) dulu
menandai `curl_verified=True` bila signature substring muncul di body — TANPA
guard catch-all. Beberapa recipe punya signature lemah (mis. `firebase_open_db`
→ `"{"`, `kibana_unauth` → `"version"`), sehingga halaman catch-all/SPA yang
kebetulan memuat substring itu bisa "terverifikasi" palsu.

**Fix:** tambah guard terpusat — match body-signature DITOLAK bila response
adalah `is_soft_200` (404/SPA shell) atau `is_catch_all_response` (identik dengan
path random kontrol). Ini melindungi SEMUA modul yang punya recipe sekaligus,
plus jalur fallback yang sudah membandingkan ke kontrol. `_negative_control`
kini juga mengembalikan body untuk perbandingan `body_similarity`.

## Pencegahan regresi
`tests/test_cors_and_reverifier.py`:
- CORS reflect tanpa creds → MEDIUM; dengan creds → HIGH.
- Re-verifier menolak signature `"{"` yang muncul di catch-all (verified=False).
- Re-verifier tetap meng-confirm signature asli (`cluster_name`) yang berbeda
  dari kontrol (verified=True).

Suite penuh: **42 passed, 1 skipped**.

## Catatan
Jalur re-verifikasi ini adalah jaring pengaman terpusat (#7): selain guard
per-modul, setiap finding CRITICAL/HIGH di-cek ulang terhadap kontrol negatif
sebelum dianggap "terverifikasi aktif".
