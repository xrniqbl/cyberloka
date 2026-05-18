#!/usr/bin/env bash
# ============================================================
#   cek.sh - Cyberloka Interactive Menu (Linux/macOS)
#   Versi: 0.9.0
#
#   Cara update:
#     git pull && pip install -e .[web,pdf]
#   atau:
#     pip install --upgrade 'cyberloka[web,pdf]'
# ============================================================

set -euo pipefail

# Mode non-interaktif: jika ada arg URL, langsung scan full
if [ $# -ge 1 ] && [[ "$1" != "-h" && "$1" != "--help" ]]; then
    TARGET="$1"
    shift
    cyberloka -t "${TARGET}" --mode full --authorized --yes \
        --json report.json --html report.html \
        --threads 10 --rate 10 --timeout 12 "$@"
    exit $?
fi

show_menu() {
    clear || true
    cat <<'BANNER'
================================================================
  CYBERLOKA v0.9.0 - Web Vulnerability Scanner
================================================================

 APA YANG MAU DICOBA?  (pilih nomor)
----------------------------------------------------------------

  1. Buka menu interaktif Cyberloka  [RECOMMENDED]
  2. Quick Scan    - passive, paling aman
  3. Full Scan     - recon + passive + active, butuh izin
  4. Buka Dashboard di browser
  5. Lihat laporan HTML terakhir
  6. Tampilkan --help
  7. Daftar semua module deteksi
  8. Update Cyberloka (git pull + pip install)
  0. Keluar

BANNER
}

interactive_scan() {
    read -rp "Target URL (mis. https://example.com): " TARGET
    [ -z "$TARGET" ] && return
    echo
    echo "Pilih mode:"
    echo "  p = passive  (aman, observasi saja)"
    echo "  a = active   (kirim payload uji + recon)"
    echo "  f = full     (semua modul, recommended)"
    read -rp "Mode [p/a/f] (default f): " MODE
    case "${MODE:-f}" in
        p|P) MODE_STR=passive ;;
        a|A) MODE_STR=active ;;
        *) MODE_STR=full ;;
    esac

    echo
    read -rp "Apakah Anda berwenang men-scan target ini? [y/N]: " AUTHED
    case "$AUTHED" in y|Y|yes|YES) ;; *) echo "Dibatalkan."; return ;; esac

    echo
    read -rp "Pakai authenticated scan (login dulu)? [y/N]: " WANT_AUTH
    AUTH_ARGS=()
    if [[ "$WANT_AUTH" =~ ^[yY]$ ]]; then
        read -rp "Login URL: " LOGIN_URL
        read -rp "Username/email: " LOGIN_USER
        read -rsp "Password: " LOGIN_PASS; echo
        AUTH_ARGS=(--login-url "$LOGIN_URL" --login-username "$LOGIN_USER" --login-password "$LOGIN_PASS")
    fi

    echo
    echo "================================================================"
    echo "  Menjalankan Cyberloka..."
    echo "================================================================"
    cyberloka -t "$TARGET" --mode "$MODE_STR" --authorized --yes \
        --json report.json --html report.html \
        --threads 10 --rate 10 --timeout 12 \
        "${AUTH_ARGS[@]}" || true
    after_scan
}

quick_scan() {
    read -rp "Target URL: " TARGET
    [ -z "$TARGET" ] && return
    echo
    cyberloka -t "$TARGET" --mode passive --authorized --yes \
        --json report.json --html report.html \
        --threads 10 --rate 10 --timeout 10 || true
    after_scan
}

full_scan() {
    read -rp "Target URL: " TARGET
    [ -z "$TARGET" ] && return
    read -rp "Apakah Anda berwenang men-scan target ini? [y/N]: " AUTHED
    case "$AUTHED" in y|Y|yes|YES) ;; *) echo "Dibatalkan."; return ;; esac
    cyberloka -t "$TARGET" --mode full --authorized --yes \
        --json report.json --html report.html \
        --threads 10 --rate 10 --timeout 12 || true
    after_scan
}

dashboard() {
    echo
    echo "Membuka dashboard di http://127.0.0.1:8765 (Ctrl-C untuk stop)"
    if command -v xdg-open >/dev/null; then xdg-open http://127.0.0.1:8765 & fi
    if command -v open >/dev/null; then open http://127.0.0.1:8765 & fi
    cyberloka-web --host 127.0.0.1 --port 8765 || true
}

open_report() {
    if [ -f report.html ]; then
        if command -v xdg-open >/dev/null; then xdg-open report.html
        elif command -v open >/dev/null; then open report.html
        else echo "Buka report.html secara manual."; fi
    else
        echo "report.html tidak ditemukan. Jalankan scan dulu."
    fi
    read -rp "[enter untuk lanjut]"
}

show_help() {
    cyberloka --help
    echo; read -rp "[enter untuk lanjut]"
}

list_modules() {
    cat <<'MOD'
================================================================
  Daftar Modul Cyberloka v0.9.0 (105 modul, 103 jalan di full)
================================================================

[RECON - 21]
  dns, whois, ports, fingerprint, subdomains, subdomain_takeover,
  api_discovery, email_security, email_security_extended,
  nextjs_specific, cf_origin, wayback, framework_default,
  graphql_deep, source_leak, crawler, cms_scan, cloud_buckets,
  k8s_exposure, dependency_confusion, favicon_hash

[PASSIVE - 22] (+exif_leak, homoglyph_check)
  headers, tls, cookies, cors, clickjacking, methods,
  sensitive_files, robots, outdated_libs, mixed_content, jwt,
  csp_evaluator, captcha_check, cache_control_audit, cors_advanced,
  cookie_scope, sentry_dsn_leak, server_timing_header,
  api_key_in_url, autocomplete_audit, exif_leak, homoglyph_check

[ACTIVE - 60] (+8 sosmed)
  csrf, sqli, xss, redirect, lfi, cmdi, dirlist, ssrf, ssrf_metadata,
  ssti, xxe, forms, session, voucher, payment, otp_check,
  password_reset, file_upload, idor_generic, host_header,
  cache_poison, hpp, rfd, dom_xss, oauth_check, pii_leak,
  race_condition, proto_pollution, http_smuggling, ws_check,
  auth_bypass, balance, env_leak, api_auth, mass_assignment,
  log_injection, jwt_confusion, crlf_injection, nosqli,
  deserialization, webhook_signature, csv_injection, graphql_dos,
  xpath_injection, logout_csrf, zip_slip, ldap_injection,
  captcha_bypass, xslt_injection, rate_limit_bypass,
  response_splitting, timing_attack,
  stored_xss, url_preview_ssrf, private_profile_bypass,
  media_persistence, dm_privacy, social_csrf, oauth_takeover,
  unicode_bypass

[SIMULATE - 2]  (hanya jika --simulate-attack)
  rate_limit, burst

MOD
    read -rp "[enter untuk lanjut]"
}

update_cyberloka() {
    echo
    echo "Pilih sumber update:"
    echo "  g = git pull (kalau Anda clone dari github)"
    echo "  p = pip install --upgrade"
    read -rp "Pilih [g/p]: " UPD
    case "$UPD" in
        g|G) git pull && pip install -e '.[web,pdf]' ;;
        p|P) pip install --upgrade 'cyberloka[web,pdf]' ;;
        *) echo "Pilihan tidak valid." ;;
    esac
    read -rp "[enter untuk lanjut]"
}

after_scan() {
    EXITCODE=$?
    echo
    echo "================================================================"
    if [ $EXITCODE -eq 0 ]; then
        echo "  [OK] Scan selesai. Tidak ada finding critical/high."
    elif [ $EXITCODE -eq 1 ]; then
        echo "  [!] Scan selesai. ADA finding CRITICAL atau HIGH."
    else
        echo "  [ERROR] Scan gagal exit code $EXITCODE."
    fi
    echo "  Laporan: report.json + report.html"
    echo "================================================================"
    read -rp "Buka report.html di browser sekarang? [Y/n]: " OPEN
    if [[ "${OPEN:-y}" =~ ^[yY]$ ]] && [ -f report.html ]; then
        if command -v xdg-open >/dev/null; then xdg-open report.html
        elif command -v open >/dev/null; then open report.html; fi
    fi
}

while true; do
    show_menu
    read -rp "Pilih [0-8]: " CHOICE
    case "$CHOICE" in
        1) interactive_scan ;;
        2) quick_scan ;;
        3) full_scan ;;
        4) dashboard ;;
        5) open_report ;;
        6) show_help ;;
        7) list_modules ;;
        8) update_cyberloka ;;
        0) exit 0 ;;
        *) echo "Pilihan tidak valid"; sleep 1 ;;
    esac
done
