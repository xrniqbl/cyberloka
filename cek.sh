#!/usr/bin/env bash
# ============================================================
#   cek.sh - Cyberloka Full Scan (Linux/macOS)
#   Menjalankan SEMUA 58 modul scan (recon + passive + active)
#
#   Gunakan:
#     ./cek.sh https://target.com
#     ./cek.sh https://target.com --login-url https://target.com/login --login-username admin --login-password secret123
#
#   Hasil:
#     - Console output berwarna (rich)
#     - report.json (JSON terstruktur)
#     - report.html (self-contained, bisa buka di browser)
# ============================================================

set -euo pipefail

if [ $# -lt 1 ]; then
    echo ""
    echo "[ERROR] Target URL belum diisi!"
    echo ""
    echo "Penggunaan:"
    echo "  ./cek.sh <URL> [opsi tambahan]"
    echo ""
    echo "Contoh:"
    echo "  ./cek.sh https://example.com"
    echo "  ./cek.sh https://example.com --login-url https://example.com/login --login-username admin --login-password pass123"
    echo "  ./cek.sh https://example.com --auth-bearer eyJhbGciOi..."
    echo ""
    exit 1
fi

TARGET="$1"
shift

echo ""
echo "===================================================================="
echo "  CYBERLOKA v0.5.0 - Full Security Scan"
echo "===================================================================="
echo "  Target  : ${TARGET}"
echo "  Mode    : full (58 modul)"
echo "  Output  : report.json + report.html"
echo "===================================================================="
echo ""

cyberloka -t "${TARGET}" \
    --mode full \
    --authorized \
    --yes \
    --json report.json \
    --html report.html \
    --threads 10 \
    --rate 10 \
    --timeout 12 \
    "$@"

EXIT_CODE=$?

echo ""
if [ ${EXIT_CODE} -eq 0 ]; then
    echo "===================================================================="
    echo "  [OK] Scan selesai. Tidak ada finding critical/high."
    echo "  Laporan: report.json, report.html"
    echo "===================================================================="
elif [ ${EXIT_CODE} -eq 1 ]; then
    echo "===================================================================="
    echo "  [!] Scan selesai. ADA finding CRITICAL atau HIGH!"
    echo "  Laporan: report.json, report.html"
    echo "  Buka report.html di browser untuk detail."
    echo "===================================================================="
else
    echo "===================================================================="
    echo "  [ERROR] Scan gagal (exit code: ${EXIT_CODE})"
    echo "===================================================================="
fi

echo ""
echo "Modul yang dijalankan (mode full):"
echo "-----------------------------------"
echo "RECON: dns, whois, ports, fingerprint, subdomains, subdomain_takeover,"
echo "       api_discovery, email_security, nextjs_specific, cf_origin,"
echo "       wayback, framework_default, graphql_deep, source_leak, crawler"
echo ""
echo "PASSIVE: headers, tls, cookies, cors, clickjacking, methods,"
echo "         sensitive_files, robots, outdated_libs, mixed_content, jwt,"
echo "         csp_evaluator, captcha_check"
echo ""
echo "ACTIVE: csrf, sqli, xss, redirect, lfi, cmdi, dirlist, ssrf,"
echo "        ssrf_metadata, ssti, xxe, forms, session, voucher, payment,"
echo "        otp_check, password_reset, file_upload, idor_generic,"
echo "        host_header, cache_poison, hpp, rfd, dom_xss, oauth_check,"
echo "        pii_leak, race_condition, proto_pollution, http_smuggling,"
echo "        ws_check"
echo ""
echo "SIMULATE: rate_limit, burst (hanya jika --simulate-attack)"
echo "-----------------------------------"
