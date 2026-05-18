@echo off
REM ============================================================
REM   cek.bat - Cyberloka Interactive Menu (Windows)
REM   Versi: 0.7.0
REM
REM   Cara update:
REM     1. Update repo terbaru :  git pull
REM     2. Re-install package  :  pip install -e .[web,pdf]
REM     3. Atau dari PyPI       :  pip install --upgrade cyberloka[web,pdf]
REM     4. Jalankan ini lagi    :  cek.bat
REM ============================================================

setlocal enabledelayedexpansion

REM --- Mode non-interaktif: kalau ada arg URL, langsung scan full ---
if not "%~1"=="" (
    if "%~1" NEQ "/?" (
        if "%~1" NEQ "-h" (
            if "%~1" NEQ "--help" (
                set TARGET=%~1
                shift
                goto :run_full_direct
            )
        )
    )
)

:menu
cls
echo ================================================================
echo   CYBERLOKA v0.7.0 - Web Vulnerability Scanner
echo ================================================================
echo.
echo  APA YANG MAU DICOBA?  (pilih nomor)
echo ----------------------------------------------------------------
echo.
echo   1. Buka menu interaktif Cyberloka  [RECOMMENDED]
echo   2. Quick Scan    - passive, paling aman
echo   3. Full Scan     - recon + passive + active, butuh izin
echo   4. Buka Dashboard di browser
echo   5. Lihat laporan HTML terakhir
echo   6. Tampilkan --help
echo   7. Daftar semua module deteksi
echo   8. Update Cyberloka (git pull + pip install)
echo   0. Keluar
echo.
set /p CHOICE="Pilih [0-8]: "

if "%CHOICE%"=="1" goto :interactive
if "%CHOICE%"=="2" goto :quick
if "%CHOICE%"=="3" goto :full
if "%CHOICE%"=="4" goto :dashboard
if "%CHOICE%"=="5" goto :open_report
if "%CHOICE%"=="6" goto :show_help
if "%CHOICE%"=="7" goto :list_modules
if "%CHOICE%"=="8" goto :update
if "%CHOICE%"=="0" goto :end

echo.
echo Pilihan tidak valid.
timeout /t 2 >nul
goto :menu


REM ============================================================
REM   1. INTERACTIVE: tanya target + opsi
REM ============================================================
:interactive
echo.
set /p TARGET="Target URL (mis. https://example.com): "
if "%TARGET%"=="" (
    echo [ERROR] Target wajib diisi.
    pause
    goto :menu
)

echo.
echo Pilih mode:
echo   p = passive  (aman, observasi saja)
echo   a = active   (kirim payload uji + recon)
echo   f = full     (semua modul, recommended utk audit lengkap)
set /p MODE="Mode [p/a/f] (default f): "
if "%MODE%"=="" set MODE=f
if /I "%MODE%"=="p" set MODESTR=passive
if /I "%MODE%"=="a" set MODESTR=active
if /I "%MODE%"=="f" set MODESTR=full
if "%MODESTR%"=="" set MODESTR=full

echo.
set /p AUTHED="Apakah Anda berwenang men-scan target ini? [y/N]: "
if /I "%AUTHED%" NEQ "y" (
    if /I "%AUTHED%" NEQ "yes" (
        echo Dibatalkan.
        pause
        goto :menu
    )
)

echo.
set /p WANT_AUTH="Pakai authenticated scan (login dulu)? [y/N]: "
set AUTH_ARGS=
if /I "%WANT_AUTH%"=="y" (
    set /p LOGIN_URL="Login URL (mis. https://example.com/login): "
    set /p LOGIN_USER="Username/email: "
    set /p LOGIN_PASS="Password: "
    set AUTH_ARGS=--login-url "!LOGIN_URL!" --login-username "!LOGIN_USER!" --login-password "!LOGIN_PASS!"
)

echo.
echo ================================================================
echo   Menjalankan Cyberloka...
echo ================================================================
cyberloka -t "%TARGET%" --mode %MODESTR% --authorized --yes ^
    --json report.json --html report.html ^
    --threads 10 --rate 10 --timeout 12 ^
    %AUTH_ARGS%
goto :after_scan


REM ============================================================
REM   2. QUICK (passive)
REM ============================================================
:quick
echo.
set /p TARGET="Target URL: "
if "%TARGET%"=="" (
    pause
    goto :menu
)
echo.
echo ================================================================
echo   Quick Scan (passive) - 27 modul
echo ================================================================
cyberloka -t "%TARGET%" --mode passive --authorized --yes ^
    --json report.json --html report.html ^
    --threads 10 --rate 10 --timeout 10
goto :after_scan


REM ============================================================
REM   3. FULL
REM ============================================================
:full
echo.
set /p TARGET="Target URL: "
if "%TARGET%"=="" (
    pause
    goto :menu
)
echo.
set /p AUTHED="Apakah Anda berwenang men-scan target ini? [y/N]: "
if /I "%AUTHED%" NEQ "y" (
    if /I "%AUTHED%" NEQ "yes" (
        echo Dibatalkan.
        pause
        goto :menu
    )
)

:run_full_direct
echo.
echo ================================================================
echo   Full Scan (63 modul recon + passive + active)
echo ================================================================
cyberloka -t "%TARGET%" --mode full --authorized --yes ^
    --json report.json --html report.html ^
    --threads 10 --rate 10 --timeout 12 ^
    %*
goto :after_scan


REM ============================================================
REM   4. DASHBOARD
REM ============================================================
:dashboard
echo.
echo ================================================================
echo   Membuka dashboard di http://127.0.0.1:8765
echo   (tekan Ctrl-C di window ini untuk stop)
echo ================================================================
start "" "http://127.0.0.1:8765"
cyberloka-web --host 127.0.0.1 --port 8765
goto :menu


REM ============================================================
REM   5. BUKA REPORT
REM ============================================================
:open_report
if exist report.html (
    start "" "report.html"
) else (
    echo.
    echo report.html tidak ditemukan. Jalankan scan dulu.
    pause
)
goto :menu


REM ============================================================
REM   6. HELP
REM ============================================================
:show_help
echo.
cyberloka --help
echo.
pause
goto :menu


REM ============================================================
REM   7. DAFTAR MODUL
REM ============================================================
:list_modules
cls
echo ================================================================
echo   Daftar Modul Cyberloka v0.7.0 (65 modul, 63 jalan di full)
echo ================================================================
echo.
echo [RECON - 15 modul]
echo   dns                  - Catatan domain (A, MX, NS, TXT, CNAME, SOA)
echo   whois                - WHOIS lookup
echo   ports                - Port scan + intrusion test (FTP, Redis, Mongo, dll)
echo   fingerprint          - Deteksi teknologi (server, framework, CMS)
echo   subdomains           - Enumerasi subdomain
echo   subdomain_takeover   - Cek subdomain dangling (GitHub, S3, dll)
echo   api_discovery        - Cari Swagger, OpenAPI, GraphQL
echo   email_security       - SPF, DKIM, DMARC, CAA, DNSSEC
echo   nextjs_specific      - Build ID, source map, dev endpoint Next.js
echo   cf_origin            - Cari IP origin di balik Cloudflare
echo   wayback              - Wayback Machine + crt.sh
echo   framework_default    - Halaman default (WP, Spring, Tomcat, dll)
echo   graphql_deep         - Introspection + field suggestion
echo   source_leak          - .git, .env, backup, kunci SSH/AWS
echo   crawler              - Pemetaan halaman + form
echo.
echo [PASSIVE - 13 modul]
echo   headers              - Header keamanan HTTP
echo   tls                  - Sertifikat HTTPS
echo   cookies              - Atribut cookie sesi
echo   cors                 - CORS misconfig
echo   clickjacking         - X-Frame-Options
echo   methods              - Metode HTTP tidak aman (TRACE, PUT, DELETE)
echo   sensitive_files      - File sensitif terbuka
echo   robots               - robots.txt + sitemap
echo   outdated_libs        - Library JS lama (jQuery, lodash, dll)
echo   mixed_content        - Resource HTTP di halaman HTTPS
echo   jwt                  - Token JWT (alg=none, exp, dll)
echo   csp_evaluator        - Kekuatan Content-Security-Policy
echo   captcha_check        - Captcha pada form sensitif
echo.
echo [ACTIVE - 35 modul]
echo   csrf                 - Token anti-CSRF
echo   sqli                 - SQL Injection
echo   xss                  - Cross-Site Scripting
echo   redirect             - Open Redirect
echo   lfi                  - Local File Inclusion
echo   cmdi                 - Command Injection
echo   dirlist              - Directory Listing
echo   ssrf                 - Server-Side Request Forgery
echo   ssrf_metadata        - SSRF ke cloud metadata
echo   ssti                 - Server-Side Template Injection
echo   xxe                  - XML External Entity
echo   forms                - Fuzz form discovered
echo   session              - Sesi login + atribut cookie
echo   voucher              - Kupon umum + stack abuse
echo   payment              - Tampering harga + IDOR order + leak gateway
echo   otp_check            - Rate-limit + panjang OTP
echo   password_reset       - User enum + token leak
echo   file_upload          - Bypass ekstensi (.php.jpg, .phtml, dll)
echo   idor_generic         - IDOR via mutasi ID
echo   host_header          - Host header injection
echo   cache_poison         - Web cache poisoning
echo   hpp                  - HTTP Parameter Pollution
echo   rfd                  - Reflected File Download
echo   dom_xss              - DOM-based XSS (static analysis)
echo   oauth_check          - OAuth state, PKCE, redirect_uri
echo   pii_leak             - NIK, NPWP, HP, kartu kredit
echo   race_condition       - Voucher/withdraw double
echo   proto_pollution      - __proto__, constructor[prototype]
echo   http_smuggling       - CL.TE / TE.CL
echo   ws_check             - WebSocket origin hijack
echo   auth_bypass          - Default credentials + admin path probe
echo   balance              - Saldo/wallet manipulation
echo   env_leak             - AWS/Stripe/JWT secret + debug endpoint
echo   api_auth             - API tanpa auth + mass export + rate limit
echo   mass_assignment      - is_admin=true, role=admin di register
echo.
echo [SIMULATE - 2 modul, hanya jika --simulate-attack]
echo   rate_limit           - Tes rate-limit login
echo   burst                - Burst request
echo.
pause
goto :menu


REM ============================================================
REM   8. UPDATE
REM ============================================================
:update
echo.
echo ================================================================
echo   Update Cyberloka
echo ================================================================
echo.
echo Pilih sumber update:
echo   g = git pull (kalau Anda clone dari github)
echo   p = pip install --upgrade
echo.
set /p UPD="Pilih [g/p]: "

if /I "%UPD%"=="g" (
    git pull
    pip install -e .[web,pdf]
) else if /I "%UPD%"=="p" (
    pip install --upgrade "cyberloka[web,pdf]"
) else (
    echo Pilihan tidak valid.
)
echo.
pause
goto :menu


REM ============================================================
REM   AFTER SCAN
REM ============================================================
:after_scan
set EXITCODE=%ERRORLEVEL%
echo.
echo ================================================================
if %EXITCODE% EQU 0 (
    echo   [OK] Scan selesai. Tidak ada finding critical/high.
) else if %EXITCODE% EQU 1 (
    echo   [!] Scan selesai. ADA finding CRITICAL atau HIGH.
) else (
    echo   [ERROR] Scan gagal exit code %EXITCODE%.
)
echo   Laporan: report.json + report.html
echo ================================================================
echo.
set /p OPEN="Buka report.html di browser sekarang? [Y/n]: "
if /I "%OPEN%" NEQ "n" (
    if exist report.html start "" "report.html"
)
echo.
pause
if not "%~1"=="" goto :end
goto :menu


:end
endlocal
exit /b 0
