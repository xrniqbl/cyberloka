@echo off
REM ============================================================
REM   cek.bat - Cyberloka Full Scan (Windows)
REM   Menjalankan SEMUA 58 modul scan (recon + passive + active)
REM   
REM   Gunakan:
REM     cek.bat https://target.com
REM     cek.bat https://target.com --login-url https://target.com/login --login-username admin --login-password secret123
REM
REM   Hasil:
REM     - Console output berwarna (rich)
REM     - report.json (JSON terstruktur)
REM     - report.html (self-contained, bisa buka di browser)
REM ============================================================

setlocal enabledelayedexpansion

REM --- Validasi target ---
if "%~1"=="" (
    echo.
    echo [ERROR] Target URL belum diisi!
    echo.
    echo Penggunaan:
    echo   cek.bat ^<URL^> [opsi tambahan]
    echo.
    echo Contoh:
    echo   cek.bat https://example.com
    echo   cek.bat https://example.com --login-url https://example.com/login --login-username admin --login-password pass123
    echo   cek.bat https://example.com --auth-bearer eyJhbGciOi...
    echo.
    exit /b 1
)

set TARGET=%~1
shift

REM --- Kumpulkan sisa argumen ---
set EXTRA_ARGS=
:loop
if "%~1"=="" goto :endloop
set EXTRA_ARGS=!EXTRA_ARGS! %1
shift
goto :loop
:endloop

echo.
echo ====================================================================
echo   CYBERLOKA v0.7.0 - Full Security Scan
echo ====================================================================
echo   Target  : %TARGET%
echo   Mode    : full (63 modul)
echo   Output  : report.json + report.html
echo ====================================================================
echo.

REM --- Jalankan scan full mode dengan semua modul ---
cyberloka -t "%TARGET%" ^
    --mode full ^
    --authorized ^
    --yes ^
    --json report.json ^
    --html report.html ^
    --threads 10 ^
    --rate 10 ^
    --timeout 12 ^
    %EXTRA_ARGS%

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ====================================================================
    echo   [OK] Scan selesai. Tidak ada finding critical/high.
    echo   Laporan: report.json, report.html
    echo ====================================================================
) else if %ERRORLEVEL% EQU 1 (
    echo.
    echo ====================================================================
    echo   [!] Scan selesai. ADA finding CRITICAL atau HIGH!
    echo   Laporan: report.json, report.html
    echo   Buka report.html di browser untuk detail.
    echo ====================================================================
) else (
    echo.
    echo ====================================================================
    echo   [ERROR] Scan gagal (exit code: %ERRORLEVEL%)
    echo ====================================================================
)

echo.
echo Modul yang dijalankan (mode full):
echo -----------------------------------
echo RECON: dns, whois, ports, fingerprint, subdomains, subdomain_takeover,
echo        api_discovery, email_security, nextjs_specific, cf_origin,
echo        wayback, framework_default, graphql_deep, source_leak, crawler
echo.
echo PASSIVE: headers, tls, cookies, cors, clickjacking, methods,
echo          sensitive_files, robots, outdated_libs, mixed_content, jwt,
echo          csp_evaluator, captcha_check
echo.
echo ACTIVE: csrf, sqli, xss, redirect, lfi, cmdi, dirlist, ssrf,
echo         ssrf_metadata, ssti, xxe, forms, session, voucher, payment,
echo         otp_check, password_reset, file_upload, idor_generic,
echo         host_header, cache_poison, hpp, rfd, dom_xss, oauth_check,
echo         pii_leak, race_condition, proto_pollution, http_smuggling,
echo         ws_check, auth_bypass, balance, env_leak, api_auth,
echo         mass_assignment
echo.
echo SIMULATE: rate_limit, burst (hanya jika --simulate-attack)
echo -----------------------------------
echo.
pause
