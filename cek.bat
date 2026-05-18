@echo off
REM =====================================================================
REM  Cyberloka quick launcher (Windows)
REM  Jalankan: cek.bat
REM =====================================================================
setlocal EnableDelayedExpansion
title Cyberloka - Web Vulnerability Scanner

REM Pindah ke folder script ini
cd /d "%~dp0"

REM Folder untuk menampung file laporan PDF/JSON/HTML
set "REPORTDIR=%~dp0reports"
if not exist "%REPORTDIR%" mkdir "%REPORTDIR%"

REM Default args untuk semua scan: PDF auto-named di folder reports + JSON & HTML.
set "COMMON_OUT=--report-dir "%REPORTDIR%" --json "%REPORTDIR%\report.json" --html "%REPORTDIR%\report.html""

:menu
cls
echo =====================================================================
echo                  CYBERLOKA - Web Vulnerability Scanner
echo =====================================================================
echo  Folder laporan: %REPORTDIR%
echo  PDF dibuat otomatis: cyberloka-report-^<host^>-^<timestamp^>.pdf
echo ---------------------------------------------------------------------
echo  1. Scan PASSIVE  (paling aman, tanpa payload aktif)
echo  2. Scan ACTIVE   (passive + active checks, butuh izin tertulis)
echo  3. Scan FULL     (recon + passive + active, paling lengkap)
echo  4. Scan modul tertentu (input manual: headers,tls,sqli,...)
echo  5. Recon saja    (dns, whois, ports, subdomains, fingerprint, waf)
echo  6. Subdomain takeover check (DNS dangling)
echo  7. Simulate attack (burst + rate-limit, butuh --login-url)
echo  8. Update repo   (git pull)
echo  9. Tampilkan daftar modul yang tersedia
echo  A. Buka folder laporan
echo  0. Keluar
echo ---------------------------------------------------------------------
set /p choice="Pilih: "

if /i "%choice%"=="1" goto passive
if /i "%choice%"=="2" goto active
if /i "%choice%"=="3" goto full
if /i "%choice%"=="4" goto custom
if /i "%choice%"=="5" goto recon
if /i "%choice%"=="6" goto takeover
if /i "%choice%"=="7" goto simulate
if /i "%choice%"=="8" goto gitpull
if /i "%choice%"=="9" goto listmod
if /i "%choice%"=="A" goto openrep
if /i "%choice%"=="0" goto end
echo Pilihan tidak dikenal.
pause
goto menu

REM ---------------------------------------------------------------------
:askTarget
set "TARGET="
set /p TARGET="Masukkan target (URL/IP, mis. https://example.com): "
if "%TARGET%"=="" (
    echo Target wajib diisi.
    pause
    goto menu
)
goto :eof

REM ---------------------------------------------------------------------
:passive
call :askTarget
python -m cyberloka -t "%TARGET%" --mode passive %COMMON_OUT%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:active
call :askTarget
python -m cyberloka -t "%TARGET%" --mode active --authorized %COMMON_OUT%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:full
call :askTarget
python -m cyberloka -t "%TARGET%" --mode full --authorized %COMMON_OUT%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:custom
call :askTarget
set "MODS="
set /p MODS="Modul (comma, contoh: headers,tls,api_discovery,jwt): "
if "%MODS%"=="" (
    echo Modul wajib diisi.
    pause
    goto menu
)
python -m cyberloka -t "%TARGET%" --modules %MODS% --authorized %COMMON_OUT%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:recon
call :askTarget
python -m cyberloka -t "%TARGET%" --modules dns,whois,ports,subdomains,fingerprint,waf_detect %COMMON_OUT%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:takeover
call :askTarget
python -m cyberloka -t "%TARGET%" --modules subdomain_takeover %COMMON_OUT%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:simulate
call :askTarget
set "LOGIN="
set /p LOGIN="Login URL (mis. https://example.com/login): "
if "%LOGIN%"=="" (
    echo Login URL wajib untuk simulate.
    pause
    goto menu
)
python -m cyberloka -t "%TARGET%" --simulate-attack --login-url "%LOGIN%" --authorized %COMMON_OUT%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

REM ---------------------------------------------------------------------
:gitpull
echo.
echo === Update repo (git pull) ===
where git >nul 2>nul
if errorlevel 1 (
    echo [ERROR] git tidak ditemukan di PATH. Install Git for Windows dulu.
    pause
    goto menu
)
git rev-parse --is-inside-work-tree >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Folder ini bukan git repository.
    pause
    goto menu
)
git fetch --all --prune
git pull --ff-only
if errorlevel 1 (
    echo.
    echo [WARN] git pull gagal (mungkin ada konflik / perubahan lokal).
    echo Stash perubahan lokal Anda lalu coba lagi:  git stash
)
echo.
echo Cabang aktif:
git rev-parse --abbrev-ref HEAD
echo Commit terakhir:
git log -1 --oneline
pause
goto menu

REM ---------------------------------------------------------------------
:listmod
echo.
echo === Daftar modul Cyberloka ===
python -c "from cyberloka.scanner import MODULE_MAP; [print(' -', k) for k in sorted(MODULE_MAP)]"
pause
goto menu

:openrep
start "" "%REPORTDIR%"
goto menu

:end
endlocal
exit /b 0
