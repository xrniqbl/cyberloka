@echo off
REM =====================================================================
REM  Cyberloka quick launcher (Windows)
REM  Jalankan: cek.bat
REM =====================================================================
setlocal EnableDelayedExpansion
title Cyberloka - Web Vulnerability Scanner

REM Pindah ke folder script ini
cd /d "%~dp0"

:menu
cls
echo =====================================================================
echo                  CYBERLOKA - Web Vulnerability Scanner
echo =====================================================================
echo  1. Scan PASSIVE  (paling aman, tanpa payload aktif)
echo  2. Scan ACTIVE   (passive + active checks, butuh izin tertulis)
echo  3. Scan FULL     (recon + passive + active, paling lengkap)
echo  4. Scan modul tertentu (input manual: headers,tls,sqli,...)
echo  5. Recon saja    (dns, whois, ports, subdomains, fingerprint, waf)
echo  6. Subdomain takeover check (DNS dangling)
echo  7. Simulate attack (burst + rate-limit, butuh --login-url)
echo  8. Update repo   (git pull)
echo  9. Tampilkan daftar modul yang tersedia
echo  0. Keluar
echo ---------------------------------------------------------------------
set /p choice="Pilih [0-9]: "

if "%choice%"=="1" goto passive
if "%choice%"=="2" goto active
if "%choice%"=="3" goto full
if "%choice%"=="4" goto custom
if "%choice%"=="5" goto recon
if "%choice%"=="6" goto takeover
if "%choice%"=="7" goto simulate
if "%choice%"=="8" goto gitpull
if "%choice%"=="9" goto listmod
if "%choice%"=="0" goto end
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
python -m cyberloka -t "%TARGET%" --mode passive --html report.html --json report.json
pause
goto menu

:active
call :askTarget
python -m cyberloka -t "%TARGET%" --mode active --authorized --html report.html --json report.json
pause
goto menu

:full
call :askTarget
python -m cyberloka -t "%TARGET%" --mode full --authorized --html report.html --json report.json
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
python -m cyberloka -t "%TARGET%" --modules %MODS% --authorized --html report.html --json report.json
pause
goto menu

:recon
call :askTarget
python -m cyberloka -t "%TARGET%" --modules dns,whois,ports,subdomains,fingerprint,waf_detect --html report.html --json report.json
pause
goto menu

:takeover
call :askTarget
python -m cyberloka -t "%TARGET%" --modules subdomain_takeover --html report.html --json report.json
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
python -m cyberloka -t "%TARGET%" --simulate-attack --login-url "%LOGIN%" --authorized --html report.html --json report.json
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

:end
endlocal
exit /b 0
