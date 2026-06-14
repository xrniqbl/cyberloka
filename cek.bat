@echo off
REM =====================================================================
REM  Cyberloka quick launcher (Windows)  -  cek.bat
REM
REM  Bagian update otomatis: setiap kali script ini dijalankan, ia akan
REM  mengecek apakah ada commit baru di remote (origin). Jika ada, user
REM  ditanya untuk update. Pilihan #8 di menu adalah update manual
REM  (git pull + pip install) yang sama.
REM =====================================================================
setlocal EnableDelayedExpansion
title Cyberloka v0.9.1 - Web Vulnerability Scanner (verification-first)
chcp 65001 >nul 2>&1

REM Pindah ke folder script ini
cd /d "%~dp0"

REM Folder untuk menampung file laporan PDF/JSON/HTML
set "REPORTDIR=%~dp0reports"
if not exist "%REPORTDIR%" mkdir "%REPORTDIR%"

REM ----- Auto-check update saat start (silent jika repo up-to-date) ------
where git >nul 2>nul
if not errorlevel 1 (
    git rev-parse --is-inside-work-tree >nul 2>nul
    if not errorlevel 1 (
        echo Memeriksa update dari repository...
        git fetch --quiet origin 2>nul
        for /f %%a in ('git rev-list HEAD..@{u} --count 2^>nul') do set "BEHIND=%%a"
        if not "!BEHIND!"=="" (
            if not "!BEHIND!"=="0" (
                echo.
                echo ====================================================================
                echo  ADA UPDATE!  !BEHIND! commit baru tersedia di repository.
                echo  Pilih [Y] untuk update sekarang ^(git pull + pip install^)
                echo  atau [N] untuk lanjut tanpa update.
                echo ====================================================================
                set /p UPDATE_NOW="Update sekarang? (Y/N): "
                if /i "!UPDATE_NOW!"=="Y" goto gitpull_silent
            )
        )
    )
)

:menu
cls
echo ======================================================================
echo   CYBERLOKA v0.9.1 - Web Vulnerability Scanner  [verification-first]
echo ======================================================================
echo.
echo   APA YANG MAU DICOBA?   ^(pilih nomor^)
echo ----------------------------------------------------------------------
echo.
echo    1. Buka menu interaktif Cyberloka     [RECOMMENDED]
echo    2. Quick Scan         - passive, paling aman
echo    3. Full Scan          - recon + passive + active, butuh izin
echo    4. Buka folder laporan
echo    5. Lihat laporan PDF terakhir
echo    6. Tampilkan --help
echo    7. Daftar semua module deteksi
echo    8. Update Cyberloka ^(git pull + pip install^)
echo    0. Keluar
echo.
set /p choice="Pilih [0-8]: "

if "%choice%"=="1" goto interactive
if "%choice%"=="2" goto quickscan
if "%choice%"=="3" goto fullscan
if "%choice%"=="4" goto openrep
if "%choice%"=="5" goto lastpdf
if "%choice%"=="6" goto showhelp
if "%choice%"=="7" goto listmod
if "%choice%"=="8" goto gitpull
if "%choice%"=="0" goto end
echo.
echo Pilihan tidak dikenal: %choice%
pause
goto menu

REM =====================================================================
REM  HELPER: minta target
REM =====================================================================
:askTarget
set "TARGET="
set /p TARGET="Masukkan target (URL/IP, mis. https://example.com): "
if "%TARGET%"=="" (
    echo Target wajib diisi.
    pause
    goto menu
)
REM Extract host from target for report naming
REM Remove protocol prefix
set "RHOST=%TARGET%"
set "RHOST=!RHOST:https://=!"
set "RHOST=!RHOST:http://=!"
REM Remove path (everything after first /)
for /f "tokens=1 delims=/" %%h in ("!RHOST!") do set "RHOST=%%h"
REM Remove port (everything after first :)
for /f "tokens=1 delims=:" %%h in ("!RHOST!") do set "RHOST=%%h"
set "RJSON=%REPORTDIR%\report-%RHOST%.json"
set "RHTML=%REPORTDIR%\report-%RHOST%.html"
set "RSARIF=%REPORTDIR%\report-%RHOST%.sarif"
set "CONF="
set /p CONF="Min confidence yang ditampilkan (Enter=tentative, atau ketik: firm / confirmed): "
set "CONFARG="
if not "%CONF%"=="" set "CONFARG=--min-confidence %CONF%"
goto :eof

REM =====================================================================
REM  1. INTERACTIVE MENU  - sub-menu lengkap untuk power users
REM =====================================================================
:interactive
cls
echo ======================================================================
echo   CYBERLOKA - Menu Interaktif
echo ======================================================================
echo   Folder laporan : %REPORTDIR%
echo   PDF auto-named : cyberloka-report-^<host^>-^<timestamp^>.pdf
echo ----------------------------------------------------------------------
echo  a. Scan PASSIVE  (paling aman)
echo  b. Scan ACTIVE   (passive + active, butuh izin tertulis)
echo  c. Scan FULL     (recon + passive + active)
echo  d. Scan modul tertentu (input: headers,tls,sqli,...)
echo  e. Recon saja    (dns, whois, ports, subdomains, fingerprint, waf)
echo  f. Subdomain takeover check
echo  g. Simulate attack (burst + rate-limit, butuh --login-url)
echo  x. Kembali ke menu utama
echo ----------------------------------------------------------------------
set /p subchoice="Pilih: "
if /i "%subchoice%"=="a" goto passive
if /i "%subchoice%"=="b" goto active
if /i "%subchoice%"=="c" goto fullscan
if /i "%subchoice%"=="d" goto custom
if /i "%subchoice%"=="e" goto recon
if /i "%subchoice%"=="f" goto takeover
if /i "%subchoice%"=="g" goto simulate
if /i "%subchoice%"=="x" goto menu
echo Pilihan tidak dikenal.
pause
goto interactive

REM =====================================================================
REM  2. QUICK SCAN (passive)
REM =====================================================================
:quickscan
:passive
call :askTarget
python -m cyberloka -t "%TARGET%" --mode passive --report-dir "%REPORTDIR%" --json "%RJSON%" --html "%RHTML%" --sarif "%RSARIF%" %CONFARG%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

REM =====================================================================
REM  3. FULL SCAN
REM =====================================================================
:fullscan
:full
call :askTarget
set "PORTS="
set /p PORTS="Port scan (Enter=umum, 'all'=full 1-65535, atau range mis. 1-1024): "
set "PORTARG="
if not "%PORTS%"=="" set "PORTARG=--ports %PORTS%"
set "OOBURL="
set /p OOBURL="OOB collaborator URL (opsional, Enter=skip; isi untuk konfirmasi blind SSRF): "
set "OOBARG="
if not "%OOBURL%"=="" set "OOBARG=--oob-url %OOBURL%"
python -m cyberloka -t "%TARGET%" --mode full --authorized --report-dir "%REPORTDIR%" --json "%RJSON%" --html "%RHTML%" --sarif "%RSARIF%" %PORTARG% %OOBARG% %CONFARG%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:active
call :askTarget
set "PORTS="
set /p PORTS="Port scan (Enter=umum, 'all'=full 1-65535, atau range mis. 1-1024): "
set "PORTARG="
if not "%PORTS%"=="" set "PORTARG=--ports %PORTS%"
set "OOBURL="
set /p OOBURL="OOB collaborator URL (opsional, Enter=skip; isi untuk konfirmasi blind SSRF): "
set "OOBARG="
if not "%OOBURL%"=="" set "OOBARG=--oob-url %OOBURL%"
python -m cyberloka -t "%TARGET%" --mode active --authorized --report-dir "%REPORTDIR%" --json "%RJSON%" --html "%RHTML%" --sarif "%RSARIF%" %PORTARG% %OOBARG% %CONFARG%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:custom
call :askTarget
set "MODS="
set /p MODS="Modul (comma, contoh: headers,tls,api_discovery,jwt): "
if "%MODS%"=="" ( echo Modul wajib diisi. & pause & goto menu )
python -m cyberloka -t "%TARGET%" --modules %MODS% --authorized --report-dir "%REPORTDIR%" --json "%RJSON%" --html "%RHTML%" --sarif "%RSARIF%" %CONFARG%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:recon
call :askTarget
python -m cyberloka -t "%TARGET%" --modules dns,whois,ports,subdomains,fingerprint,waf_detect --report-dir "%REPORTDIR%" --json "%RJSON%" --html "%RHTML%" %CONFARG%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:takeover
call :askTarget
python -m cyberloka -t "%TARGET%" --modules subdomain_takeover --report-dir "%REPORTDIR%" --json "%RJSON%" --html "%RHTML%" %CONFARG%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

:simulate
call :askTarget
set "LOGIN="
set /p LOGIN="Login URL (mis. https://example.com/login): "
if "%LOGIN%"=="" ( echo Login URL wajib untuk simulate. & pause & goto menu )
python -m cyberloka -t "%TARGET%" --simulate-attack --login-url "%LOGIN%" --authorized --report-dir "%REPORTDIR%" --json "%RJSON%" --html "%RHTML%" %CONFARG%
echo.
echo Laporan tersimpan di: %REPORTDIR%
pause
goto menu

REM =====================================================================
REM  4. BUKA FOLDER LAPORAN
REM =====================================================================
:openrep
start "" "%REPORTDIR%"
goto menu

REM =====================================================================
REM  5. LIHAT LAPORAN PDF TERAKHIR
REM =====================================================================
:lastpdf
set "LAST_PDF="
for /f "delims=" %%f in ('dir /b /o-d "%REPORTDIR%\cyberloka-report-*.pdf" 2^>nul') do (
    if not defined LAST_PDF set "LAST_PDF=%REPORTDIR%\%%f"
)
if not defined LAST_PDF (
    echo Belum ada laporan PDF di %REPORTDIR%.
    echo Jalankan scan dulu (menu 2 atau 3).
    pause
    goto menu
)
echo Membuka: %LAST_PDF%
start "" "%LAST_PDF%"
goto menu

REM =====================================================================
REM  6. TAMPILKAN --help
REM =====================================================================
:showhelp
echo.
python -m cyberloka --help
echo.
pause
goto menu

REM =====================================================================
REM  7. DAFTAR MODUL
REM =====================================================================
:listmod
echo.
echo === Daftar modul Cyberloka ===
python -c "from cyberloka.scanner import MODULE_MAP; [print(' -', k) for k in sorted(MODULE_MAP)]"
echo.
pause
goto menu

REM =====================================================================
REM  8. UPDATE CYBERLOKA  (git pull + pip install)
REM =====================================================================
:gitpull
cls
echo ======================================================================
echo   UPDATE CYBERLOKA  (git pull + pip install)
echo ======================================================================
echo.
:gitpull_silent
where git >nul 2>nul
if errorlevel 1 (
    echo [ERROR] git tidak ditemukan di PATH.
    echo         Install Git for Windows: https://git-scm.com/download/win
    pause
    goto menu
)
git rev-parse --is-inside-work-tree >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Folder ini bukan git repository.
    echo         Clone ulang: git clone https://github.com/xrniqbl/cyberloka.git
    pause
    goto menu
)

echo Branch aktif sebelum update:
git rev-parse --abbrev-ref HEAD
echo.

REM Stash perubahan lokal otomatis biar pull mulus
git diff --quiet >nul 2>nul
set "STASHED=0"
if errorlevel 1 (
    echo [INFO] Ada perubahan lokal yang belum di-commit.
    echo        Otomatis di-stash sementara: 'cyberloka-auto-stash'.
    git stash push -u -m "cyberloka-auto-stash" >nul
    set "STASHED=1"
)

echo === git fetch ===
git fetch --all --prune
echo.
echo === git pull ===
git pull --ff-only
if errorlevel 1 (
    echo.
    echo [WARN] git pull gagal ^(kemungkinan konflik / non fast-forward^).
    echo        Lakukan resolve manual lalu jalankan ulang menu 8.
    if "%STASHED%"=="1" (
        echo.
        echo [INFO] Mengembalikan perubahan lokal dari stash...
        git stash pop >nul 2>nul
    )
    pause
    goto menu
)

if "%STASHED%"=="1" (
    echo.
    echo [INFO] Mengembalikan perubahan lokal dari stash...
    git stash pop >nul 2>nul
    if errorlevel 1 (
        echo [WARN] Konflik saat stash pop. Resolve manual: git status
        pause
        goto menu
    )
)

REM Update dependencies juga.
REM Catatan: kita sudah `cd /d "%~dp0"` di awal script, jadi pakai path
REM relatif (`.` dan `requirements.txt`) saja. Hindari `"%~dp0"` karena
REM trailing backslash + tanda kutip menyebabkan Windows menafsirkan
REM `\"` sebagai escape sequence -> path jadi rusak.
echo.
echo === Mengecek apakah Python tersedia ===
where python >nul 2>nul
if errorlevel 1 (
    echo [WARN] Python tidak ditemukan di PATH. Skip pip install.
    goto pipdone
)

if exist "requirements.txt" (
    echo === pip install -r requirements.txt ===
    python -m pip install --upgrade -r requirements.txt
    if errorlevel 1 (
        echo [WARN] pip install requirements.txt gagal. Lanjut.
    )
)

if exist "pyproject.toml" (
    echo === pip install -e . ^(local install^) ===
    python -m pip install --upgrade -e .
    if errorlevel 1 (
        echo [WARN] pip install -e . gagal. Coba manual:
        echo        cd /d "%~dp0"
        echo        python -m pip install -e .
    )
)
:pipdone

echo.
echo ======================================================================
echo   UPDATE SELESAI
echo ======================================================================
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do echo  Branch : %%b
for /f "delims=" %%c in ('git log -1 --oneline') do echo  Commit : %%c
echo.
echo  Verifikasi cepat:
python -c "from cyberloka.scanner import MODULE_MAP; print('   - Total modul scanner :', len(MODULE_MAP))" 2>nul
python -c "import reportlab; print('   - reportlab           :', reportlab.Version)" 2>nul
python -c "from cyberloka.reporting import pdf_report, extras, scenarios; print('   - PDF reporter        : OK')" 2>nul
echo.
pause
goto menu

REM =====================================================================
:end
echo Sampai jumpa.
endlocal
exit /b 0
