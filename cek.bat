@echo off
rem Cyberloka - pemeriksa kerentanan website (mode interaktif, Windows)
rem
rem Cukup jalankan, masukkan domain/IP, lalu pilih mode 1/2/3.
rem
rem WAJIB: hanya gunakan untuk website yang Anda miliki / yang memberi izin.

setlocal enabledelayedexpansion

set TARGET=%~1
set MODE_INPUT=%~2

echo.
echo ============================================================
echo   CYBERLOKA - Pemeriksa Kerentanan Website
echo ============================================================
echo.

rem Minta target bila belum dikasih
if "%TARGET%"=="" (
    set /p "TARGET=Masukkan domain atau IP target: "
)

if "%TARGET%"=="" (
    echo Target tidak boleh kosong. Dibatalkan.
    exit /b 2
)

rem Tampilkan menu mode bila belum dikasih
if "%MODE_INPUT%"=="" (
    echo.
    echo Pilih mode scan:
    echo   [1] PASSIVE  - paling aman, hanya membaca header/cookies/TLS
    echo                  ^(cocok untuk website apapun^)
    echo   [2] ACTIVE   - passive + crawler + cek SQLi/XSS/SSRF/JWT/dll.
    echo                  ^(butuh izin scan dari pemilik website^)
    echo   [3] FULL     - active + recon ^(DNS/port/subdomain/OpenAPI^)
    echo                  ^(paling lengkap, butuh izin scan^)
    echo.
    set /p "MODE_INPUT=Pilihan [1-3, default 1]: "
    if "!MODE_INPUT!"=="" set MODE_INPUT=1
)

rem Normalisasi mode
set MODE=passive
if "%MODE_INPUT%"=="1" set MODE=passive
if /i "%MODE_INPUT%"=="passive" set MODE=passive
if /i "%MODE_INPUT%"=="pasif" set MODE=passive
if /i "%MODE_INPUT%"=="p" set MODE=passive
if "%MODE_INPUT%"=="2" set MODE=active
if /i "%MODE_INPUT%"=="active" set MODE=active
if /i "%MODE_INPUT%"=="aktif" set MODE=active
if /i "%MODE_INPUT%"=="a" set MODE=active
if "%MODE_INPUT%"=="3" set MODE=full
if /i "%MODE_INPUT%"=="full" set MODE=full
if /i "%MODE_INPUT%"=="lengkap" set MODE=full
if /i "%MODE_INPUT%"=="l" set MODE=full

rem Tambahkan https:// kalau belum ada
echo %TARGET% | findstr /b /i "http://" >nul
if errorlevel 1 (
    echo %TARGET% | findstr /b /i "https://" >nul
    if errorlevel 1 set TARGET=https://%TARGET%
)

echo.
echo Target : %TARGET%
echo Mode   : %MODE%
echo.

cd /d "%~dp0"

rem Setup venv ^& deps
if not exist ".venv" (
    echo [setup] Menyiapkan environment Python...
    python -m venv .venv
)
call .venv\Scripts\activate.bat

python -c "import requests, rich, jinja2" 2>nul
if errorlevel 1 (
    echo [setup] Menginstall dependency...
    python -m pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
)

if not exist reports mkdir reports

rem Generate filename via Python (anti-error untuk semua locale Windows)
for /f "delims=" %%i in ('python -c "from datetime import datetime; print(datetime.now().strftime('%%Y%%m%%d_%%H%%M%%S'))"') do set "TS=%%i"

rem Sanitize target -> safe filename: hapus skema, ganti karakter terlarang dengan _
for /f "delims=" %%i in ('python -c "import sys,re; t=sys.argv[1]; t=re.sub(r'^https?://','',t); print(re.sub(r'[^A-Za-z0-9._-]','_',t))" "%TARGET%"') do set "SAFE=%%i"

set "JSON_OUT=reports\%SAFE%_%TS%.json"
set "HTML_OUT=reports\%SAFE%_%TS%.html"
set "TXT_OUT=reports\%SAFE%_%TS%.txt"

set EXTRA=
if not "%MODE%"=="passive" set EXTRA=--authorized --yes --crawl

echo Menjalankan scan, mohon tunggu...
echo.
python -m cyberloka -t "%TARGET%" --mode %MODE% %EXTRA% --json "%JSON_OUT%" --html "%HTML_OUT%" --narrative "%TXT_OUT%" --quiet

echo.
echo ============================================================
echo  HASIL SCAN
echo ============================================================
if exist "%TXT_OUT%" (
    type "%TXT_OUT%"
) else (
    echo [error] file laporan tidak terbuat. Cek pesan error di atas.
    exit /b 1
)

echo.
echo ============================================================
echo  Laporan tersimpan di:
echo    %TXT_OUT%   ^(ringkasan teks bahasa Indonesia^)
echo    %HTML_OUT%  ^(laporan visual, double-click untuk buka^)
echo    %JSON_OUT%  ^(data terstruktur^)
echo ============================================================

endlocal
