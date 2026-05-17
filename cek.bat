@echo off
rem Cyberloka - pemeriksa kerentanan website (mode super sederhana, Windows)
rem
rem Cukup masukkan domain atau IP, tool akan otomatis:
rem   1) install dependency yang dibutuhkan
rem   2) scan website (mode passive yang aman)
rem   3) cetak: "Website ini rentan / aman" + daftar celah dalam bahasa Indonesia
rem
rem Pemakaian:
rem   cek.bat example.com
rem   cek.bat https://example.com aktif
rem
rem WAJIB: hanya gunakan untuk website yang Anda miliki / yang memberi izin.

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo.
    echo Cyberloka - pemeriksa kerentanan website
    echo.
    echo Cara pakai:
    echo     cek.bat ^<domain-atau-ip^>           # mode aman ^(passive^)
    echo     cek.bat ^<domain-atau-ip^> aktif     # tambah scan aktif
    echo.
    echo Contoh:
    echo     cek.bat example.com
    echo     cek.bat https://target-anda.com aktif
    exit /b 2
)

set TARGET=%~1
set MODE_INPUT=%~2

if /i "%MODE_INPUT%"=="aktif" (set MODE=active) else (
if /i "%MODE_INPUT%"=="active" (set MODE=active) else (
if /i "%MODE_INPUT%"=="full" (set MODE=full) else (
if /i "%MODE_INPUT%"=="lengkap" (set MODE=full) else (set MODE=passive))))

rem Tambahkan https:// kalau belum ada
echo %TARGET% | findstr /b /i "http://" >nul
if errorlevel 1 (
    echo %TARGET% | findstr /b /i "https://" >nul
    if errorlevel 1 set TARGET=https://%TARGET%
)

cd /d "%~dp0"

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
for /f "tokens=2 delims==" %%a in ('wmic OS Get LocalDateTime /value ^| find "="') do set DT=%%a
set TS=!DT:~0,8!_!DT:~8,6!
set SAFE=%TARGET:https://=%
set SAFE=!SAFE:http://=!
set SAFE=!SAFE:/=_!
set SAFE=!SAFE::=_!
set JSON_OUT=reports\!SAFE!_!TS!.json
set HTML_OUT=reports\!SAFE!_!TS!.html
set TXT_OUT=reports\!SAFE!_!TS!.txt

set EXTRA=
if not "%MODE%"=="passive" set EXTRA=--authorized --yes --crawl

python -m cyberloka -t "%TARGET%" --mode %MODE% %EXTRA% --json "!JSON_OUT!" --html "!HTML_OUT!" --narrative "!TXT_OUT!" --quiet

echo.
echo Laporan tersimpan di:
echo    !TXT_OUT!   ^(ringkasan teks^)
echo    !HTML_OUT!  ^(laporan visual^)
echo    !JSON_OUT!  ^(data terstruktur^)

endlocal
