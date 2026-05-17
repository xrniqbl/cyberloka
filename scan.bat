@echo off
rem Cyberloka one-shot scanner wrapper (Windows)
rem
rem Pemakaian:
rem    scan.bat https://target-anda.com [mode]
rem mode: passive (default) | active | full
rem
rem WAJIB: hanya scan target yang Anda miliki / izinkan.

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: %0 ^<https://target.com^> [passive^|active^|full]
    echo.
    echo Contoh:
    echo     %0 https://target-anda.com passive
    echo     %0 http://localhost:3000 active
    exit /b 2
)

set TARGET=%~1
set MODE=%~2
if "%MODE%"=="" set MODE=passive

cd /d "%~dp0"

rem 1) venv
if not exist ".venv" (
    echo [setup] Membuat virtualenv...
    python -m venv .venv
)
call .venv\Scripts\activate.bat

rem 2) deps
python -c "import requests, rich, jinja2" 2>nul
if errorlevel 1 (
    echo [setup] Menginstall dependency...
    python -m pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
)

rem 3) prep output
if not exist reports mkdir reports
for /f "tokens=2 delims==" %%a in ('wmic OS Get LocalDateTime /value ^| find "="') do set DT=%%a
set TS=!DT:~0,8!_!DT:~8,6!
set HOST_SAFE=%TARGET:https://=%
set HOST_SAFE=!HOST_SAFE:http://=!
set HOST_SAFE=!HOST_SAFE:/=_!
set HOST_SAFE=!HOST_SAFE::=_!
set JSON_OUT=reports\!HOST_SAFE!_!TS!.json
set HTML_OUT=reports\!HOST_SAFE!_!TS!.html

echo.
echo ============================================================
echo  CYBERLOKA - Web Vulnerability Scan
echo  target : %TARGET%
echo  mode   : %MODE%
echo  output : !JSON_OUT!
echo           !HTML_OUT!
echo ============================================================
echo.

set EXTRA=
if not "%MODE%"=="passive" set EXTRA=--authorized --yes --crawl

python -m cyberloka -t "%TARGET%" --mode %MODE% %EXTRA% --json "!JSON_OUT!" --html "!HTML_OUT!" --quiet

echo.
echo ============================================================
if exist "!JSON_OUT!" (
    python -c "import json; d=json.load(open(r'!JSON_OUT!')); s=d.get('summary',{}).get('by_severity',{}); print(' Total finding :', d.get('summary',{}).get('total',0)); [print(f'  {k.upper():8s}: {s.get(k,0)}') for k in ('critical','high','medium','low','info')]"
)
echo ============================================================
echo.
echo   HTML report: !HTML_OUT!
echo   JSON report: !JSON_OUT!
echo.
echo   Untuk diff:
echo     python -m cyberloka diff old.json !JSON_OUT!
echo.

endlocal
