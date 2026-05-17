@echo off
REM ============================================================
REM  Cyberloka - Feature Check Script (Windows)
REM ============================================================
REM  Verifikasi semua fitur (login session, TXT/PDF report,
REM  menu interaktif, dashboard, verify deep re-test, dll.)
REM  bisa berjalan di environment Anda.
REM ============================================================

setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

echo.
echo ============================================================
echo   CYBERLOKA - Feature Check
echo ============================================================
echo.

REM 1. Cek Python
where python >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Python tidak ditemukan. Install Python 3.10+ dulu.
    goto :end
)
echo [OK]  Python tersedia
python --version

REM 2. Cek instalasi cyberloka
python -c "import cyberloka; print('  cyberloka', cyberloka.__version__)" 2>nul
if errorlevel 1 (
    echo [FAIL] Modul cyberloka belum terinstall.
    echo        Jalankan: python -m pip install -e ".[all]"
    goto :end
)

REM 3. Cek dependencies opsional
echo.
echo === Dependencies ===
python -c "import jinja2; print('[OK]  jinja2     ', jinja2.__version__)" 2>nul || echo [WARN] jinja2 missing -- HTML report tidak akan jalan
python -c "import flask;  print('[OK]  flask      ', flask.__version__)"  2>nul || echo [WARN] flask missing -- dashboard tidak akan jalan (install: pip install "cyberloka[dashboard]")
python -c "import reportlab; print('[OK]  reportlab  ', reportlab.Version)" 2>nul || echo [WARN] reportlab missing -- PDF report tidak akan jalan (install: pip install "cyberloka[pdf]")
python -c "import rich;   print('[OK]  rich       ', rich.__version__)"   2>nul || echo [FAIL] rich missing
python -c "import requests; print('[OK]  requests   ', requests.__version__)" 2>nul || echo [FAIL] requests missing

REM 4. Run offline smoke tests
echo.
echo === Smoke Tests (offline, no network) ===
echo.

if exist "scripts\smoke_test.py" (
    echo --- Risk + Compliance ---
    python scripts\smoke_test.py 2>nul | findstr /C:"All smoke checks passed" /C:"FAIL"
    if errorlevel 1 (
        echo [WARN] smoke_test.py gagal. Run manual: python scripts\smoke_test.py
    ) else (
        echo [OK]  Risk scoring + compliance + executive summary
    )
) else (
    echo [SKIP] scripts\smoke_test.py tidak ada
)

if exist "scripts\verify_smoke_test.py" (
    echo --- Verify (deep re-scan) ---
    python scripts\verify_smoke_test.py 2>nul | findstr /C:"All verify smoke checks passed" /C:"FAIL"
    if errorlevel 1 (
        echo [WARN] verify_smoke_test.py gagal.
    ) else (
        echo [OK]  Deep verification (9 modules)
    )
) else (
    echo [SKIP] scripts\verify_smoke_test.py tidak ada
)

if exist "scripts\feature_smoke_test.py" (
    echo --- Login session + TXT/PDF + menu + dashboard ---
    python scripts\feature_smoke_test.py 2>nul | findstr /C:"All feature smoke checks passed" /C:"FAIL"
    if errorlevel 1 (
        echo [WARN] feature_smoke_test.py gagal.
    ) else (
        echo [OK]  Login session + TXT/PDF reports + interactive menu
    )
) else (
    echo [SKIP] scripts\feature_smoke_test.py tidak ada
)

REM 5. Cek CLI commands tersedia
echo.
echo === CLI Commands ===
python -m cyberloka --version >nul 2>&1 && echo [OK]  python -m cyberloka          || echo [FAIL] python -m cyberloka
where cyberloka >nul 2>&1                && echo [OK]  cyberloka                    || echo [INFO] 'cyberloka' belum di PATH (pakai 'python -m cyberloka')
where cyberloka-dashboard >nul 2>&1      && echo [OK]  cyberloka-dashboard          || echo [INFO] 'cyberloka-dashboard' belum di PATH

REM 6. Buat folder reports
if not exist "reports" mkdir reports
echo.
echo === Folder Output ===
echo [OK]  reports\ siap dipakai

REM 7. Menu untuk coba live
echo.
echo ============================================================
echo   FITUR TERSEDIA - Pilih untuk dicoba
echo ============================================================
echo.
echo   1. Buka menu interaktif Cyberloka
echo   2. Quick scan passive ke target uji (httpbin.org)
echo   3. Buka dashboard di browser
echo   4. Tampilkan --help (semua opsi CLI)
echo   0. Keluar
echo.
set /p choice="Pilih [0-4]: "

if "%choice%"=="1" (
    python -m cyberloka --menu
    goto :end
)
if "%choice%"=="2" (
    set /p target="Target URL [https://httpbin.org]: "
    if "!target!"=="" set "target=https://httpbin.org"
    python -m cyberloka -t !target! --mode passive --reports-dir reports --txt --pdf --no-compliance
    echo.
    echo Lihat hasil di folder reports\
    goto :end
)
if "%choice%"=="3" (
    echo Memulai dashboard di http://127.0.0.1:5005/
    python -m cyberloka.dashboard.app --reports-dir reports --open
    goto :end
)
if "%choice%"=="4" (
    python -m cyberloka --help
    goto :end
)

:end
echo.
endlocal
pause
