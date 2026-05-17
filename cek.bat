@echo off
REM ============================================================
REM  Cyberloka - Feature Check Script (Windows)
REM  Pakai goto-labels (bukan nested if-blocks) supaya tidak
REM  kena bug CMD parser dengan parens di dalam echo.
REM ============================================================

setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

echo.
echo ============================================================
echo   CYBERLOKA - Feature Check
echo ============================================================
echo.

REM --- 1. Python ----------------------------------------------------------
where python >nul 2>&1
if errorlevel 1 goto :no_python
echo [OK]  Python tersedia
python --version
goto :check_pkg

:no_python
echo [FAIL] Python tidak ditemukan. Install Python 3.10+ dulu.
goto :end

REM --- 2. Cyberloka package ----------------------------------------------
:check_pkg
python -c "import cyberloka; print('  cyberloka', cyberloka.__version__)" 2>nul
if errorlevel 1 goto :no_pkg
goto :check_deps

:no_pkg
echo [FAIL] Modul cyberloka belum terinstall.
echo        Jalankan: python -m pip install -e ".[all]"
goto :end

REM --- 3. Optional dependencies ------------------------------------------
:check_deps
echo.
echo === Dependencies ===
call :check_dep jinja2    "HTML report"
call :check_dep flask     "Web Dashboard"
call :check_dep reportlab "PDF report"
call :check_dep rich      "console UI (REQUIRED)"
call :check_dep requests  "HTTP client (REQUIRED)"

REM --- 4. Smoke tests -----------------------------------------------------
echo.
echo === Smoke Tests (offline, no network) ===
echo.

if not exist "scripts\smoke_test.py" goto :skip_smoke1
echo Running risk + compliance test...
python scripts\smoke_test.py >nul 2>&1
if errorlevel 1 echo [WARN] smoke_test.py gagal
if not errorlevel 1 echo [OK]  Risk scoring + compliance + executive summary
goto :smoke2

:skip_smoke1
echo [SKIP] scripts\smoke_test.py tidak ada

:smoke2
if not exist "scripts\verify_smoke_test.py" goto :skip_smoke2
echo Running deep verify test...
python scripts\verify_smoke_test.py >nul 2>&1
if errorlevel 1 echo [WARN] verify_smoke_test.py gagal
if not errorlevel 1 echo [OK]  Deep verification module
goto :smoke3

:skip_smoke2
echo [SKIP] scripts\verify_smoke_test.py tidak ada

:smoke3
if not exist "scripts\feature_smoke_test.py" goto :skip_smoke3
echo Running login + TXT/PDF + menu test...
python scripts\feature_smoke_test.py >nul 2>&1
if errorlevel 1 echo [WARN] feature_smoke_test.py gagal
if not errorlevel 1 echo [OK]  Login session + TXT/PDF reports + menu
goto :cli_check

:skip_smoke3
echo [SKIP] scripts\feature_smoke_test.py tidak ada

REM --- 5. CLI commands ----------------------------------------------------
:cli_check
echo.
echo === CLI Commands ===
python -m cyberloka --version >nul 2>&1
if errorlevel 1 echo [FAIL] python -m cyberloka
if not errorlevel 1 echo [OK]  python -m cyberloka

where cyberloka >nul 2>&1
if errorlevel 1 echo [INFO] 'cyberloka' belum di PATH ^(pakai 'python -m cyberloka'^)
if not errorlevel 1 echo [OK]  cyberloka

where cyberloka-dashboard >nul 2>&1
if errorlevel 1 echo [INFO] 'cyberloka-dashboard' belum di PATH
if not errorlevel 1 echo [OK]  cyberloka-dashboard

REM --- 6. Reports folder --------------------------------------------------
if not exist "reports" mkdir reports
echo.
echo === Folder Output ===
echo [OK]  reports\ siap dipakai

REM --- 7. Action menu -----------------------------------------------------
:menu
echo.
echo ============================================================
echo   APA YANG MAU DICOBA?  (pilih nomor)
echo ============================================================
echo.
echo   1. Buka menu interaktif Cyberloka  [RECOMMENDED]
echo   2. Quick Scan   - passive, paling aman
echo   3. Full Scan    - recon + passive + active, butuh izin
echo   4. Buka Dashboard di browser
echo   5. Lihat laporan HTML terakhir
echo   6. Tampilkan --help
echo   0. Keluar
echo.
set /p choice="Pilih [0-6]: "

if "%choice%"=="1" goto :run_menu
if "%choice%"=="2" goto :run_quick
if "%choice%"=="3" goto :run_full
if "%choice%"=="4" goto :run_dashboard
if "%choice%"=="5" goto :run_view
if "%choice%"=="6" goto :run_help
if "%choice%"=="0" goto :end
echo Pilihan tidak dikenal.
goto :menu

:run_menu
python -m cyberloka --menu
goto :menu

:run_quick
echo.
set /p target=">> Masukkan domain/IP target: "
if "%target%"=="" goto :menu
python -m cyberloka -t %target% --mode passive --reports-dir reports --txt --pdf --yes
echo.
echo [OK] Scan selesai. Cek folder reports\
goto :menu

:run_full
echo.
echo [WARN] Full scan menjalankan probe aktif. Pastikan Anda berwenang.
echo.
set /p target=">> Masukkan domain/IP target: "
if "%target%"=="" goto :menu
python -m cyberloka -t %target% --mode full --authorized --reports-dir reports --txt --pdf --verify-after-scan --open-dashboard --yes
echo.
echo [OK] Scan selesai. Lihat dashboard atau folder reports\
goto :menu

:run_dashboard
echo.
echo Memulai dashboard di http://127.0.0.1:5005/
python -m cyberloka.dashboard.app --reports-dir reports --open
goto :menu

:run_view
echo.
echo Laporan HTML di folder reports\:
dir /B /O:-D reports\*.html 2>nul
echo.
echo Buka file HTML di browser dengan double-click di File Explorer.
goto :menu

:run_help
echo.
python -m cyberloka --help
goto :menu

REM --- Helper subroutine: check_dep <module> <description> ---------------
:check_dep
python -c "import %~1" 2>nul
if errorlevel 1 goto :dep_missing
for /f "delims=" %%v in ('python -c "import %~1; print(getattr(%~1, '__version__', getattr(%~1, 'Version', '?')))" 2^>nul') do echo [OK]  %~1 %%v
goto :eof

:dep_missing
echo [WARN] %~1 missing - %~2 tidak akan jalan
goto :eof

:end
echo.
endlocal
pause
