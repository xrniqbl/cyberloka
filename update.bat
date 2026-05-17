@echo off
REM ============================================================
REM  Cyberloka - Update Script (Windows)
REM ============================================================
REM  Pull versi terbaru dari GitHub, hapus cache stale,
REM  reinstall paket, lalu verifikasi.
REM ============================================================

setlocal EnableDelayedExpansion

REM Branch yang akan di-pull. Ubah ke "main" setelah PR di-merge.
set "BRANCH=feat/risk-compliance-dashboard"

echo.
echo ============================================================
echo   CYBERLOKA - Update dari GitHub
echo ============================================================
echo   Branch: %BRANCH%
echo.

REM --- 1. Cek prasyarat ----------------------------------------
where git >nul 2>&1
if errorlevel 1 goto :no_git
where python >nul 2>&1
if errorlevel 1 goto :no_python

if not exist "pyproject.toml" goto :wrong_dir

REM --- 2. Stash perubahan lokal --------------------------------
echo [1/6] Menyimpan perubahan lokal sementara (jika ada)...
git stash push -u -m "auto-stash by update.bat" >nul 2>&1

REM --- 3. Fetch dan checkout branch ----------------------------
echo [2/6] Fetching dari GitHub...
git fetch origin
if errorlevel 1 goto :fetch_fail

echo [3/6] Checkout branch %BRANCH%...
git checkout %BRANCH% 2>nul
if errorlevel 1 git checkout -b %BRANCH% origin/%BRANCH%
git pull --ff-only origin %BRANCH%
if errorlevel 1 goto :pull_fail

REM --- 4. Hapus cache stale (mencegah ImportError aneh) -------
echo [4/6] Menghapus cache stale (__pycache__, *.pyc)...
for /d /r %%i in (__pycache__) do @if exist "%%i" rd /s /q "%%i"
del /s /q *.pyc 2>nul

REM --- 5. Reinstall paket --------------------------------------
echo [5/6] Menginstall ulang dependencies...
python -m pip install --upgrade pip >nul
python -m pip install -e ".[all]" --force-reinstall --no-deps
if errorlevel 1 goto :install_extras_fail
python -m pip install -e ".[all]"
if errorlevel 1 goto :install_fail
goto :verify

:install_extras_fail
echo [WARN] Install dengan extras [all] gagal. Mencoba tanpa extras...
python -m pip install -e .
if errorlevel 1 goto :install_fail

REM --- 6. Verifikasi -------------------------------------------
:verify
echo [6/6] Verifikasi instalasi...
python -m cyberloka --version
if errorlevel 1 goto :verify_fail

REM Cek module baru ter-load
python -c "from cyberloka.core.threat_intel import list_supported_modules; print('  threat_intel:', len(list_supported_modules()), 'modul')" 2>nul
if errorlevel 1 echo [WARN] threat_intel module belum ter-load -- restart CMD lalu coba lagi.

python -c "from cyberloka.scanner import get_last_module_stats; print('  module stats: OK')" 2>nul
if errorlevel 1 echo [WARN] module stats belum ter-load -- restart CMD lalu coba lagi.

echo.
echo ============================================================
echo   UPDATE SELESAI
echo ============================================================
echo.
echo   Coba fitur baru:
echo     cyberloka                    (menu interaktif)
echo     cyberloka --list-modules     (lihat 21 modul deteksi)
echo     cek.bat                      (test semua fitur)
echo.
goto :end

REM --- Error handlers (no nested parens, CMD-safe) ------------
:no_git
echo [ERROR] Git tidak ditemukan. Install dulu: https://git-scm.com/
goto :end

:no_python
echo [ERROR] Python tidak ditemukan. Install Python 3.10+ dulu.
goto :end

:wrong_dir
echo [ERROR] Jalankan update.bat dari dalam folder cyberloka.
echo         Saat ini di: %CD%
goto :end

:fetch_fail
echo [ERROR] git fetch gagal. Cek koneksi internet / kredensial.
goto :end

:pull_fail
echo [WARN] Fast-forward pull gagal. Mungkin ada konflik lokal.
echo        Coba manual: git status
goto :end

:install_fail
echo [ERROR] pip install gagal. Cek log di atas.
goto :end

:verify_fail
echo [ERROR] Cyberloka tidak bisa dijalankan setelah install.
echo         Mungkin perlu restart CMD untuk refresh PATH.
goto :end

:end
echo.
endlocal
pause
