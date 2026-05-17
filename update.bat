@echo off
REM ============================================================
REM  Cyberloka - Update Script (Windows)
REM ============================================================
REM  Pull versi terbaru dari GitHub dan reinstall paket.
REM  Pakai ini SETELAH PR #4 di-merge ke main, atau ganti
REM  variabel BRANCH di bawah ke nama branch yang Anda mau.
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

REM 1. Cek prasyarat
where git >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git tidak ditemukan. Install dulu: https://git-scm.com/
    goto :end
)
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python tidak ditemukan. Install Python 3.10+ dulu.
    goto :end
)

REM 2. Pastikan kita di folder repo cyberloka
if not exist "pyproject.toml" (
    echo [ERROR] Jalankan update.bat dari dalam folder cyberloka.
    echo         Saat ini di: %CD%
    goto :end
)

REM 3. Stash perubahan lokal (kalau ada) supaya pull tidak konflik
echo [1/5] Menyimpan perubahan lokal sementara (jika ada)...
git stash push -u -m "auto-stash by update.bat" >nul 2>&1

REM 4. Fetch dan checkout branch
echo [2/5] Fetching dari GitHub...
git fetch origin
if errorlevel 1 (
    echo [ERROR] git fetch gagal. Cek koneksi internet / kredensial.
    goto :end
)

echo [3/5] Checkout branch %BRANCH%...
git checkout %BRANCH% 2>nul || git checkout -b %BRANCH% origin/%BRANCH%
git pull --ff-only origin %BRANCH%
if errorlevel 1 (
    echo [WARN] Fast-forward pull gagal. Mungkin ada konflik lokal.
    echo        Coba manual: git status
    goto :end
)

REM 5. Reinstall paket (editable + semua extras)
echo [4/5] Menginstall ulang dependencies...
python -m pip install --upgrade pip >nul
python -m pip install -e ".[all]"
if errorlevel 1 (
    echo [WARN] Install dengan extras [all] gagal. Mencoba tanpa extras...
    python -m pip install -e .
)

REM 6. Verifikasi
echo [5/5] Verifikasi instalasi...
python -m cyberloka --version
if errorlevel 1 (
    echo [ERROR] Cyberloka tidak bisa dijalankan.
    goto :end
)

echo.
echo ============================================================
echo   UPDATE SELESAI
echo ============================================================
echo.
echo   Coba fitur baru:
echo     cyberloka                    (menu interaktif)
echo     cyberloka --help             (semua opsi CLI)
echo     cek.bat                      (test semua fitur)
echo.

:end
endlocal
pause
