@echo off
REM ====================================================================
REM  update.bat - shortcut update Cyberloka tanpa lewat menu.
REM  Sama dengan opsi 8 di cek.bat: git pull + pip install.
REM ====================================================================
setlocal
cd /d "%~dp0"
title Cyberloka - Update
chcp 65001 >nul 2>&1

where git >nul 2>nul
if errorlevel 1 (
    echo [ERROR] git tidak ditemukan di PATH.
    echo         Install Git for Windows: https://git-scm.com/download/win
    pause
    exit /b 1
)
git rev-parse --is-inside-work-tree >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Folder ini bukan git repository.
    pause
    exit /b 1
)

echo Branch aktif:
git rev-parse --abbrev-ref HEAD

REM Auto-stash jika ada perubahan lokal
set "STASHED=0"
git diff --quiet >nul 2>nul
if errorlevel 1 (
    echo [INFO] Ada perubahan lokal, di-stash sementara.
    git stash push -u -m "cyberloka-auto-stash" >nul
    set "STASHED=1"
)

echo === git fetch ===
git fetch --all --prune
echo === git pull ===
git pull --ff-only
if errorlevel 1 (
    echo [WARN] git pull gagal. Resolve konflik dulu.
    if "%STASHED%"=="1" git stash pop >nul 2>nul
    pause
    exit /b 1
)

if "%STASHED%"=="1" git stash pop >nul 2>nul

where python >nul 2>nul
if errorlevel 1 (
    echo [WARN] Python tidak ditemukan di PATH. Skip pip install.
) else (
    if exist requirements.txt (
        echo === pip install -r requirements.txt ===
        python -m pip install --upgrade -r requirements.txt
    )
    if exist pyproject.toml (
        echo === pip install -e . ^(local install^) ===
        python -m pip install --upgrade -e .
    )
)

echo.
echo ====================================================================
echo  UPDATE SELESAI
echo ====================================================================
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do echo  Branch : %%b
for /f "delims=" %%c in ('git log -1 --oneline') do echo  Commit : %%c
echo.
echo  Verifikasi cepat:
python -c "from cyberloka.scanner import MODULE_MAP; print('   - Total modul scanner :', len(MODULE_MAP))" 2>nul
python -c "import reportlab; print('   - reportlab           :', reportlab.Version)" 2>nul
python -c "from cyberloka.reporting import pdf_report, extras, scenarios; print('   - PDF reporter        : OK')" 2>nul
echo.
pause
endlocal
exit /b 0
