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
if not errorlevel 1 (
    if exist requirements.txt python -m pip install --upgrade -q -r requirements.txt
    if exist pyproject.toml   python -m pip install --upgrade -q -e .
)

echo.
echo ====================================================================
echo  UPDATE SELESAI
echo ====================================================================
git log -1 --oneline
echo.
pause
endlocal
exit /b 0
