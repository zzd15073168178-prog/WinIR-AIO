@echo off
title Sysmon GUI Build Tool
cd /d "%~dp0"

echo ============================================================
echo                Sysmon GUI Build Tool
echo ============================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found
    pause
    exit /b 1
)

echo [INFO] Python detected
python --version
echo.

if not exist "build_exe.py" (
    echo [ERROR] build_exe.py not found
    pause
    exit /b 1
)

echo [INFO] Starting build...
echo.

python build_exe.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo Press any key to open dist folder...
pause >nul
explorer dist
exit /b 0

