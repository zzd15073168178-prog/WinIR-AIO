@echo off
title Sysinternals GUI Launcher

echo ================================================
echo   Sysinternals Tools GUI Launcher
echo ================================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found!
    echo.
    echo Please install Python 3.6 or higher
    echo Download: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [OK] Python installed:
python --version

echo.
echo Starting GUI application...
echo.

python sysinternals_gui.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Program failed to run!
    echo.
    pause
)

