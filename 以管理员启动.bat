@echo off

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title Sysinternals GUI [Administrator Mode]

echo ================================================
echo   Sysinternals Tools GUI Launcher
echo   [Administrator Mode]
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
echo [OK] Administrator privileges granted

echo.
echo Starting GUI application with admin rights...
echo.

cd /d "%~dp0"

python sysmon_gui_new.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Program failed to run!
    echo.
    pause
)

