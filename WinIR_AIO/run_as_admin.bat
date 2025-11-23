@echo off
title WinIR-AIO v2.0 (Admin)

REM Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Requesting administrator privileges...
    echo.
    
    REM Create a VBScript to elevate
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /b
)

echo ========================================
echo   WinIR-AIO - Windows Incident Response
echo   Running with Administrator Privileges
echo ========================================
echo.

cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.10 or higher
    pause
    exit /b 1
)

REM Install requirements if needed
echo [INFO] Checking dependencies...
pip show PySide6 >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Installing required packages...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Run the application
echo.
echo [INFO] Starting WinIR-AIO with admin privileges...
echo ----------------------------------------
python main.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Application exited with error
)

pause
exit /b %errorlevel%
