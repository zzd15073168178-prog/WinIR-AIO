@echo off
title WinIR-AIO v2.0
echo ========================================
echo   WinIR-AIO - Windows Incident Response
echo   All-in-One Tool v2.0
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.10 or higher
    pause
    exit /b 1
)

REM Check for virtual environment
if exist "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo [INFO] No virtual environment found
    echo [INFO] Consider creating one: python -m venv venv
)

REM Install requirements if needed
echo.
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
echo [INFO] Starting WinIR-AIO...
echo ----------------------------------------
python main.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Application exited with error
    pause
)

exit /b %errorlevel%
