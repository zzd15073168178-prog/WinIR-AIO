@echo off
title WinIR-AIO Automated Tests
echo ========================================
echo   WinIR-AIO Automated Test Suite
echo ========================================
echo.

REM Check if pytest is installed
python -c "import pytest" 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Installing test dependencies...
    pip install -r requirements-test.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install test dependencies
        pause
        exit /b 1
    )
)

echo [INFO] Running automated tests...
echo ----------------------------------------
echo.

REM Run all tests with coverage
python -m pytest tests/ -v --cov=src --cov-report=html --cov-report=term

echo.
echo ----------------------------------------
echo [INFO] Test execution complete
echo [INFO] Coverage report: htmlcov/index.html
echo.
pause

