@echo off
chcp 65001 >nul 2>&1

:: Check admin rights
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting admin privileges...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
)

pushd "%CD%"
CD /D "%~dp0"

echo ============================================================
echo   Sysmon 应急响应工具 - 以管理员身份运行
echo ============================================================
echo.
echo   [1] 完整版 GUI (美化界面，需要 ttkbootstrap)
echo   [2] 简化版 GUI (纯 Tkinter，无额外依赖)
echo   [3] 命令行工具 (CLI)
echo.
set /p choice="请选择启动方式 (1/2/3): "

if "%choice%"=="1" (
    echo.
    echo 启动完整版 GUI...
    python sysmon_gui_new.py
) else if "%choice%"=="2" (
    echo.
    echo 启动简化版 GUI...
    python sysmon_simple_gui.py
) else if "%choice%"=="3" (
    echo.
    echo 进入命令行模式...
    echo 输入 python sysmon_cli.py --help 查看帮助
    echo.
    cmd /k
) else (
    echo.
    echo 默认启动简化版 GUI...
    python sysmon_simple_gui.py
)

if errorlevel 1 (
    echo.
    echo 启动失败！请检查依赖：pip install -r requirements.txt
    pause
)
