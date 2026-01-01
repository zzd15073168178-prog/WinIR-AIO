#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sysinternals Tools GUI - System Monitor
"""

import os
import sys
import traceback

# 设置控制台编码为 UTF-8，解决中文乱码
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    os.system('chcp 65001 >nul 2>&1')


def show_error_and_wait(error_msg, full_traceback=None):
    """显示错误信息并等待用户按键"""
    print("")
    print("=" * 70)
    print("  [ERROR] 程序启动失败")
    print("=" * 70)
    print("")
    print(f"错误信息: {error_msg}")
    print("")
    if full_traceback:
        print("详细错误:")
        print("-" * 70)
        print(full_traceback)
        print("-" * 70)
    print("")
    print("可能的解决方案:")
    print("  1. 确保以管理员身份运行")
    print("  2. 检查是否缺少依赖库")
    print("  3. 检查 Python 版本兼容性")
    print("")
    input("按 Enter 键退出...")


def check_ttkbootstrap_available():
    """检查 ttkbootstrap 是否可用"""
    try:
        import PIL
        import ttkbootstrap
        return True
    except ImportError:
        return False


def run_full_gui():
    """运行完整版 GUI (ttkbootstrap)"""
    from console_logger import log_separator, log_info

    log_info("启动完整版 GUI (ttkbootstrap)...")
    log_separator("Starting GUI")

    log_info("Step 1: Importing ttkbootstrap...")
    import ttkbootstrap as ttk
    log_info("Step 1: OK")

    log_info("Step 2: Creating Window...")
    root = ttk.Window(themename='litera')
    log_info("Step 2: OK")

    log_info("Step 3: Importing SysmonGUI...")
    from gui.main_window import SysmonGUI
    log_info("Step 3: OK")

    log_info("Step 4: Creating SysmonGUI instance...")
    app = SysmonGUI(root)
    log_info("Step 4: OK")

    log_info("Application running...")
    print("-" * 60)
    print("")

    root.mainloop()

    print("")
    log_separator("Application Closed")


def run_simple_gui():
    """运行简化版 GUI (纯 tkinter)"""
    from console_logger import log_separator, log_info

    log_info("ttkbootstrap/PIL 不可用，启动简化版 GUI...")
    log_separator("Starting Simple GUI")

    # 导入简化版 GUI
    from sysmon_simple_gui import main as simple_main
    simple_main()


def main():
    print("")
    print("=" * 60)
    print("  Sysinternals Tools GUI - System Monitor")
    print("=" * 60)
    print("")

    try:
        # 延迟导入，以便捕获导入错误
        from console_logger import log_separator, log_info

        log_info("Initializing application...")
        log_info(f"Python: {sys.version.split()[0]}")
        log_info(f"Working dir: {os.getcwd()}")
        print("")

        # 检查 ttkbootstrap 是否可用
        if check_ttkbootstrap_available():
            run_full_gui()
        else:
            log_info("[WARN] PIL/ttkbootstrap 不可用，自动切换到简化版 GUI")
            run_simple_gui()

    except ImportError as e:
        tb = traceback.format_exc()
        # 如果是 PIL 相关错误，尝试简化版
        if 'PIL' in str(e) or 'ttkbootstrap' in str(e):
            print(f"[WARN] {e}")
            print("[INFO] 尝试启动简化版 GUI...")
            try:
                run_simple_gui()
                return
            except Exception as e2:
                tb2 = traceback.format_exc()
                show_error_and_wait(f"简化版 GUI 也启动失败: {e2}", tb2)
                sys.exit(1)
        else:
            show_error_and_wait(f"导入模块失败: {e}", tb)
            sys.exit(1)
    except Exception as e:
        tb = traceback.format_exc()
        show_error_and_wait(f"程序异常: {e}", tb)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        tb = traceback.format_exc()
        show_error_and_wait(f"未捕获的异常: {e}", tb)
        sys.exit(1)

