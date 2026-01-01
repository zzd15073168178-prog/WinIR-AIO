#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build script for PyInstaller - Sysmon GUI 打包工具"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def check_dependencies():
    """检查并安装依赖"""
    print("\n检查依赖...")

    # 检查 PyInstaller
    try:
        import PyInstaller
        print(f"  [OK] PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("  [!] 安装 PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller", "-q"])

    # 检查其他依赖
    deps = ['psutil', 'pywin32', 'pillow', 'ttkbootstrap', 'requests']
    for dep in deps:
        try:
            __import__(dep.replace('-', '_').split('[')[0])
            print(f"  [OK] {dep}")
        except ImportError:
            print(f"  [!] 安装 {dep}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep, "-q"])

    # 检查可选依赖
    try:
        import yara
        print(f"  [OK] yara-python")
    except ImportError:
        print(f"  [!] yara-python 未安装 (Yara扫描功能将不可用)")

    return True

def clean_build():
    """清理旧的构建文件"""
    print("\n清理旧构建...")
    for d in ['build', 'dist', '__pycache__']:
        if os.path.exists(d):
            shutil.rmtree(d)
            print(f"  删除 {d}/")
    for f in ['sysmon_gui.spec', 'SysmonGUI.spec']:
        if os.path.exists(f):
            os.remove(f)

def create_spec():
    """创建 PyInstaller spec 文件"""
    # 获取当前脚本所在目录的绝对路径
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # 检查哪些工具文件存在
    tools = ['handle.exe', 'Listdlls.exe', 'procdump.exe', 'Procmon.exe', 'autorunsc64.exe']
    existing_tools = [t for t in tools if os.path.exists(os.path.join(base_dir, t))]

    # 构建数据文件列表
    datas_lines = []

    # 添加工具文件
    for t in existing_tools:
        datas_lines.append(f"    ('{t}', '.')")

    # 添加 rules 目录（包含所有 .yar 文件）
    rules_dir = os.path.join(base_dir, 'rules')
    if os.path.exists(rules_dir) and os.listdir(rules_dir):
        # 添加整个 rules 目录
        datas_lines.append("    ('rules', 'rules')")
        print(f"  [OK] 找到 rules 目录，包含 {len([f for f in os.listdir(rules_dir) if f.endswith(('.yar', '.yara'))])} 个规则文件")

    datas_str = ',\n'.join(datas_lines)

    spec = f"""# -*- mode: python ; coding: utf-8 -*-
# Auto-generated spec file for Sysmon GUI

import os
block_cipher = None

# 数据文件 - Sysinternals 工具和 Yara 规则
added_files = [
{datas_str}
]

a = Analysis(
    ['sysmon_gui_new.py'],
    pathex=['.'],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        # tkinter 完整模块
        'tkinter', 'tkinter.ttk', 'tkinter.filedialog', 'tkinter.messagebox',
        'tkinter.scrolledtext', 'tkinter.font', 'tkinter.colorchooser',

        # ttkbootstrap 及其所有子模块
        'ttkbootstrap', 'ttkbootstrap.style', 'ttkbootstrap.themes',
        'ttkbootstrap.constants', 'ttkbootstrap.widgets', 'ttkbootstrap.dialogs',
        'ttkbootstrap.dialogs.colorchooser', 'ttkbootstrap.dialogs.dialogs',
        'ttkbootstrap.toast', 'ttkbootstrap.tooltip', 'ttkbootstrap.scrolled',
        'ttkbootstrap.tableview', 'ttkbootstrap.utility', 'ttkbootstrap.localization',
        'ttkbootstrap.icons', 'ttkbootstrap.publisher', 'ttkbootstrap.themes.standard',
        'ttkbootstrap.themes.user',

        # PIL/Pillow 完整模块 (ttkbootstrap 依赖)
        'PIL', 'PIL._imaging', 'PIL._tkinter_finder', 'PIL._imagingtk',
        'PIL.Image', 'PIL.ImageTk', 'PIL.ImageDraw', 'PIL.ImageFont',
        'PIL.ImageColor', 'PIL.ImageFilter', 'PIL.ImageGrab', 'PIL.ImageOps',
        'PIL.ImageSequence', 'PIL.ImageFile', 'PIL.BmpImagePlugin',
        'PIL.PngImagePlugin', 'PIL.JpegImagePlugin', 'PIL.GifImagePlugin',

        # 系统监控
        'psutil', 'psutil._pswindows',

        # Windows API
        'win32api', 'win32con', 'win32process', 'win32security', 'win32file',
        'win32event', 'win32gui', 'win32service', 'win32serviceutil',
        'pywintypes', 'pythoncom', 'wmi',

        # ctypes
        'ctypes', 'ctypes.wintypes',

        # 标准库
        'winreg', 'csv', 'json', 're', 'hashlib', 'urllib', 'urllib.request',
        'concurrent.futures', 'threading', 'queue', 'traceback', 'io',
        'pathlib', 'webbrowser', 'subprocess', 'datetime', 'typing',

        # 网络相关
        'requests', 'urllib3', 'certifi', 'charset_normalizer', 'idna',

        # 可选: Yara
        'yara',

        # 项目模块 - GUI (已移除: procmon_tab, persistence_tab, sandbox_tab, file_monitor_tab -> sandbox_project)
        'gui', 'gui.tabs', 'gui.main_window',
        'gui.tabs.base_tab', 'gui.tabs.process_tab', 'gui.tabs.process_tree_tab',
        'gui.tabs.network_tab', 'gui.tabs.dll_tab', 'gui.tabs.handle_tab',
        'gui.tabs.dump_tab', 'gui.tabs.security_tab',
        'gui.tabs.hash_tab', 'gui.tabs.file_locker_tab', 'gui.tabs.memory_scanner_tab',
        'gui.tabs.yara_tab', 'gui.tabs.process_trace_tab', 'gui.tabs.eventlog_tab',
        'gui.tabs.user_audit_tab',

        # 项目模块 - utils
        'utils', 'utils.network', 'utils.filesystem', 'utils.permissions',
        'utils.processes', 'utils.validation', 'utils.format',

        # 项目模块 - persistence
        'persistence', 'persistence.persistence_detector', 'persistence.registry_detector',
        'persistence.scheduled_task_detector', 'persistence.service_detector',
        'persistence.wmi_detector', 'persistence.system_detector', 'persistence.browser_detector',

        # 项目模块 - managers (已移除: monitor_manager, sandbox_manager -> sandbox_project)
        'console_logger', 'constants', 'exceptions', 'debug_console',
        'process_manager', 'network_manager', 'dll_manager', 'handle_manager',
        'dump_manager', 'security_manager', 'hash_manager',
        'file_locker', 'memory_scanner', 'memory_scanner_v2', 'yara_scanner', 'threat_intel',
        'process_history_manager', 'eventlog_manager', 'user_audit_manager',
        'report_generator', 'analysis_manager',

        # 简化版 GUI (备用)
        'sysmon_simple_gui',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        'matplotlib', 'numpy', 'pandas', 'scipy', 'pytest',
        'IPython', 'jupyter', 'notebook', 'sphinx', 'docutils',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SysmonGUI',
    debug=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=True,  # True 显示控制台便于调试，发布版可改为 False
    icon=None,
    uac_admin=True,  # 请求管理员权限
)
"""
    with open('SysmonGUI.spec', 'w', encoding='utf-8') as f:
        f.write(spec)
    print("  [OK] 创建 SysmonGUI.spec")

def build():
    """执行 PyInstaller 打包"""
    print("\n开始打包...")
    print("  (这可能需要几分钟，请耐心等待...)\n")

    cmd = [sys.executable, '-m', 'PyInstaller', '--clean', '--noconfirm', 'SysmonGUI.spec']
    result = subprocess.run(cmd)
    return result.returncode == 0

def copy_additional_files():
    """复制额外文件到输出目录"""
    print("\n复制额外文件...")
    dist = Path('dist')

    # 复制文档
    for name in ['README.md', 'README_使用指南.md', '持久化检测使用指南.md']:
        if os.path.exists(name):
            shutil.copy2(name, dist / name)
            print(f"  复制 {name}")

    # 创建工作目录
    for d in ['dumps', 'reports', 'procmon_logs']:
        (dist / d).mkdir(exist_ok=True)
        print(f"  创建 {d}/")

    # 复制 Yara 规则
    if os.path.exists('rules'):
        rules_dst = dist / 'rules'
        rules_dst.mkdir(exist_ok=True)
        for f in os.listdir('rules'):
            if f.endswith(('.yar', '.yara')):
                shutil.copy2(Path('rules') / f, rules_dst / f)
                print(f"  复制 rules/{f}")

def get_exe_size():
    """获取生成的 EXE 文件大小"""
    exe_path = Path('dist/SysmonGUI.exe')
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        return f"{size_mb:.1f} MB"
    return "未知"

def main():
    print("=" * 55)
    print("  Sysmon GUI 打包工具")
    print("  生成独立可执行文件")
    print("=" * 55)

    # 切换到脚本所在目录
    os.chdir(Path(__file__).parent)
    print(f"\n工作目录: {os.getcwd()}")

    # 检查主入口文件
    if not os.path.exists('sysmon_gui_new.py'):
        print("\n[错误] 找不到 sysmon_gui_new.py")
        sys.exit(1)

    check_dependencies()
    clean_build()
    create_spec()

    if build():
        copy_additional_files()
        exe_size = get_exe_size()

        print("\n" + "=" * 55)
        print("  [成功] 打包完成!")
        print("=" * 55)
        print(f"\n  输出文件: dist/SysmonGUI.exe")
        print(f"  文件大小: {exe_size}")
        print(f"\n  使用方法:")
        print(f"    1. 将 dist 文件夹复制到目标机器")
        print(f"    2. 右键 SysmonGUI.exe -> 以管理员身份运行")
        print(f"\n  注意: 首次运行可能需要较长时间解压")
        print("=" * 55)
    else:
        print("\n" + "=" * 55)
        print("  [失败] 打包失败")
        print("=" * 55)
        print("\n  请检查上方的错误信息")
        print("  常见问题:")
        print("    - 确保所有依赖已安装")
        print("    - 检查是否有语法错误")
        print("    - 尝试运行: python sysmon_gui_new.py 测试")
        sys.exit(1)

if __name__ == '__main__':
    main()

