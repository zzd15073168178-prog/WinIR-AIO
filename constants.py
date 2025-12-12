#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
常量定义模块
包含所有常量配置
"""

import os
import sys

def get_resource_path(relative_path):
    """
    获取资源文件的绝对路径
    兼容开发环境和PyInstaller打包后的环境
    """
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller 打包后，资源文件在临时目录
        base_path = sys._MEIPASS
    else:
        # 开发环境，使用脚本所在目录
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# ==================== 可疑端口列表 ====================
SUSPICIOUS_PORTS = [
    4444, 4445, 5555, 6666, 7777, 8888, 9999,
    31337, 12345, 54321, 1337, 3389,
    6667, 6668, 6669,
]

# ==================== 可疑进程列表 ====================
SUSPICIOUS_PROCESSES = [
    'notepad.exe', 'calc.exe', 'mspaint.exe',
    'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'
]

# ==================== 系统进程列表 ====================
SYSTEM_PROCESSES = [
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
    'lsass.exe', 'svchost.exe', 'winlogon.exe'
]

# ==================== 标准端口列表 ====================
STANDARD_PORTS = [80, 443, 22, 21, 25, 110, 143, 3389, 3306, 5432, 8080, 8443]

# ==================== API配置 ====================
IP_LOCATION_API = "http://ip-api.com/json/{ip}?lang=zh-CN"
IP_LOCATION_TIMEOUT = 2

# ==================== 目录配置 ====================
PROCMON_LOGS_DIR = 'procmon_logs'
REPORTS_DIR = 'reports'
DUMPS_DIR = 'dumps'

# ==================== 系统目录列表 ====================
SYSTEM_DIRECTORIES = [
    r'C:\WINDOWS\SYSTEM32',
    r'C:\WINDOWS\SYSWOW64',
    r'C:\WINDOWS\WINSXS',
    r'C:\WINDOWS',
    r'C:\PROGRAM FILES',
    r'C:\PROGRAM FILES (X86)',
]

# ==================== 可疑路径关键词 ====================
SUSPICIOUS_PATH_KEYWORDS = [
    'TEMP', 'TMP', 'DOWNLOADS', 'DESKTOP', 'PUBLIC',
    'APPDATA\\LOCAL\\TEMP', 'RECYCLER', 'RECYCLE.BIN'
]

# ==================== 可疑文件扩展名 ====================
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
    '.hta', '.scr', '.pif', '.com', '.msi', '.jar'
]

# ==================== 工具路径配置 ====================
def get_tool_path(tool_name):
    """获取工具文件的完整路径"""
    tool_files = {
        'listdlls': 'Listdlls.exe',
        'handle': 'handle.exe',
        'procdump': 'procdump.exe',
        'procmon': 'Procmon.exe',
    }
    if tool_name not in tool_files:
        return None
    return get_resource_path(tool_files[tool_name])

TOOLS = {
    'listdlls': get_resource_path('Listdlls.exe'),
    'handle': get_resource_path('handle.exe'),
    'procdump': get_resource_path('procdump.exe'),
    'procmon': get_resource_path('Procmon.exe'),
}

# ==================== UI配置 ====================
WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 900
REFRESH_INTERVAL = 5
MAX_LOG_LINES = 1000

# ==================== 性能阈值配置 ====================
THRESHOLDS = {
    'cpu_warning': 80,
    'memory_warning': 50,
    'suspicious_connections': 10,
    'max_processes_tracked': 100,
}

TIMEOUTS = {
    'ip_location': 2,
    'process_query': 5,
    'network_scan': 10,
    'analysis_operation': 30,
}

