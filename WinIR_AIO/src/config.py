"""
Configuration module for WinIR-AIO
Contains paths, URLs, and constants for the application
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any

# Application metadata
APP_NAME = "WinIR-AIO"
APP_VERSION = "2.0.2"
APP_AUTHOR = "Cybersecurity Team"
APP_DESCRIPTION = "Windows Incident Response All-in-One Tool"

# Base paths
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    BASE_DIR = Path(sys.executable).parent
else:
    # Running as script
    BASE_DIR = Path(__file__).resolve().parent.parent

# Directory paths
BIN_DIR = BASE_DIR / "bin"
ASSETS_DIR = BASE_DIR / "assets"
TEMP_DIR = BASE_DIR / "temp"
LOGS_DIR = BASE_DIR / "logs"

# Ensure critical directories exist
BIN_DIR.mkdir(exist_ok=True)
TEMP_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# Sysinternals tools configuration
SYSINTERNALS_BASE_URL = "https://live.sysinternals.com"

SYSINTERNALS_TOOLS: Dict[str, Dict[str, Any]] = {
    "autorunsc": {
        "filename": "autorunsc.exe",
        "url": f"{SYSINTERNALS_BASE_URL}/autorunsc.exe",
        "required": True,
        "description": "Autoruns command-line version",
        "min_size": 500_000,  # Minimum expected file size in bytes
    },
    "sigcheck": {
        "filename": "sigcheck.exe",
        "url": f"{SYSINTERNALS_BASE_URL}/sigcheck.exe",
        "required": True,
        "description": "File version and signature viewer",
        "min_size": 300_000,
    },
    "tcpview": {
        "filename": "tcpview.exe",
        "url": f"{SYSINTERNALS_BASE_URL}/tcpview.exe",
        "required": False,
        "description": "TCP and UDP endpoint viewer",
        "min_size": 200_000,
    },
    "handle": {
        "filename": "handle.exe",
        "url": f"{SYSINTERNALS_BASE_URL}/handle.exe",
        "required": False,
        "description": "Handle and DLL viewer",
        "min_size": 200_000,
    },
}

# Network configuration
DOWNLOAD_TIMEOUT = 30  # seconds
DOWNLOAD_CHUNK_SIZE = 8192  # bytes
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

# Process configuration
PROCESS_TIMEOUT = 30  # seconds for subprocess operations
MAX_CONCURRENT_TASKS = 4

# UI Configuration
WINDOW_TITLE = f"{APP_NAME} v{APP_VERSION}"
WINDOW_MIN_WIDTH = 1200
WINDOW_MIN_HEIGHT = 700
SIDEBAR_WIDTH = 200

# Module icons (Font Awesome icons or custom)
MODULE_ICONS = {
    "dashboard": "📊",
    "process": "🔍",
    "network": "🌐",
    "persistence": "🔐",
    "logs": "📝",
}

# Encoding configuration for Windows
WINDOWS_ENCODING = "gbk"  # Default for Chinese Windows
FALLBACK_ENCODING = "utf-8"

# Log levels
LOG_LEVELS = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

# Export settings
EXPORT_FORMATS = ["CSV", "JSON", "HTML", "TXT"]
DEFAULT_EXPORT_FORMAT = "CSV"

# Theme colors
THEME = {
    "primary": "#2c3e50",
    "secondary": "#34495e",
    "accent": "#3498db",
    "success": "#27ae60",
    "warning": "#f39c12",
    "danger": "#e74c3c",
    "background": "#ecf0f1",
    "text": "#2c3e50",
    "text_light": "#7f8c8d",
}

# WMI Query timeout
WMI_TIMEOUT = 10  # seconds

# Admin check
def is_admin() -> bool:
    """Check if running with administrator privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Get tool path
def get_tool_path(tool_name: str) -> Path:
    """Get the full path to a Sysinternals tool"""
    if tool_name in SYSINTERNALS_TOOLS:
        return BIN_DIR / SYSINTERNALS_TOOLS[tool_name]["filename"]
    raise ValueError(f"Unknown tool: {tool_name}")

# Check if tool exists
def tool_exists(tool_name: str) -> bool:
    """Check if a Sysinternals tool exists locally"""
    tool_path = get_tool_path(tool_name)
    if not tool_path.exists():
        return False
    # Also check minimum size to ensure it's not corrupted
    min_size = SYSINTERNALS_TOOLS[tool_name].get("min_size", 0)
    return tool_path.stat().st_size >= min_size
