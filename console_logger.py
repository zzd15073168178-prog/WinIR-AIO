#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
控制台日志模块
"""

import sys
from datetime import datetime

CONSOLE_LOG_ENABLED = True

def console_log(message, level="INFO"):
    """输出日志到控制台"""
    if not CONSOLE_LOG_ENABLED:
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    clean_message = message
    for emoji in ['📋', '🔍', '🌐', '💉', '🔧', '💾', '📊', '🌲', '✅', '❌', '⚠️', '🔄', '📁', '📄', '🗑️', '▶️', '⏹️', '🛡️']:
        clean_message = clean_message.replace(emoji, '')
    level_markers = {'INFO': '[INFO]', 'WARN': '[WARN]', 'ERROR': '[ERROR]', 'DEBUG': '[DEBUG]', 'ACTION': '[ACTION]'}
    marker = level_markers.get(level, '[INFO]')
    print(f"{timestamp} {marker} {clean_message.strip()}")
    sys.stdout.flush()

def log_action(action, target="", details=""):
    """记录用户操作"""
    message = f"{action}: {target}" if target else action
    if details:
        message += f" ({details})"
    console_log(message, "ACTION")

def log_info(message):
    console_log(message, "INFO")

def log_warn(message):
    console_log(message, "WARN")

def log_error(message):
    console_log(message, "ERROR")

def log_separator(title=""):
    if title:
        print(f"\n{'='*20} {title} {'='*20}")
    else:
        print("=" * 50)
    sys.stdout.flush()

