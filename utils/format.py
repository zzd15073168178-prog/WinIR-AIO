#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
格式化工具模块
"""

from datetime import datetime


def get_file_size_str(size_bytes):
    """将字节大小转换为可读字符串"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def format_timestamp(timestamp):
    """格式化时间戳"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def get_current_timestamp():
    """获取当前时间戳字符串"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')