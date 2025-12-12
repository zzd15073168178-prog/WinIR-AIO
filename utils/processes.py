#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程操作模块
"""

import psutil
from constants import SYSTEM_PROCESSES, SUSPICIOUS_PROCESSES


def is_system_process(proc_name):
    """判断是否为系统进程"""
    return proc_name.lower() in [p.lower() for p in SYSTEM_PROCESSES]


def is_suspicious_process_name(proc_name):
    """判断进程名是否可疑"""
    return proc_name.lower() in [p.lower() for p in SUSPICIOUS_PROCESSES]


def get_process_info(pid):
    """获取进程详细信息"""
    try:
        proc = psutil.Process(pid)
        return {
            'pid': pid,
            'name': proc.name(),
            'exe': proc.exe(),
            'cmdline': ' '.join(proc.cmdline()),
            'cwd': proc.cwd(),
            'status': proc.status(),
            'username': proc.username(),
            'create_time': proc.create_time(),
            'cpu_percent': proc.cpu_percent(),
            'memory_percent': proc.memory_percent(),
            'num_threads': proc.num_threads(),
            'num_handles': proc.num_handles() if hasattr(proc, 'num_handles') else 0,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def get_process_parent(pid):
    """获取进程的父进程"""
    try:
        proc = psutil.Process(pid)
        return proc.ppid()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def get_process_children(pid):
    """获取进程的子进程列表"""
    try:
        proc = psutil.Process(pid)
        return [child.pid for child in proc.children(recursive=False)]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []