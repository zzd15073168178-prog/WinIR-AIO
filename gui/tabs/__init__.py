#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI选项卡模块 - 应急响应安全分析
模块化设计，各功能拆分为独立选项卡

已剥离到 sandbox_project:
- ProcmonTab (Procmon监控)
- PersistenceTab (持久化检测)
- SandboxTab (行为沙箱)
- FileMonitorTab (文件监控)
"""

from .base_tab import BaseTab
from .process_tab import ProcessTab
from .process_tree_tab import ProcessTreeTab
from .network_tab import NetworkTab
from .dll_tab import DllTab
from .handle_tab import HandleTab
from .dump_tab import DumpTab
from .security_tab import SecurityTab
from .hash_tab import HashTab
from .file_locker_tab import FileLockerTab
from .memory_scanner_tab import MemoryScannerTab
from .yara_tab import YaraTab
from .process_trace_tab import ProcessTraceTab
from .eventlog_tab import EventLogTab
from .user_audit_tab import UserAuditTab

__all__ = [
    'BaseTab',
    'ProcessTab',
    'ProcessTreeTab',
    'NetworkTab',
    'DllTab',
    'HandleTab',
    'DumpTab',
    'SecurityTab',
    'HashTab',
    'FileLockerTab',
    'MemoryScannerTab',
    'YaraTab',
    'ProcessTraceTab',
    'EventLogTab',
    'UserAuditTab',
]