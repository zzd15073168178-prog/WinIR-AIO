#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI选项卡模块
模块化设计，各功能拆分为独立选项卡
"""

from .base_tab import BaseTab
from .process_tab import ProcessTab
from .process_tree_tab import ProcessTreeTab
from .network_tab import NetworkTab
from .dll_tab import DllTab
from .handle_tab import HandleTab
from .dump_tab import DumpTab
from .procmon_tab import ProcmonTab
from .security_tab import SecurityTab
from .hash_tab import HashTab
from .file_locker_tab import FileLockerTab
from .memory_scanner_tab import MemoryScannerTab
from .yara_tab import YaraTab
from .process_trace_tab import ProcessTraceTab
from .eventlog_tab import EventLogTab
from .persistence_tab import PersistenceTab
from .user_audit_tab import UserAuditTab
from .sandbox_tab import SandboxTab
from .file_monitor_tab import FileMonitorTab

__all__ = [
    'BaseTab',
    'ProcessTab',
    'ProcessTreeTab',
    'NetworkTab',
    'DllTab',
    'HandleTab',
    'DumpTab',
    'ProcmonTab',
    'SecurityTab',
    'HashTab',
    'FileLockerTab',
    'MemoryScannerTab',
    'YaraTab',
    'ProcessTraceTab',
    'EventLogTab',
    'PersistenceTab',
    'UserAuditTab',
    'SandboxTab',
    'FileMonitorTab',
]