#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI模块 - Sysinternals工具图形界面
模块化设计，各功能拆分为独立选项卡
"""

from .tabs.base_tab import BaseTab
from .tabs.process_tab import ProcessTab
from .tabs.process_tree_tab import ProcessTreeTab
from .tabs.network_tab import NetworkTab
from .tabs.dll_tab import DllTab
from .tabs.handle_tab import HandleTab
from .tabs.dump_tab import DumpTab
from .tabs.procmon_tab import ProcmonTab

__all__ = [
    'BaseTab',
    'ProcessTab',
    'ProcessTreeTab',
    'NetworkTab',
    'DllTab',
    'HandleTab',
    'DumpTab',
    'ProcmonTab',
]