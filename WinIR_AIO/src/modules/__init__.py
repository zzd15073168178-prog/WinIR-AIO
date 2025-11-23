"""Modules package for WinIR-AIO"""

from .base_module import BaseModule
from .dashboard import DashboardModule
from .process import ProcessModule
from .network import NetworkModule
from .persistence import PersistenceModule
from .logs import LogsModule

__all__ = [
    'BaseModule',
    'DashboardModule',
    'ProcessModule',
    'NetworkModule',
    'PersistenceModule',
    'LogsModule'
]
