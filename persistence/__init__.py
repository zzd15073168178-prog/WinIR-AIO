#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
持久化检测模块（重构版本）
整合所有持久化检测功能，提供向后兼容的接口
"""

from .persistence_detector import PersistenceDetector
from . import registry_detector
from . import scheduled_task_detector
from . import service_detector
from . import wmi_detector
from . import system_detector
from . import browser_detector

__all__ = ['PersistenceDetector']