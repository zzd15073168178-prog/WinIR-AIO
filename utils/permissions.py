#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
权限检查模块
"""

import ctypes


def is_admin():
    """检查是否以管理员身份运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False