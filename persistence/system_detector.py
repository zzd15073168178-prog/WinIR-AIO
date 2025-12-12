#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
系统持久化检测模块（启动文件夹等）
"""

import os
import winreg


class SystemDetector:
    """系统持久化检测器"""
    
    def get_startup_folders(self):
        """获取启动文件夹中的所有文件"""
        items = []
        
        # 启动文件夹路径
        startup_paths = [
            os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'),
        ]
        
        for folder in startup_paths:
            if os.path.exists(folder):
                try:
                    for item in os.listdir(folder):
                        item_path = os.path.join(folder, item)
                        items.append({
                            'folder': folder,
                            'name': item,
                            'path': item_path,
                            'is_file': os.path.isfile(item_path)
                        })
                except Exception as e:
                    print(f"[持久化检测] 读取启动文件夹失败 {folder}: {e}")
        
        return items
    
    def get_startup_approved(self):
        """StartupApproved由registry_detector处理"""
        return []