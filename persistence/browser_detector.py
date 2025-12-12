#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
浏览器持久化检测模块
"""

import os


class BrowserDetector:
    """浏览器扩展检测器"""
    
    def get_extensions(self):
        """获取浏览器扩展（Chrome）"""
        extensions = []
        
        # Chrome扩展路径
        chrome_ext_path = os.path.expandvars(
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions'
        )
        
        if os.path.exists(chrome_ext_path):
            try:
                for ext_id in os.listdir(chrome_ext_path):
                    ext_path = os.path.join(chrome_ext_path, ext_id)
                    if os.path.isdir(ext_path):
                        extensions.append({
                            'browser': 'Chrome',
                            'id': ext_id,
                            'path': ext_path
                        })
            except Exception as e:
                print(f"[持久化检测] 读取Chrome扩展失败: {e}")
        
        return extensions