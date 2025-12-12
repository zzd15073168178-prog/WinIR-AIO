#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLL管理模块
处理DLL注入检测功能
"""

import subprocess
import os
from utils import is_system_directory, get_dll_detailed_info
from constants import TOOLS
from utils.validation import sanitize_pid


class DLLManager:
    """DLL管理器"""

    def __init__(self):
        self.dll_list = []

    def detect_injection(self, pid):
        """检测DLL注入（别名方法）"""
        return self.check_dll_injection(pid)

    def check_dll_injection(self, pid):
        """检测DLL注入"""
        # 安全验证：验证 PID
        valid, safe_pid, error = sanitize_pid(pid)
        if not valid:
            return False, f"PID 验证失败: {error}", []

        # 检查工具是否存在
        if not os.path.exists(TOOLS['listdlls']):
            return False, f"未找到工具: {TOOLS['listdlls']}", []

        try:
            # 构建命令（使用列表形式）
            cmd = [TOOLS['listdlls'], '-accepteula', str(safe_pid)]

            # 安全执行：使用列表形式，禁用 shell
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=30,
                shell=False  # 关键：禁用 shell 解析
            )

            if result.returncode != 0:
                return False, f"执行失败: {result.stderr}", []

            # 解析输出
            dll_list = self.parse_dll_output(result.stdout, safe_pid)
            self.dll_list = dll_list

            return True, "查询成功", dll_list

        except subprocess.TimeoutExpired:
            return False, "查询超时", []
        except Exception as e:
            return False, f"查询出错: {str(e)}", []
    
    def parse_dll_output(self, output, pid):
        """解析Listdlls输出"""
        dll_list = []
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # 跳过标题行
                if 'Base' in line or 'Size' in line or '---' in line:
                    continue
                
                # 解析DLL行
                # 格式: 0x00007ff8a0000000  0x123000  C:\Windows\System32\kernel32.dll
                if line.startswith('0x'):
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        base_addr = parts[0]
                        size = parts[1]
                        dll_path = parts[2]
                        
                        # 尝试获取版本信息
                        version = self.get_dll_version(dll_path)
                        
                        # 判断是否可疑
                        is_suspicious = not is_system_directory(dll_path)
                        
                        dll_list.append({
                            'path': dll_path,
                            'base_addr': base_addr,
                            'size': size,
                            'version': version,
                            'is_suspicious': is_suspicious
                        })
        
        except Exception as e:
            print(f"解析DLL输出失败: {str(e)}")
        
        return dll_list
    
    def get_dll_version(self, dll_path):
        """获取DLL版本信息"""
        try:
            # 这里可以使用win32api获取版本信息
            # 为了简化，暂时返回N/A
            return "N/A"
        except:
            return "N/A"
    
    def get_suspicious_dlls(self):
        """获取可疑DLL列表"""
        return [dll for dll in self.dll_list if dll['is_suspicious']]
    
    def get_dll_stats(self):
        """获取DLL统计信息"""
        total = len(self.dll_list)
        suspicious = len(self.get_suspicious_dlls())
        
        return {
            'total': total,
            'suspicious': suspicious,
            'normal': total - suspicious
        }
    
    def search_dll(self, keyword):
        """搜索DLL"""
        if not keyword:
            return self.dll_list

        keyword_lower = keyword.lower()
        return [dll for dll in self.dll_list if keyword_lower in dll['path'].lower()]

    def get_dll_details(self, dll_path):
        """获取DLL的详细信息"""
        return get_dll_detailed_info(dll_path)

