#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
句柄管理模块
处理句柄查询功能
"""

import subprocess
import os
from constants import TOOLS
from utils.validation import sanitize_pid, sanitize_filter_type


# 允许的句柄过滤类型白名单
ALLOWED_HANDLE_TYPES = {
    '全部', 'None', 'File', 'Section', 'Mutant', 'Event',
    'Key', 'Process', 'Thread', 'Directory', 'Semaphore',
    'Timer', 'Desktop', 'WindowStation', 'Token', 'Job'
}


class HandleManager:
    """句柄管理器"""

    def __init__(self):
        self.handle_list = []

    def query_handles(self, pid, filter_type='全部'):
        """查询进程句柄"""
        # 安全验证：验证 PID
        valid, safe_pid, error = sanitize_pid(pid)
        if not valid:
            return False, f"PID 验证失败: {error}", []

        # 安全验证：验证过滤类型（白名单）
        valid, safe_filter, error = sanitize_filter_type(filter_type, list(ALLOWED_HANDLE_TYPES))
        if not valid:
            return False, f"过滤类型验证失败: {error}", []

        # 检查工具是否存在
        if not os.path.exists(TOOLS['handle']):
            return False, f"未找到工具: {TOOLS['handle']}", []

        try:
            # 构建命令（使用列表形式）
            cmd = [TOOLS['handle'], '-accepteula', '-p', str(safe_pid)]

            # 添加过滤（只使用白名单中的值）
            if safe_filter and safe_filter != '全部' and safe_filter != 'None':
                cmd.extend(['-t', safe_filter])

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
                return False, f"查询失败: {result.stderr}", []

            # 解析输出
            handle_list = self.parse_handle_output(result.stdout, safe_pid)
            self.handle_list = handle_list

            return True, "查询成功", handle_list

        except subprocess.TimeoutExpired:
            return False, "查询超时", []
        except Exception as e:
            return False, f"查询出错: {str(e)}", []
    
    def parse_handle_output(self, output, pid):
        """解析Handle输出"""
        handle_list = []
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # 跳过标题行
                if 'Handle' in line and 'Type' in line:
                    continue
                if line.startswith('-'):
                    continue
                if 'pid:' in line.lower():
                    continue
                
                # 解析句柄行
                # 格式: 0x123: File  C:\path\to\file
                if ':' in line:
                    parts = line.split(':', 2)
                    if len(parts) >= 2:
                        handle_value = parts[0].strip()
                        
                        # 提取类型和名称
                        rest = parts[1].strip()
                        if len(parts) >= 3:
                            rest = parts[1].strip() + ':' + parts[2]
                        
                        # 分离类型和名称
                        type_and_name = rest.split(None, 1)
                        if len(type_and_name) >= 1:
                            handle_type = type_and_name[0].strip()
                            handle_name = type_and_name[1].strip() if len(type_and_name) > 1 else ''
                            
                            handle_list.append({
                                'type': handle_type,
                                'value': handle_value,
                                'name': handle_name
                            })
        
        except Exception as e:
            print(f"解析句柄输出失败: {str(e)}")
        
        return handle_list
    
    def get_handles_by_type(self, handle_type):
        """按类型获取句柄"""
        return [h for h in self.handle_list if h['type'].lower() == handle_type.lower()]
    
    def get_handle_stats(self):
        """获取句柄统计信息"""
        type_count = {}
        
        for handle in self.handle_list:
            handle_type = handle['type']
            type_count[handle_type] = type_count.get(handle_type, 0) + 1
        
        return {
            'total': len(self.handle_list),
            'by_type': type_count
        }
    
    def search_handle(self, keyword):
        """搜索句柄"""
        if not keyword:
            return self.handle_list
        
        keyword_lower = keyword.lower()
        return [h for h in self.handle_list 
                if keyword_lower in h['name'].lower() or 
                   keyword_lower in h['type'].lower()]

