#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
计划任务持久化检测模块
"""

import subprocess


class ScheduledTaskDetector:
    """计划任务检测器"""
    
    def get_tasks(self):
        """获取所有计划任务"""
        tasks = []
        
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'CSV', '/v', '/nh'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if not line.strip():
                        continue
                    
                    parts = self._parse_csv_line(line)
                    if len(parts) >= 9:
                        task_name = parts[0].strip('"')
                        task_to_run = parts[8].strip('"') if len(parts) > 8 else ''
                        
                        if task_name and not task_name.startswith('\\Microsoft\\'):
                            task_info = {
                                'name': task_name,
                                'command': task_to_run,
                                'status': parts[2].strip('"') if len(parts) > 2 else '',
                                'author': parts[6].strip('"') if len(parts) > 6 else '',
                                'schedule': parts[16].strip('"') if len(parts) > 16 else '',
                                'schedule_type': parts[17].strip('"') if len(parts) > 17 else '',
                                'start_time': parts[18].strip('"') if len(parts) > 18 else '',
                                'start_date': parts[19].strip('"') if len(parts) > 19 else '',
                                'enabled_state': parts[10].strip('"') if len(parts) > 10 else '',
                                'raw': line.strip()
                            }
                            tasks.append(task_info)
        except subprocess.TimeoutExpired:
            print("[持久化检测] 获取计划任务超时")
        except Exception as e:
            print(f"[持久化检测] 获取计划任务失败: {e}")
        
        return tasks
    
    def _parse_csv_line(self, line):
        """简单的CSV解析（处理带引号的字段）"""
        parts = []
        current = ''
        in_quotes = False
        
        for char in line:
            if char == '"':
                in_quotes = not in_quotes
                current += char
            elif char == ',' and not in_quotes:
                parts.append(current)
                current = ''
            else:
                current += char
        
        if current:
            parts.append(current)
        
        return parts