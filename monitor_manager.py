#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
监控管理模块
处理Procmon实时监控功能
"""

import subprocess
import os
import time
import csv
from collections import defaultdict
from utils import create_procmon_log_path
from constants import TOOLS


class MonitorManager:
    """Procmon监控管理器"""
    
    def __init__(self):
        self.procmon_process = None
        self.log_file = None
        self.is_monitoring = False
    
    def start_monitor(self, pid=None, pid_filters=None):
        """启动Procmon监控
        
        Args:
            pid: 进程PID（可选，如果指定则只监控该进程）
            pid_filters: 需要保留的PID集合（包含目标及其后代）
        
        Returns:
            (success, message, log_file)
        """
        # 检查工具是否存在
        if not os.path.exists(TOOLS['procmon']):
            return False, f"未找到工具: {TOOLS['procmon']}", None
        
        # 检查是否已在监控
        if self.is_monitoring:
            return False, "Procmon已在运行", None
        
        try:
            # 生成日志文件路径（不带扩展名，Procmon会自动添加.pml）
            if pid:
                log_file = create_procmon_log_path(pid)
            else:
                log_file = create_procmon_log_path('all')
            
            # 构建命令
            cmd = [
                TOOLS['procmon'],
                '/AcceptEula',
                '/Quiet',
                '/Minimized',
                '/BackingFile', log_file
            ]
            
            # 如果指定了PID集合，生成过滤配置
            if pid_filters:
                filter_path = self._create_filter_file(pid_filters)
                if filter_path:
                    cmd.extend(['/LoadConfig', filter_path])
            
            # 启动Procmon
            self.procmon_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.log_file = log_file + '.pml'  # Procmon自动添加.pml扩展名
            self.is_monitoring = True
            
            return True, "Procmon监控已启动", self.log_file
            
        except Exception as e:
            return False, f"启动Procmon失败: {str(e)}", None
    
    def stop_monitor(self):
        """停止Procmon监控
        
        Returns:
            (success, message, log_file)
        """
        if not self.is_monitoring:
            return False, "Procmon未在运行", None
        
        try:
            # 停止Procmon（发送终止命令）
            subprocess.run(
                [TOOLS['procmon'], '/Terminate'],
                timeout=10
            )
            
            # 等待进程结束
            if self.procmon_process:
                self.procmon_process.wait(timeout=5)
            
            log_file = self.log_file
            self.procmon_process = None
            self.is_monitoring = False
            
            # 等待文件写入完成
            time.sleep(1)
            
            return True, "Procmon监控已停止", log_file
            
        except Exception as e:
            return False, f"停止Procmon失败: {str(e)}", None
    
    def is_running(self):
        """检查Procmon是否正在运行"""
        return self.is_monitoring
    
    def get_log_file(self):
        """获取当前日志文件路径"""
        return self.log_file
    
    def parse_log(self, log_file=None):
        """解析Procmon日志
        
        Args:
            log_file: 日志文件路径（可选，默认使用当前日志）
        
        Returns:
            事件列表
        """
        if not log_file:
            log_file = self.log_file
        
        if not log_file or not os.path.exists(log_file):
            return []
        
        # 注意：Procmon的.pml文件是二进制格式
        # 需要使用Procmon的命令行工具转换为CSV或XML
        # 这里简化处理，返回空列表
        # 实际使用中需要先转换格式再解析
        
        return []
    
    def export_log_to_csv(self, log_file=None, output_file=None):
        """将Procmon日志导出为CSV

        Args:
            log_file: 日志文件路径
            output_file: 输出文件路径

        Returns:
            (success, message, output_file)
        """
        if not log_file:
            log_file = self.log_file

        if not log_file or not os.path.exists(log_file):
            return False, "日志文件不存在", None

        if not output_file:
            output_file = log_file.replace('.pml', '.csv')

        try:
            # 使用Procmon导出为CSV
            cmd = [
                TOOLS['procmon'],
                '/OpenLog', log_file,
                '/SaveAs', output_file,
                '/SaveApplyFilter'
            ]

            subprocess.run(cmd, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # 等待文件生成
            time.sleep(2)

            if os.path.exists(output_file):
                return True, "导出成功", output_file
            else:
                return False, "导出失败", None

        except Exception as e:
            return False, f"导出失败: {str(e)}", None

    def parse_csv_log(self, csv_file, target_pid=None, pid_whitelist=None):
        """解析Procmon CSV日志

        Args:
            csv_file: CSV文件路径
            target_pid: 目标进程PID（兼容旧参数）
            pid_whitelist: PID集合（只保留这些进程及其事件）

        Returns:
            dict: 包含分类事件的字典
        """
        if not os.path.exists(csv_file):
            return None

        events = {
            'file_operations': [],      # 文件操作
            'registry_operations': [],  # 注册表操作
            'network_operations': [],   # 网络操作
            'process_operations': [],   # 进程操作
            'all_events': []            # 所有事件
        }

        allowed_pids = set()
        if pid_whitelist:
            for pid in pid_whitelist:
                try:
                    allowed_pids.add(int(pid))
                except (TypeError, ValueError):
                    continue
        if target_pid:
            try:
                allowed_pids.add(int(target_pid))
            except (TypeError, ValueError):
                pass

        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # 如果指定了PID集合，只保留相关事件
                    if allowed_pids:
                        try:
                            pid = int(row.get('PID', 0))
                        except (TypeError, ValueError):
                            continue
                        if pid not in allowed_pids:
                            continue

                    # 提取关键字段
                    event = {
                        'time': row.get('Time of Day', ''),
                        'process_name': row.get('Process Name', ''),
                        'pid': row.get('PID', ''),
                        'operation': row.get('Operation', ''),
                        'path': row.get('Path', ''),
                        'result': row.get('Result', ''),
                        'detail': row.get('Detail', '')
                    }

                    events['all_events'].append(event)

                    # 分类事件
                    operation = event['operation'].upper()

                    # 文件操作
                    if any(op in operation for op in ['CREATEFILE', 'WRITEFILE', 'READFILE',
                                                       'DELETEFILE', 'RENAMEFILE', 'SETINFORMATION']):
                        events['file_operations'].append(event)

                    # 注册表操作
                    elif any(op in operation for op in ['REGCREATEKEY', 'REGSETVALUE', 'REGDELETEKEY',
                                                         'REGDELETEVALUE', 'REGOPENKEY', 'REGQUERYVALUE']):
                        events['registry_operations'].append(event)

                    # 网络操作
                    elif any(op in operation for op in ['TCP', 'UDP', 'SEND', 'RECEIVE']):
                        events['network_operations'].append(event)

                    # 进程操作
                    elif any(op in operation for op in ['PROCESS', 'THREAD', 'LOAD']):
                        events['process_operations'].append(event)

            return events

        except Exception as e:
            print(f"解析CSV失败: {e}")
            return None

    def analyze_behaviors(self, events):
        """分析事件，识别可疑行为

        Args:
            events: parse_csv_log返回的事件字典

        Returns:
            dict: 分析结果
        """
        if not events:
            return None

        analysis = {
            'persistence_mechanisms': [],  # 持久化机制
            'sensitive_files': [],         # 敏感文件访问
            'suspicious_registry': [],     # 可疑注册表操作
            'file_modifications': [],      # 文件修改
            'statistics': {}               # 统计信息
        }

        # 持久化相关的注册表键
        persistence_keys = [
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
            r'SYSTEM\CurrentControlSet\Services',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        ]

        # 敏感文件路径
        sensitive_paths = [
            'AppData\\Local\\Microsoft\\Windows\\WebCache',  # 浏览器缓存
            'AppData\\Roaming\\Microsoft\\Windows\\Cookies', # Cookie
            'AppData\\Local\\Google\\Chrome',                # Chrome数据
            'AppData\\Roaming\\Mozilla\\Firefox',            # Firefox数据
            'Documents',                                      # 文档
            'Desktop'                                         # 桌面
        ]

        # 分析注册表操作
        for event in events.get('registry_operations', []):
            path = event['path'].upper()
            operation = event['operation'].upper()

            # 检查持久化机制
            for key in persistence_keys:
                if key.upper() in path:
                    if 'SET' in operation or 'CREATE' in operation:
                        analysis['persistence_mechanisms'].append({
                            'time': event['time'],
                            'type': 'registry',
                            'operation': event['operation'],
                            'path': event['path'],
                            'detail': event['detail']
                        })
                        break

            # 检查可疑注册表操作
            if 'DELETE' in operation or 'SET' in operation:
                analysis['suspicious_registry'].append(event)

        # 分析文件操作
        for event in events.get('file_operations', []):
            path = event['path'].upper()
            operation = event['operation'].upper()

            # 检查敏感文件访问
            for sensitive in sensitive_paths:
                if sensitive.upper() in path:
                    analysis['sensitive_files'].append(event)
                    break

            # 检查文件修改
            if any(op in operation for op in ['WRITE', 'DELETE', 'RENAME', 'SETINFORMATION']):
                analysis['file_modifications'].append(event)

        # 统计信息
        analysis['statistics'] = {
            'total_events': len(events.get('all_events', [])),
            'file_operations': len(events.get('file_operations', [])),
            'registry_operations': len(events.get('registry_operations', [])),
            'network_operations': len(events.get('network_operations', [])),
            'process_operations': len(events.get('process_operations', [])),
            'persistence_found': len(analysis['persistence_mechanisms']),
            'sensitive_files_accessed': len(analysis['sensitive_files']),
            'files_modified': len(analysis['file_modifications'])
        }

        return analysis
    def _create_filter_file(self, pid_filters):
        """创建Procmon过滤配置文件，只保留特定PID

        Returns:
            str: 配置文件路径
        """
        try:
            config_path = create_procmon_log_path('filter') + '.pmc'
            filters = '\n'.join(str(pid) for pid in sorted(pid_filters))
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(f'[Filters]\nPID={filters}\n')
            return config_path
        except Exception as e:
            print(f"创建Procmon过滤文件失败: {e}")
            return None
