#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
动态分析管理模块
处理恶意软件动态分析功能
"""

import subprocess
import os
import time
import threading
import csv
import psutil
from datetime import datetime
from process_manager import ProcessManager
from network_manager import NetworkManager
from report_generator import ReportGenerator
from monitor_manager import MonitorManager
from utils.validation import sanitize_executable_path, sanitize_args


class AnalysisManager:
    """动态分析管理器"""

    def __init__(self):
        self.process_manager = ProcessManager()
        self.network_manager = NetworkManager()
        self.report_generator = ReportGenerator()
        self.monitor_manager = MonitorManager()

        self.is_analyzing = False
        self.target_pid = None
        self.target_process = None
        self.target_exe_path = None
        self.start_time = None

        # 活动记录
        self.file_activities = []
        self.registry_activities = []
        self.network_activities = []
        self.process_activities = []
        self.persistence_mechanisms = []
        self.child_pids = set()

        # Procmon日志文件
        self.procmon_log_file = None
        self.procmon_csv_file = None

        # 初始快照（用于对比）
        self.initial_processes = set()
        self.initial_connections = []
    
    def start_analysis(self, executable_path, args="", timeout=60):
        """启动动态分析

        Args:
            executable_path: 可执行文件路径
            args: 命令行参数
            timeout: 超时时间（秒）

        Returns:
            (success, message, pid)
        """
        if self.is_analyzing:
            return False, "已有分析正在进行", None

        # 安全验证：验证可执行文件路径
        valid, safe_path, error = sanitize_executable_path(executable_path)
        if not valid:
            return False, f"路径验证失败: {error}", None

        # 安全验证：验证命令行参数
        valid, args_list, error = sanitize_args(args)
        if not valid:
            return False, f"参数验证失败: {error}", None

        try:
            # 保存目标路径（使用验证后的安全路径）
            self.target_exe_path = safe_path

            # 清空之前的记录
            self.file_activities = []
            self.registry_activities = []
            self.network_activities = []
            self.process_activities = []
            self.persistence_mechanisms = []

            # 获取初始快照
            self.initial_processes = set(p.pid for p in psutil.process_iter())
            self.initial_connections = self.network_manager.get_all_connections()

            # 启动Procmon监控
            success, message, log_file = self.monitor_manager.start_monitor()
            if not success:
                return False, f"启动Procmon失败: {message}", None

            self.procmon_log_file = log_file

            # 等待Procmon启动
            time.sleep(2)

            # 安全执行：使用列表形式传递参数，避免 shell=True
            cmd_list = [safe_path] + args_list

            process = subprocess.Popen(
                cmd_list,
                shell=False,  # 关键：禁用 shell 解析，防止命令注入
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            self.target_pid = process.pid
            self.target_process = process
            self.is_analyzing = True
            self.start_time = datetime.now()
            self.child_pids = {self.target_pid}

            # 启动监控线程
            monitor_thread = threading.Thread(
                target=self._monitor_process,
                args=(timeout,),
                daemon=True
            )
            monitor_thread.start()

            return True, f"分析已启动，PID: {self.target_pid}", self.target_pid

        except Exception as e:
            # 清理
            if self.monitor_manager.is_monitoring:
                self.monitor_manager.stop_monitor()
            return False, f"启动分析失败: {str(e)}", None
    
    def stop_analysis(self):
        """停止动态分析

        Returns:
            (success, message)
        """
        if not self.is_analyzing:
            return False, "没有正在进行的分析"

        try:
            # 终止目标进程
            if self.target_process:
                try:
                    self.target_process.terminate()
                    self.target_process.wait(timeout=5)
                except:
                    pass

            # 停止Procmon监控
            if self.monitor_manager.is_monitoring:
                success, message, log_file = self.monitor_manager.stop_monitor()
                if success:
                    self.procmon_log_file = log_file

            self.is_analyzing = False

            # 等待一下让Procmon完成写入
            time.sleep(2)

            # 解析Procmon日志
            self._parse_procmon_log()

            # 检测持久化机制
            self._detect_persistence()

            return True, "分析已停止"

        except Exception as e:
            return False, f"停止分析失败: {str(e)}"
    
    def _monitor_process(self, timeout):
        """监控进程（在后台线程中运行）"""
        start_time = time.time()

        while self.is_analyzing:
            # 检查超时
            if time.time() - start_time > timeout:
                self.stop_analysis()
                break

            # 检查进程是否还在运行
            if self.target_process and self.target_process.poll() is not None:
                # 进程已退出，等待一下再停止分析
                time.sleep(3)
                self.stop_analysis()
                break

            # 监控网络活动
            self._monitor_network()

            # 监控进程活动
            self._monitor_processes()

            # 等待一段时间
            time.sleep(1)

    def _monitor_network(self):
        """监控网络活动"""
        if not self.target_pid:
            return

        try:
            connections = self.network_manager.get_connection_by_pid(self.target_pid)

            for conn in connections:
                # 检查是否已记录
                if not any(c['remote_addr'] == conn['remote_addr'] for c in self.network_activities):
                    self.network_activities.append({
                        'time': datetime.now(),
                        'remote_addr': conn['remote_addr'],
                        'remote_ip': conn['remote_ip'],
                        'remote_port': conn['remote_port'],
                        'protocol': conn['protocol'],
                        'is_suspicious': conn['is_suspicious']
                    })
        except:
            pass

    def _monitor_processes(self):
        """监控进程活动"""
        try:
            # 检查是否有新的进程
            current_processes = set(p.pid for p in psutil.process_iter())
            new_processes = current_processes - self.initial_processes

            tracked_parents = self._get_monitored_pids()

            for pid in new_processes:
                try:
                    proc = psutil.Process(pid)
                    if proc.ppid() in tracked_parents:
                        proc_info = {
                            'time': datetime.now(),
                            'pid': pid,
                            'name': proc.name(),
                            'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                            'parent_pid': proc.ppid()
                        }

                        # 检查是否已记录
                        if not any(p['pid'] == pid for p in self.process_activities):
                            self.process_activities.append(proc_info)
                            self.child_pids.add(pid)
                except:
                    pass
        except:
            pass

    def _get_monitored_pids(self):
        """返回需要关注的PID集合（目标进程及其后代）"""
        pid_set = set()
        if self.target_pid:
            pid_set.add(self.target_pid)
        pid_set.update(self.child_pids)

        for proc in self.process_activities:
            try:
                pid = int(proc.get('pid', 0))
                if pid:
                    pid_set.add(pid)
            except (TypeError, ValueError):
                continue

        return pid_set
    
    def _parse_procmon_log(self):
        """解析Procmon日志"""
        if not self.procmon_log_file or not os.path.exists(self.procmon_log_file):
            return

        try:
            # 导出为CSV
            success, message, csv_file = self.monitor_manager.export_log_to_csv(self.procmon_log_file)
            if not success or not csv_file or not os.path.exists(csv_file):
                return

            self.procmon_csv_file = csv_file
            allowed_pids = self._get_monitored_pids()

            # 解析CSV文件
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    try:
                        if allowed_pids:
                            try:
                                pid_value = int(row.get('PID', 0))
                            except (TypeError, ValueError):
                                continue
                            if pid_value not in allowed_pids:
                                continue

                        operation = row.get('Operation', '')
                        path = row.get('Path', '')
                        result = row.get('Result', '')

                        # 文件操作
                        if any(op in operation for op in ['CreateFile', 'WriteFile', 'SetDispositionInformationFile', 'SetRenameInformationFile']):
                            if result == 'SUCCESS' and path:
                                file_info = {
                                    'time': row.get('Time of Day', ''),
                                    'operation': operation,
                                    'path': path,
                                    'result': result
                                }
                                # 去重
                                if not any(f['path'] == path and f['operation'] == operation for f in self.file_activities):
                                    self.file_activities.append(file_info)

                        # 注册表操作
                        elif any(op in operation for op in ['RegSetValue', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue']):
                            if result == 'SUCCESS' and path:
                                reg_info = {
                                    'time': row.get('Time of Day', ''),
                                    'operation': operation,
                                    'path': path,
                                    'result': result
                                }
                                # 去重
                                if not any(r['path'] == path and r['operation'] == operation for r in self.registry_activities):
                                    self.registry_activities.append(reg_info)

                    except:
                        continue

        except Exception as e:
            print(f"解析Procmon日志失败: {e}")

    def _detect_persistence(self):
        """检测持久化机制"""
        # 检查注册表持久化
        persistence_keys = [
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices',
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
            'HKLM\\System\\CurrentControlSet\\Services',
            'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        ]

        for reg_activity in self.registry_activities:
            path = reg_activity.get('path', '').upper()

            for key in persistence_keys:
                if key.upper() in path:
                    self.persistence_mechanisms.append({
                        'type': '注册表持久化',
                        'location': reg_activity['path'],
                        'operation': reg_activity['operation'],
                        'time': reg_activity['time']
                    })
                    break

        # 检查文件持久化（启动文件夹）
        startup_paths = [
            'STARTUP',
            'START MENU\\PROGRAMS\\STARTUP',
            'APPDATA\\ROAMING\\MICROSOFT\\WINDOWS\\START MENU\\PROGRAMS\\STARTUP'
        ]

        for file_activity in self.file_activities:
            path = file_activity.get('path', '').upper()

            for startup_path in startup_paths:
                if startup_path in path:
                    self.persistence_mechanisms.append({
                        'type': '启动文件夹',
                        'location': file_activity['path'],
                        'operation': file_activity['operation'],
                        'time': file_activity['time']
                    })
                    break

        # 检查计划任务
        for file_activity in self.file_activities:
            path = file_activity.get('path', '').upper()
            if 'SYSTEM32\\TASKS' in path or 'SCHTASKS' in path:
                self.persistence_mechanisms.append({
                    'type': '计划任务',
                    'location': file_activity['path'],
                    'operation': file_activity['operation'],
                    'time': file_activity['time']
                })

    def get_analysis_summary(self):
        """获取分析摘要

        Returns:
            摘要字典
        """
        return {
            'pid': self.target_pid,
            'start_time': self.start_time,
            'duration': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
            'file_operations': len(self.file_activities),
            'registry_operations': len(self.registry_activities),
            'network_connections': len(self.network_activities),
            'process_operations': len(self.process_activities),
            'persistence_mechanisms': len(self.persistence_mechanisms)
        }
    
    def generate_report(self, format='html'):
        """生成分析报告
        
        Args:
            format: 报告格式 ('html', 'json', 'text')
        
        Returns:
            (success, message, file_path)
        """
        # 准备报告数据
        report_data = {
            'summary': self.get_analysis_summary(),
            'file_activities': self.file_activities,
            'registry_activities': self.registry_activities,
            'network_activities': [
                {**activity, 'time': activity['time'].isoformat()}
                for activity in self.network_activities
            ],
            'process_activities': self.process_activities,
            'persistence_mechanisms': self.persistence_mechanisms
        }
        
        self.report_generator.set_report_data(report_data)
        
        # 生成报告
        if format == 'html':
            return self.report_generator.generate_html_report()
        elif format == 'json':
            return self.report_generator.generate_json_report()
        elif format == 'text':
            return self.report_generator.generate_text_report()
        else:
            return False, f"不支持的格式: {format}", None
