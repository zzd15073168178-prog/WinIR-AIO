#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
行为监控沙箱管理器
分析可疑程序运行时的行为：文件释放、进程创建、网络连接、注册表修改、持久化变化
"""

import subprocess
import os
import time
import threading
import csv
import hashlib
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Callable, Set, Tuple

from monitor_manager import MonitorManager
from persistence_detector import PersistenceDetector
from network_manager import NetworkManager
from utils.validation import sanitize_executable_path, sanitize_args, sanitize_pid


# 可执行文件扩展名
EXECUTABLE_EXTENSIONS = {
    '.exe': 'Windows 可执行文件',
    '.dll': '动态链接库',
    '.sys': '驱动程序',
    '.bat': '批处理脚本',
    '.cmd': '命令脚本',
    '.ps1': 'PowerShell 脚本',
    '.vbs': 'VBScript 脚本',
    '.js': 'JScript 脚本',
    '.hta': 'HTML 应用程序',
    '.scr': '屏幕保护程序',
    '.msi': '安装程序',
    '.jar': 'Java 程序',
    '.com': 'DOS 可执行文件',
}

# 敏感目录
SENSITIVE_DIRS = [
    r'\windows\system32',
    r'\windows\syswow64',
    r'\windows\temp',
    r'\appdata\local\temp',
    r'\appdata\roaming',
    r'\programdata',
    r'\users\public',
]


class SandboxManager:
    """行为监控沙箱管理器"""

    def __init__(self):
        # 复用现有组件
        self.monitor_manager = MonitorManager()
        self.persistence_detector = PersistenceDetector()
        self.network_manager = NetworkManager()

        # 沙箱状态
        self.is_running = False
        self.target_pid: Optional[int] = None
        self.target_process: Optional[subprocess.Popen] = None
        self.target_exe_path: Optional[str] = None
        self.target_args: str = ""
        self.working_dir: Optional[str] = None
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.timeout: int = 60

        # 追踪的 PID 集合（目标进程及其所有子进程）
        self.tracked_pids: Set[int] = set()
        self.initial_pids: Set[int] = set()
        self.initial_connections: List[Dict] = []

        # Procmon 日志
        self.procmon_log_file: Optional[str] = None
        self.procmon_csv_file: Optional[str] = None

        # 分析结果
        self.results = {
            'dropped_files': [],           # 释放的所有文件
            'executable_files': [],        # 释放的可执行文件
            'spawned_processes': [],       # 启动的进程（含命令行）
            'network_connections': [],     # 网络连接
            'registry_modifications': [],  # 注册表修改
            'persistence_changes': [],     # 持久化变化
            'file_operations': [],         # 所有文件操作（原始）
        }

        # 回调函数
        self.on_status_change: Optional[Callable[[str, str], None]] = None
        self.on_progress_update: Optional[Callable[[int, str], None]] = None
        self.on_complete: Optional[Callable[[Dict], None]] = None

        # 监控线程
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ==================== 主要方法 ====================

    def start_analysis(self, executable_path: str, args: str = "",
                       timeout: int = 60, working_dir: str = None) -> Tuple[bool, str, Optional[int]]:
        """
        启动沙箱分析

        Args:
            executable_path: 目标可执行文件路径
            args: 命令行参数
            timeout: 超时时间（秒）
            working_dir: 工作目录

        Returns:
            (success: bool, message: str, pid: int or None)
        """
        if self.is_running:
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
            self._update_status("preparing", "正在准备沙箱环境...")
            self._update_progress(5, "清空旧结果")

            # 保存参数（使用验证后的安全路径）
            self.target_exe_path = safe_path
            self.target_args = args
            self.working_dir = working_dir or os.path.dirname(safe_path)
            self.timeout = timeout

            # 清空旧结果
            self._clear_results()

            # 获取初始状态
            self._update_progress(10, "获取初始进程列表")
            self.initial_pids = set(p.pid for p in psutil.process_iter())
            self.initial_connections = self.network_manager.get_all_connections()

            # 获取持久化初始快照
            self._update_progress(15, "获取持久化快照...")
            self._update_status("snapshot", "正在获取系统快照...")
            self.persistence_detector.take_initial_snapshot()

            # 启动 Procmon 监控
            self._update_progress(25, "启动 Procmon 监控")
            self._update_status("procmon", "正在启动 Procmon...")
            success, message, log_file = self.monitor_manager.start_monitor()
            if not success:
                return False, f"启动 Procmon 失败: {message}", None
            self.procmon_log_file = log_file

            # 等待 Procmon 稳定
            time.sleep(2)

            # 启动目标进程
            self._update_progress(35, "启动目标进程")
            self._update_status("running", "正在运行目标程序...")

            # 安全执行：使用列表形式传递参数，避免 shell=True
            cmd_list = [safe_path] + args_list
            self.target_process = subprocess.Popen(
                cmd_list,
                shell=False,  # 关键：禁用 shell 解析，防止命令注入
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.working_dir
            )

            self.target_pid = self.target_process.pid
            self.tracked_pids = {self.target_pid}
            self.is_running = True
            self.start_time = datetime.now()
            self._stop_event.clear()

            # 启动监控线程
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                args=(timeout,),
                daemon=True
            )
            self._monitor_thread.start()

            return True, f"分析已启动，PID: {self.target_pid}", self.target_pid

        except Exception as e:
            # 清理
            if self.monitor_manager.is_monitoring:
                self.monitor_manager.stop_monitor()
            self._update_status("error", f"启动失败: {e}")
            return False, f"启动分析失败: {str(e)}", None

    def stop_analysis(self) -> Tuple[bool, str]:
        """
        停止沙箱分析

        Returns:
            (success: bool, message: str)
        """
        if not self.is_running:
            return False, "没有正在进行的分析"

        try:
            self._stop_event.set()
            self._update_status("stopping", "正在停止分析...")
            self._update_progress(60, "终止目标进程")

            # 终止目标进程及其子进程
            self._terminate_target_process()

            # 停止 Procmon
            self._update_progress(65, "停止 Procmon")
            if self.monitor_manager.is_monitoring:
                success, message, log_file = self.monitor_manager.stop_monitor()
                if success:
                    self.procmon_log_file = log_file

            self.is_running = False
            self.end_time = datetime.now()

            # 等待 Procmon 完成写入
            time.sleep(2)

            # 完成分析
            self._finalize_analysis()

            return True, "分析已停止"

        except Exception as e:
            self._update_status("error", f"停止失败: {e}")
            return False, f"停止分析失败: {str(e)}"

    def get_results(self) -> Dict:
        """获取分析结果"""
        return self.results.copy()

    def get_summary(self) -> Dict:
        """获取分析摘要"""
        duration = 0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()

        return {
            'target_file': self.target_exe_path,
            'target_args': self.target_args,
            'target_pid': self.target_pid,
            'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else None,
            'end_time': self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else None,
            'duration': duration,
            'dropped_files_count': len(self.results['dropped_files']),
            'executable_files_count': len(self.results['executable_files']),
            'spawned_processes_count': len(self.results['spawned_processes']),
            'network_connections_count': len(self.results['network_connections']),
            'registry_modifications_count': len(self.results['registry_modifications']),
            'persistence_changes_count': len(self.results['persistence_changes']),
            'tracked_pids': list(self.tracked_pids),
        }

    def generate_report(self, format: str = 'html') -> Tuple[bool, str, Optional[str]]:
        """
        生成分析报告

        Args:
            format: 报告格式 ('html', 'json', 'text')

        Returns:
            (success: bool, message: str, file_path: str or None)
        """
        report_data = {
            'summary': self.get_summary(),
            'dropped_files': self.results['dropped_files'],
            'executable_files': self.results['executable_files'],
            'spawned_processes': self.results['spawned_processes'],
            'network_connections': self.results['network_connections'],
            'registry_modifications': self.results['registry_modifications'],
            'persistence_changes': self.results['persistence_changes'],
        }

        # 确保 reports 目录存在
        reports_dir = 'reports'
        os.makedirs(reports_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        try:
            if format == 'json':
                file_path = os.path.join(reports_dir, f'sandbox_report_{timestamp}.json')
                import json
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
                return True, "JSON 报告已生成", file_path

            elif format == 'html':
                file_path = os.path.join(reports_dir, f'sandbox_report_{timestamp}.html')
                html_content = self._generate_html_report(report_data)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                return True, "HTML 报告已生成", file_path

            else:
                return False, f"不支持的格式: {format}", None

        except Exception as e:
            return False, f"生成报告失败: {e}", None

    def _generate_html_report(self, data: Dict) -> str:
        """生成 HTML 报告内容"""
        summary = data.get('summary', {})
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>行为沙箱分析报告</title>
    <style>
        body {{ font-family: "Microsoft YaHei", Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        h2 {{ color: #ff6b6b; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
        th {{ background: #16213e; color: #00d4ff; }}
        tr:nth-child(even) {{ background: #1f1f3d; }}
        .critical {{ color: #ff4757; font-weight: bold; }}
        .warning {{ color: #ffa502; }}
        .info {{ color: #2ed573; }}
        .summary-box {{ background: #16213e; padding: 15px; border-radius: 8px; margin: 10px 0; }}
        .summary-item {{ display: inline-block; margin: 10px 20px; }}
        .summary-value {{ font-size: 24px; color: #00d4ff; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>行为沙箱分析报告</h1>

    <div class="summary-box">
        <h2>分析摘要</h2>
        <p><strong>目标文件:</strong> {summary.get('target_file', 'N/A')}</p>
        <p><strong>命令参数:</strong> {summary.get('target_args', 'N/A')}</p>
        <p><strong>目标 PID:</strong> {summary.get('target_pid', 'N/A')}</p>
        <p><strong>开始时间:</strong> {summary.get('start_time', 'N/A')}</p>
        <p><strong>结束时间:</strong> {summary.get('end_time', 'N/A')}</p>
        <p><strong>分析时长:</strong> {summary.get('duration', 0):.1f} 秒</p>
        <div>
            <span class="summary-item"><span class="summary-value">{summary.get('dropped_files_count', 0)}</span> 释放文件</span>
            <span class="summary-item"><span class="summary-value">{summary.get('executable_files_count', 0)}</span> 可执行文件</span>
            <span class="summary-item"><span class="summary-value">{summary.get('spawned_processes_count', 0)}</span> 进程</span>
            <span class="summary-item"><span class="summary-value">{summary.get('network_connections_count', 0)}</span> 网络连接</span>
            <span class="summary-item"><span class="summary-value">{summary.get('registry_modifications_count', 0)}</span> 注册表修改</span>
            <span class="summary-item"><span class="summary-value">{summary.get('persistence_changes_count', 0)}</span> 持久化变化</span>
        </div>
    </div>
'''
        # 释放文件
        if data.get('dropped_files'):
            html += '''
    <h2>释放文件</h2>
    <table>
        <tr><th>文件名</th><th>类型</th><th>大小</th><th>操作</th><th>MD5</th><th>路径</th></tr>
'''
            for f in data['dropped_files']:
                html += f'''        <tr>
            <td>{f.get('filename', '')}</td>
            <td>{f.get('file_type', '')}</td>
            <td>{f.get('size_str', '')}</td>
            <td>{f.get('operation', '')}</td>
            <td>{f.get('md5', '')}</td>
            <td>{f.get('path', '')}</td>
        </tr>
'''
            html += '    </table>\n'

        # 运行程序
        if data.get('spawned_processes'):
            html += '''
    <h2>运行程序</h2>
    <table>
        <tr><th>PID</th><th>进程名</th><th>命令行</th><th>父进程</th><th>启动时间</th></tr>
'''
            for p in data['spawned_processes']:
                html += f'''        <tr>
            <td>{p.get('pid', '')}</td>
            <td>{p.get('name', '')}</td>
            <td>{p.get('cmdline', '')}</td>
            <td>{p.get('parent_pid', '')}</td>
            <td>{p.get('create_time', '')}</td>
        </tr>
'''
            html += '    </table>\n'

        # 网络连接
        if data.get('network_connections'):
            html += '''
    <h2>网络连接</h2>
    <table>
        <tr><th>时间</th><th>进程</th><th>协议</th><th>远程地址</th><th>状态</th></tr>
'''
            for c in data['network_connections']:
                html += f'''        <tr>
            <td>{c.get('time', '')}</td>
            <td>{c.get('process_name', '')}</td>
            <td>{c.get('protocol', '')}</td>
            <td>{c.get('remote_addr', '')}</td>
            <td>{c.get('status', '')}</td>
        </tr>
'''
            html += '    </table>\n'

        # 持久化变化
        if data.get('persistence_changes'):
            html += '''
    <h2>持久化变化</h2>
    <table>
        <tr><th>类型</th><th>操作</th><th>位置</th><th>严重性</th></tr>
'''
            for p in data['persistence_changes']:
                severity = p.get('severity', 'info')
                html += f'''        <tr class="{severity}">
            <td>{p.get('type', '')}</td>
            <td>{p.get('action', '')}</td>
            <td>{p.get('location', '')}</td>
            <td>{severity}</td>
        </tr>
'''
            html += '    </table>\n'

        html += '''
    <hr>
    <p style="color: #666; font-size: 12px;">报告生成时间: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
</body>
</html>'''
        return html

    # ==================== 内部方法 ====================

    def _clear_results(self):
        """清空分析结果"""
        self.results = {
            'dropped_files': [],
            'executable_files': [],
            'spawned_processes': [],
            'network_connections': [],
            'registry_modifications': [],
            'persistence_changes': [],
            'file_operations': [],
        }
        self.tracked_pids.clear()
        self.initial_pids.clear()
        self.initial_connections.clear()
        self.procmon_log_file = None
        self.procmon_csv_file = None
        self.start_time = None
        self.end_time = None

    def _monitor_loop(self, timeout: int):
        """监控循环（在后台线程中运行）"""
        start_time = time.time()
        last_progress = 35

        while not self._stop_event.is_set():
            elapsed = time.time() - start_time

            # 更新进度
            progress = min(35 + int((elapsed / timeout) * 20), 55)
            if progress > last_progress:
                last_progress = progress
                remaining = int(timeout - elapsed)
                self._update_progress(progress, f"监控中... 剩余 {remaining} 秒")

            # 检查超时
            if elapsed >= timeout:
                self._update_status("timeout", "监控超时，正在停止...")
                self.stop_analysis()
                break

            # 检查进程是否退出
            if self.target_process and self.target_process.poll() is not None:
                time.sleep(3)  # 等待一下让子进程也退出
                self._update_status("exited", "目标进程已退出")
                self.stop_analysis()
                break

            # 监控子进程
            self._track_child_processes()

            # 监控网络活动
            self._monitor_network_activity()

            time.sleep(1)

    def _track_child_processes(self):
        """追踪目标进程的所有子进程"""
        try:
            current_pids = set(p.pid for p in psutil.process_iter())
            new_pids = current_pids - self.initial_pids

            for pid in new_pids:
                if pid in self.tracked_pids:
                    continue

                try:
                    proc = psutil.Process(pid)
                    parent_pid = proc.ppid()

                    # 检查是否是目标进程或已追踪进程的子进程
                    if parent_pid in self.tracked_pids:
                        self.tracked_pids.add(pid)

                        # 获取进程信息
                        try:
                            cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
                        except:
                            cmdline = ''

                        try:
                            exe_path = proc.exe()
                        except:
                            exe_path = ''

                        proc_info = {
                            'pid': pid,
                            'name': proc.name(),
                            'cmdline': cmdline,
                            'exe_path': exe_path,
                            'parent_pid': parent_pid,
                            'create_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                            'status': 'running',
                        }

                        # 去重
                        if not any(p['pid'] == pid for p in self.results['spawned_processes']):
                            self.results['spawned_processes'].append(proc_info)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

    def _monitor_network_activity(self):
        """监控网络活动"""
        if not self.tracked_pids:
            return

        try:
            for pid in self.tracked_pids:
                connections = self.network_manager.get_connection_by_pid(pid)

                for conn in connections:
                    # 检查是否已记录
                    key = f"{conn['remote_addr']}:{conn['protocol']}"
                    if not any(c.get('_key') == key for c in self.results['network_connections']):
                        conn_info = {
                            '_key': key,
                            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'pid': pid,
                            'process_name': conn.get('process_name', ''),
                            'protocol': conn['protocol'],
                            'local_addr': conn['local_addr'],
                            'remote_addr': conn['remote_addr'],
                            'remote_ip': conn['remote_ip'],
                            'remote_port': conn['remote_port'],
                            'status': conn.get('status', ''),
                            'is_suspicious': conn.get('is_suspicious', False),
                        }
                        self.results['network_connections'].append(conn_info)
        except Exception:
            pass

    def _terminate_target_process(self):
        """终止目标进程及其所有子进程"""
        # 先终止子进程
        for pid in list(self.tracked_pids):
            if pid == self.target_pid:
                continue
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                proc.wait(timeout=3)
            except:
                try:
                    proc.kill()
                except:
                    pass

        # 终止主进程
        if self.target_process:
            try:
                self.target_process.terminate()
                self.target_process.wait(timeout=5)
            except:
                try:
                    self.target_process.kill()
                except:
                    pass

        # 更新进程状态
        for proc in self.results['spawned_processes']:
            proc['status'] = 'exited'

    def _finalize_analysis(self):
        """完成分析（解析日志、对比快照）"""
        self._update_progress(70, "获取最终快照")
        self._update_status("analyzing", "正在分析结果...")

        # 获取持久化最终快照并对比
        self.persistence_detector.take_final_snapshot()
        self._update_progress(75, "对比持久化变化")
        changes = self.persistence_detector.detect_changes()
        self.results['persistence_changes'] = changes

        # 解析 Procmon 日志
        self._update_progress(80, "解析 Procmon 日志")
        self._parse_procmon_log()

        # 提取释放的文件
        self._update_progress(90, "提取释放文件")
        self._extract_dropped_files()

        # 完成
        self._update_progress(100, "分析完成")
        self._update_status("completed", "分析完成")

        # 回调
        if self.on_complete:
            self.on_complete(self.results)

    def _parse_procmon_log(self):
        """解析 Procmon 日志"""
        if not self.procmon_log_file or not os.path.exists(self.procmon_log_file):
            return

        try:
            # 导出为 CSV
            success, message, csv_file = self.monitor_manager.export_log_to_csv(self.procmon_log_file)
            if not success or not csv_file or not os.path.exists(csv_file):
                return

            self.procmon_csv_file = csv_file

            # 解析 CSV
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    try:
                        # 过滤 PID
                        try:
                            pid = int(row.get('PID', 0))
                        except (TypeError, ValueError):
                            continue

                        if pid not in self.tracked_pids:
                            continue

                        operation = row.get('Operation', '')
                        path = row.get('Path', '')
                        result = row.get('Result', '')
                        time_str = row.get('Time of Day', '')

                        # 文件操作
                        if any(op in operation for op in ['CreateFile', 'WriteFile', 'SetDisposition', 'SetRename']):
                            if result == 'SUCCESS' and path:
                                file_info = {
                                    'time': time_str,
                                    'pid': pid,
                                    'operation': operation,
                                    'path': path,
                                    'result': result,
                                    'detail': row.get('Detail', ''),
                                }
                                # 去重
                                if not any(f['path'] == path and f['operation'] == operation
                                          for f in self.results['file_operations']):
                                    self.results['file_operations'].append(file_info)

                        # 注册表操作
                        elif any(op in operation for op in ['RegSetValue', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue']):
                            if result == 'SUCCESS' and path:
                                reg_info = {
                                    'time': time_str,
                                    'pid': pid,
                                    'operation': operation,
                                    'path': path,
                                    'result': result,
                                    'detail': row.get('Detail', ''),
                                }
                                # 去重
                                if not any(r['path'] == path and r['operation'] == operation
                                          for r in self.results['registry_modifications']):
                                    self.results['registry_modifications'].append(reg_info)

                    except Exception:
                        continue

        except Exception as e:
            print(f"[沙箱] 解析 Procmon 日志失败: {e}")

    def _extract_dropped_files(self):
        """从文件操作中提取释放的文件"""
        seen_paths = set()

        for op in self.results['file_operations']:
            path = op['path']
            operation = op['operation']

            # 只关注写入操作
            if 'Write' not in operation and 'Create' not in operation:
                continue

            # 跳过已处理的路径
            if path.lower() in seen_paths:
                continue
            seen_paths.add(path.lower())

            # 检查文件是否存在
            if not os.path.exists(path):
                continue

            # 跳过目录
            if os.path.isdir(path):
                continue

            try:
                # 获取文件信息
                stat = os.stat(path)
                size = stat.st_size

                # 计算哈希
                md5_hash = self._calculate_md5(path)

                # 检查是否为可执行文件
                is_exe, exe_type = self._is_executable_file(path)

                # 检查是否在敏感目录
                is_sensitive = self._is_in_sensitive_dir(path)

                file_info = {
                    'path': path,
                    'filename': os.path.basename(path),
                    'size': size,
                    'size_str': self._format_size(size),
                    'md5': md5_hash,
                    'is_executable': is_exe,
                    'file_type': exe_type or self._get_file_type(path),
                    'is_sensitive_location': is_sensitive,
                    'operation': 'Created' if 'Create' in operation else 'Modified',
                    'time': op['time'],
                }

                self.results['dropped_files'].append(file_info)

                # 单独记录可执行文件
                if is_exe:
                    self.results['executable_files'].append(file_info)

            except Exception:
                continue

    def _is_executable_file(self, path: str) -> Tuple[bool, Optional[str]]:
        """判断是否为可执行文件"""
        ext = os.path.splitext(path.lower())[1]
        if ext in EXECUTABLE_EXTENSIONS:
            return True, EXECUTABLE_EXTENSIONS[ext]
        return False, None

    def _is_in_sensitive_dir(self, path: str) -> bool:
        """检查文件是否在敏感目录"""
        path_lower = path.lower()
        return any(sensitive in path_lower for sensitive in SENSITIVE_DIRS)

    def _get_file_type(self, path: str) -> str:
        """获取文件类型描述"""
        ext = os.path.splitext(path.lower())[1]
        common_types = {
            '.txt': '文本文件',
            '.log': '日志文件',
            '.ini': '配置文件',
            '.cfg': '配置文件',
            '.xml': 'XML 文件',
            '.json': 'JSON 文件',
            '.dat': '数据文件',
            '.tmp': '临时文件',
            '.db': '数据库文件',
        }
        return common_types.get(ext, '其他文件')

    def _calculate_md5(self, path: str) -> str:
        """计算文件 MD5"""
        try:
            md5 = hashlib.md5()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5.update(chunk)
            return md5.hexdigest()
        except:
            return ''

    def _format_size(self, size: int) -> str:
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _update_status(self, status: str, message: str):
        """更新状态（线程安全）"""
        if self.on_status_change:
            try:
                self.on_status_change(status, message)
            except:
                pass

    def _update_progress(self, progress: int, message: str):
        """更新进度（线程安全）"""
        if self.on_progress_update:
            try:
                self.on_progress_update(progress, message)
            except:
                pass


# ==================== 测试代码 ====================

if __name__ == '__main__':
    print("=" * 70)
    print("行为监控沙箱 - 测试模式")
    print("=" * 70)

    sandbox = SandboxManager()

    # 设置回调
    sandbox.on_status_change = lambda s, m: print(f"[状态] {s}: {m}")
    sandbox.on_progress_update = lambda p, m: print(f"[进度] {p}%: {m}")

    print("\n沙箱管理器已初始化")
    print("可用方法:")
    print("  - start_analysis(exe_path, args, timeout)")
    print("  - stop_analysis()")
    print("  - get_results()")
    print("  - get_summary()")
    print("  - generate_report(format)")
