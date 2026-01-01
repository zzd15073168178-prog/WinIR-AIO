#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
行为监控沙箱管理器 V2
增强版：集成 Autoruns 持久化检测

持久化检测支持两种模式:
- 'builtin': 使用内置 Python 检测器（快速，覆盖主要位置）
- 'autoruns': 使用微软 Autoruns 工具（全面，覆盖 100+ 位置）
- 'both': 两者都用（最全面）
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
from enum import Enum

from monitor_manager import MonitorManager
from persistence_detector import PersistenceDetector
from network_manager import NetworkManager
from utils.validation import sanitize_executable_path, sanitize_args, sanitize_pid

# 尝试导入 Autoruns 检测器
try:
    from autoruns_detector import AutorunsDetector
    AUTORUNS_AVAILABLE = True
except ImportError:
    AUTORUNS_AVAILABLE = False


class PersistenceMode(Enum):
    """持久化检测模式"""
    BUILTIN = "builtin"      # 内置 Python 检测器（快速）
    AUTORUNS = "autoruns"    # 微软 Autoruns 工具（全面）
    BOTH = "both"            # 两者都用


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


class SandboxManagerV2:
    """
    行为监控沙箱管理器 V2

    增强功能：
    - 支持 Autoruns 持久化检测（覆盖 100+ 位置）
    - 可选择检测模式：builtin / autoruns / both

    使用方法：
    ```python
    # 使用 Autoruns 检测（推荐，更全面）
    sandbox = SandboxManagerV2(persistence_mode='autoruns')

    # 使用内置检测（更快）
    sandbox = SandboxManagerV2(persistence_mode='builtin')

    # 两者都用（最全面）
    sandbox = SandboxManagerV2(persistence_mode='both')

    # 启动分析
    success, msg, pid = sandbox.start_analysis('C:\\path\\to\\sample.exe', timeout=60)

    # 等待完成或手动停止
    sandbox.stop_analysis()

    # 获取结果
    results = sandbox.get_results()
    ```
    """

    def __init__(self, persistence_mode: str = 'autoruns'):
        """
        初始化沙箱管理器

        Args:
            persistence_mode: 持久化检测模式
                - 'builtin': 内置检测器（快速）
                - 'autoruns': Autoruns 工具（全面，推荐）
                - 'both': 两者都用
        """
        # 复用现有组件
        self.monitor_manager = MonitorManager()
        self.persistence_detector = PersistenceDetector()  # 内置检测器
        self.network_manager = NetworkManager()

        # Autoruns 检测器
        self.autoruns_detector: Optional[AutorunsDetector] = None
        self.persistence_mode = PersistenceMode(persistence_mode)

        # 初始化 Autoruns 检测器
        if self.persistence_mode in (PersistenceMode.AUTORUNS, PersistenceMode.BOTH):
            if AUTORUNS_AVAILABLE:
                try:
                    self.autoruns_detector = AutorunsDetector()
                    print(f"[沙箱] Autoruns 检测器已加载: {self.autoruns_detector.autoruns_path}")
                except FileNotFoundError as e:
                    print(f"[沙箱] 警告: {e}")
                    print("[沙箱] 将使用内置检测器")
                    self.persistence_mode = PersistenceMode.BUILTIN
            else:
                print("[沙箱] 警告: Autoruns 模块不可用，将使用内置检测器")
                self.persistence_mode = PersistenceMode.BUILTIN

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
            'persistence_changes': [],     # 持久化变化（内置检测器）
            'autoruns_changes': [],        # 持久化变化（Autoruns）
            'file_operations': [],         # 所有文件操作（原始）
        }

        # 回调函数
        self.on_status_change: Optional[Callable[[str, str], None]] = None
        self.on_progress_update: Optional[Callable[[int, str], None]] = None
        self.on_complete: Optional[Callable[[Dict], None]] = None
        self.on_new_process: Optional[Callable[[Dict], None]] = None  # 新进程回调

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

            # 保存参数
            self.target_exe_path = safe_path
            self.target_args = args
            self.working_dir = working_dir or os.path.dirname(safe_path)
            self.timeout = timeout

            # 清空旧结果
            self._clear_results()

            # 获取初始状态
            self._update_progress(8, "获取初始进程列表")
            self.initial_pids = set(p.pid for p in psutil.process_iter())
            self.initial_connections = self.network_manager.get_all_connections()

            # 获取持久化初始快照
            self._update_status("snapshot", "正在获取系统快照...")
            self._take_persistence_snapshot(is_initial=True)

            # 启动 Procmon 监控
            self._update_progress(30, "启动 Procmon 监控")
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

            # 安全执行
            cmd_list = [safe_path] + args_list
            self.target_process = subprocess.Popen(
                cmd_list,
                shell=False,
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
            if self.monitor_manager.is_monitoring:
                self.monitor_manager.stop_monitor()
            self._update_status("error", f"启动失败: {e}")
            return False, f"启动分析失败: {str(e)}", None

    def _take_persistence_snapshot(self, is_initial: bool = True):
        """
        获取持久化快照

        Args:
            is_initial: 是否为初始快照
        """
        action = "初始" if is_initial else "最终"

        # 内置检测器
        if self.persistence_mode in (PersistenceMode.BUILTIN, PersistenceMode.BOTH):
            self._update_progress(10 if is_initial else 70, f"[内置] 获取{action}快照...")
            if is_initial:
                self.persistence_detector.take_initial_snapshot()
            else:
                self.persistence_detector.take_final_snapshot()

        # Autoruns 检测器
        if self.persistence_mode in (PersistenceMode.AUTORUNS, PersistenceMode.BOTH):
            if self.autoruns_detector:
                self._update_progress(15 if is_initial else 72, f"[Autoruns] 获取{action}快照（可能需要 30-60 秒）...")
                if is_initial:
                    self.autoruns_detector.take_initial_snapshot()
                else:
                    self.autoruns_detector.take_final_snapshot()

    def stop_analysis(self) -> Tuple[bool, str]:
        """停止沙箱分析"""
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

        # 合并持久化变化数量
        persistence_count = len(self.results['persistence_changes'])
        autoruns_count = len(self.results['autoruns_changes'])
        total_persistence = persistence_count + autoruns_count

        return {
            'target_file': self.target_exe_path,
            'target_args': self.target_args,
            'target_pid': self.target_pid,
            'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else None,
            'end_time': self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else None,
            'duration': duration,
            'persistence_mode': self.persistence_mode.value,
            'dropped_files_count': len(self.results['dropped_files']),
            'executable_files_count': len(self.results['executable_files']),
            'spawned_processes_count': len(self.results['spawned_processes']),
            'network_connections_count': len(self.results['network_connections']),
            'registry_modifications_count': len(self.results['registry_modifications']),
            'persistence_changes_count': total_persistence,
            'persistence_builtin_count': persistence_count,
            'persistence_autoruns_count': autoruns_count,
            'tracked_pids': list(self.tracked_pids),
        }

    def get_all_persistence_changes(self) -> List[Dict]:
        """获取所有持久化变化（合并两个检测器的结果）"""
        all_changes = []

        # 内置检测器的结果
        for change in self.results['persistence_changes']:
            change_copy = change.copy()
            change_copy['source'] = 'builtin'
            all_changes.append(change_copy)

        # Autoruns 的结果
        for change in self.results['autoruns_changes']:
            change_copy = change.copy() if isinstance(change, dict) else change.to_dict()
            change_copy['source'] = 'autoruns'
            all_changes.append(change_copy)

        return all_changes

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
            'autoruns_changes': [],
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
        """监控循环"""
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
                time.sleep(3)
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

                    if parent_pid in self.tracked_pids:
                        self.tracked_pids.add(pid)

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

                        if not any(p['pid'] == pid for p in self.results['spawned_processes']):
                            self.results['spawned_processes'].append(proc_info)

                            # 新进程回调
                            if self.on_new_process:
                                try:
                                    self.on_new_process(proc_info)
                                except:
                                    pass

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

        if self.target_process:
            try:
                self.target_process.terminate()
                self.target_process.wait(timeout=5)
            except:
                try:
                    self.target_process.kill()
                except:
                    pass

        for proc in self.results['spawned_processes']:
            proc['status'] = 'exited'

    def _finalize_analysis(self):
        """完成分析"""
        self._update_status("analyzing", "正在分析结果...")

        # 获取最终持久化快照并对比
        self._take_persistence_snapshot(is_initial=False)

        # 内置检测器对比
        if self.persistence_mode in (PersistenceMode.BUILTIN, PersistenceMode.BOTH):
            self._update_progress(75, "[内置] 对比持久化变化")
            changes = self.persistence_detector.detect_changes()
            self.results['persistence_changes'] = changes

        # Autoruns 对比
        if self.persistence_mode in (PersistenceMode.AUTORUNS, PersistenceMode.BOTH):
            if self.autoruns_detector:
                self._update_progress(78, "[Autoruns] 对比持久化变化")
                autoruns_changes = self.autoruns_detector.detect_changes()
                # 转换为字典格式
                self.results['autoruns_changes'] = [
                    c.to_dict() if hasattr(c, 'to_dict') else c
                    for c in autoruns_changes
                ]

        # 解析 Procmon 日志
        self._update_progress(85, "解析 Procmon 日志")
        self._parse_procmon_log()

        # 提取释放的文件
        self._update_progress(92, "提取释放文件")
        self._extract_dropped_files()

        # 完成
        self._update_progress(100, "分析完成")
        self._update_status("completed", "分析完成")

        if self.on_complete:
            self.on_complete(self.results)

    def _parse_procmon_log(self):
        """解析 Procmon 日志"""
        if not self.procmon_log_file or not os.path.exists(self.procmon_log_file):
            return

        try:
            success, message, csv_file = self.monitor_manager.export_log_to_csv(self.procmon_log_file)
            if not success or not csv_file or not os.path.exists(csv_file):
                return

            self.procmon_csv_file = csv_file

            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    try:
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
                                if not any(f['path'] == path and f['operation'] == operation
                                          for f in self.results['file_operations']):
                                    self.results['file_operations'].append(file_info)

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

            if 'Write' not in operation and 'Create' not in operation:
                continue

            if path.lower() in seen_paths:
                continue
            seen_paths.add(path.lower())

            if not os.path.exists(path):
                continue

            if os.path.isdir(path):
                continue

            try:
                stat = os.stat(path)
                size = stat.st_size
                md5_hash = self._calculate_md5(path)
                is_exe, exe_type = self._is_executable_file(path)
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
        """更新状态"""
        if self.on_status_change:
            try:
                self.on_status_change(status, message)
            except:
                pass

    def _update_progress(self, progress: int, message: str):
        """更新进度"""
        if self.on_progress_update:
            try:
                self.on_progress_update(progress, message)
            except:
                pass

    # ==================== 报告生成 ====================

    def generate_report(self, format: str = 'html') -> Tuple[bool, str, Optional[str]]:
        """生成分析报告"""
        report_data = {
            'summary': self.get_summary(),
            'dropped_files': self.results['dropped_files'],
            'executable_files': self.results['executable_files'],
            'spawned_processes': self.results['spawned_processes'],
            'network_connections': self.results['network_connections'],
            'registry_modifications': self.results['registry_modifications'],
            'persistence_changes': self.get_all_persistence_changes(),
        }

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
        """生成 HTML 报告"""
        summary = data.get('summary', {})
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>行为沙箱分析报告 (V2)</title>
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
        .autoruns-badge {{ background: #9b59b6; color: white; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
        .builtin-badge {{ background: #3498db; color: white; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>行为沙箱分析报告 (V2 - Autoruns 增强版)</h1>

    <div class="summary-box">
        <h2>分析摘要</h2>
        <p><strong>目标文件:</strong> {summary.get('target_file', 'N/A')}</p>
        <p><strong>命令参数:</strong> {summary.get('target_args', 'N/A')}</p>
        <p><strong>目标 PID:</strong> {summary.get('target_pid', 'N/A')}</p>
        <p><strong>持久化检测模式:</strong> {summary.get('persistence_mode', 'N/A')}</p>
        <p><strong>开始时间:</strong> {summary.get('start_time', 'N/A')}</p>
        <p><strong>结束时间:</strong> {summary.get('end_time', 'N/A')}</p>
        <p><strong>分析时长:</strong> {summary.get('duration', 0):.1f} 秒</p>
        <div>
            <span class="summary-item"><span class="summary-value">{summary.get('dropped_files_count', 0)}</span> 释放文件</span>
            <span class="summary-item"><span class="summary-value">{summary.get('executable_files_count', 0)}</span> 可执行文件</span>
            <span class="summary-item"><span class="summary-value">{summary.get('spawned_processes_count', 0)}</span> 进程</span>
            <span class="summary-item"><span class="summary-value">{summary.get('network_connections_count', 0)}</span> 网络连接</span>
            <span class="summary-item"><span class="summary-value">{summary.get('persistence_changes_count', 0)}</span> 持久化变化</span>
        </div>
    </div>
'''
        # 持久化变化
        if data.get('persistence_changes'):
            html += '''
    <h2>持久化变化</h2>
    <table>
        <tr><th>来源</th><th>类型</th><th>操作</th><th>位置</th><th>值</th><th>严重性</th></tr>
'''
            for p in data['persistence_changes']:
                severity = p.get('severity', 'info')
                source = p.get('source', 'unknown')
                badge_class = 'autoruns-badge' if source == 'autoruns' else 'builtin-badge'
                value = p.get('value', p.get('entry', ''))
                if isinstance(value, dict):
                    value = str(value)[:100]
                html += f'''        <tr class="{severity}">
            <td><span class="{badge_class}">{source}</span></td>
            <td>{p.get('type', '')}</td>
            <td>{p.get('action', '')}</td>
            <td>{p.get('location', '')[:60]}</td>
            <td>{str(value)[:80]}</td>
            <td>{severity}</td>
        </tr>
'''
            html += '    </table>\n'

        # 释放文件
        if data.get('dropped_files'):
            html += '''
    <h2>释放文件</h2>
    <table>
        <tr><th>文件名</th><th>类型</th><th>大小</th><th>MD5</th><th>路径</th></tr>
'''
            for f in data['dropped_files']:
                html += f'''        <tr>
            <td>{f.get('filename', '')}</td>
            <td>{f.get('file_type', '')}</td>
            <td>{f.get('size_str', '')}</td>
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
        <tr><th>PID</th><th>进程名</th><th>命令行</th><th>父进程</th></tr>
'''
            for p in data['spawned_processes']:
                html += f'''        <tr>
            <td>{p.get('pid', '')}</td>
            <td>{p.get('name', '')}</td>
            <td>{p.get('cmdline', '')[:100]}</td>
            <td>{p.get('parent_pid', '')}</td>
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

        html += f'''
    <hr>
    <p style="color: #666; font-size: 12px;">
        报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
        持久化检测: {summary.get('persistence_mode', 'N/A')} 模式
    </p>
</body>
</html>'''
        return html


# ==================== 测试代码 ====================

if __name__ == '__main__':
    print("=" * 70)
    print("行为监控沙箱 V2 - 集成 Autoruns")
    print("=" * 70)

    print(f"\nAutoruns 模块可用: {AUTORUNS_AVAILABLE}")

    # 测试不同模式
    for mode in ['builtin', 'autoruns', 'both']:
        print(f"\n测试模式: {mode}")
        try:
            sandbox = SandboxManagerV2(persistence_mode=mode)
            print(f"  实际模式: {sandbox.persistence_mode.value}")
            print(f"  Autoruns 检测器: {'已加载' if sandbox.autoruns_detector else '未加载'}")
        except Exception as e:
            print(f"  错误: {e}")

    print("\n" + "=" * 70)
    print("使用方法:")
    print("  sandbox = SandboxManagerV2(persistence_mode='autoruns')")
    print("  sandbox.start_analysis('C:\\\\path\\\\to\\\\sample.exe', timeout=60)")
    print("=" * 70)
