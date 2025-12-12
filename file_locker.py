#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文件解锁与强制删除管理模块"""

import os
import sys
import subprocess
import shutil
import ctypes
from ctypes import wintypes
from typing import Dict, List, Optional, Callable
import re


def get_resource_path(relative_path):
    """获取资源文件路径，兼容开发环境和 PyInstaller 打包环境"""
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller 打包后，资源文件在临时目录
        return os.path.join(sys._MEIPASS, relative_path)
    else:
        # 开发环境，使用脚本所在目录
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


class FileLocker:
    """文件解锁与强制删除管理器"""

    def __init__(self):
        self.handle_exe = self._find_handle_exe()
        self.locking_processes = []

    def _find_handle_exe(self) -> Optional[str]:
        """查找 handle.exe 工具"""
        candidates = ['handle64.exe', 'handle.exe']
        for exe in candidates:
            path = get_resource_path(exe)
            if os.path.exists(path):
                return path
        return None

    def is_tool_available(self) -> bool:
        """检查 handle.exe 是否可用"""
        return self.handle_exe is not None

    def find_locking_processes(self, file_path: str, progress_callback: Callable = None) -> List[Dict]:
        """
        查找锁定文件的进程

        Args:
            file_path: 文件或文件夹路径
            progress_callback: 进度回调

        Returns:
            锁定进程列表
        """
        self.locking_processes = []

        if not os.path.exists(file_path):
            return []

        # 方法1: 使用 handle.exe (Sysinternals)
        if self.handle_exe:
            if progress_callback:
                progress_callback("使用 handle.exe 查找...")
            self.locking_processes = self._find_with_handle_exe(file_path)

        # 方法2: 使用 Windows API (备用)
        if not self.locking_processes:
            if progress_callback:
                progress_callback("使用 Windows API 查找...")
            self.locking_processes = self._find_with_windows_api(file_path)

        return self.locking_processes

    def _find_with_handle_exe(self, file_path: str) -> List[Dict]:
        """使用 handle.exe 查找"""
        processes = []

        try:
            cmd = [self.handle_exe, '-a', '-u', '-nobanner', '-accepteula', file_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=30
            )

            # 解析输出
            # 格式: ProcessName pid: Type (RW-) HandleValue: Path
            pattern = r'^(\S+)\s+pid:\s*(\d+)\s+type:\s*(\w+)\s+(\S+):\s*(.+)$'

            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or 'No matching handles found' in line:
                    continue

                # 尝试解析
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    processes.append({
                        'name': match.group(1),
                        'pid': int(match.group(2)),
                        'type': match.group(3),
                        'handle': match.group(4),
                        'path': match.group(5)
                    })
                else:
                    # 简化格式解析
                    parts = line.split()
                    if len(parts) >= 3 and 'pid:' in line.lower():
                        try:
                            name = parts[0]
                            pid_idx = next(i for i, p in enumerate(parts) if 'pid:' in p.lower())
                            pid = int(parts[pid_idx + 1] if pid_idx + 1 < len(parts) else parts[pid_idx].split(':')[1])
                            processes.append({
                                'name': name,
                                'pid': pid,
                                'type': 'File',
                                'handle': '',
                                'path': file_path
                            })
                        except (ValueError, StopIteration):
                            pass

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return processes

    def _find_with_windows_api(self, file_path: str) -> List[Dict]:
        """使用 Windows API 查找 (Restart Manager API)"""
        processes = []

        try:
            import ctypes
            from ctypes import wintypes

            # Restart Manager API
            rstrtmgr = ctypes.WinDLL('rstrtmgr.dll')

            CCH_RM_SESSION_KEY = 33
            RM_SESSION_KEY = ctypes.c_wchar * CCH_RM_SESSION_KEY

            class RM_UNIQUE_PROCESS(ctypes.Structure):
                _fields_ = [
                    ('dwProcessId', wintypes.DWORD),
                    ('ProcessStartTime', wintypes.FILETIME)
                ]

            class RM_PROCESS_INFO(ctypes.Structure):
                _fields_ = [
                    ('Process', RM_UNIQUE_PROCESS),
                    ('strAppName', ctypes.c_wchar * 256),
                    ('strServiceShortName', ctypes.c_wchar * 64),
                    ('ApplicationType', wintypes.DWORD),
                    ('AppStatus', wintypes.DWORD),
                    ('TSSessionId', wintypes.DWORD),
                    ('bRestartable', wintypes.BOOL)
                ]

            # 函数声明
            RmStartSession = rstrtmgr.RmStartSession
            RmStartSession.restype = wintypes.DWORD
            RmStartSession.argtypes = [
                ctypes.POINTER(wintypes.DWORD),
                wintypes.DWORD,
                RM_SESSION_KEY
            ]

            RmRegisterResources = rstrtmgr.RmRegisterResources
            RmRegisterResources.restype = wintypes.DWORD
            RmRegisterResources.argtypes = [
                wintypes.DWORD,
                wintypes.UINT,
                ctypes.POINTER(ctypes.c_wchar_p),
                wintypes.UINT,
                ctypes.POINTER(RM_UNIQUE_PROCESS),
                wintypes.UINT,
                ctypes.POINTER(ctypes.c_wchar_p)
            ]

            RmGetList = rstrtmgr.RmGetList
            RmGetList.restype = wintypes.DWORD
            RmGetList.argtypes = [
                wintypes.DWORD,
                ctypes.POINTER(wintypes.UINT),
                ctypes.POINTER(wintypes.UINT),
                ctypes.POINTER(RM_PROCESS_INFO),
                ctypes.POINTER(wintypes.DWORD)
            ]

            RmEndSession = rstrtmgr.RmEndSession
            RmEndSession.restype = wintypes.DWORD
            RmEndSession.argtypes = [wintypes.DWORD]

            # 启动会话
            session_handle = wintypes.DWORD()
            session_key = RM_SESSION_KEY()

            ret = RmStartSession(ctypes.byref(session_handle), 0, session_key)
            if ret != 0:
                return processes

            try:
                # 注册资源
                files = (ctypes.c_wchar_p * 1)(file_path)
                ret = RmRegisterResources(session_handle, 1, files, 0, None, 0, None)
                if ret != 0:
                    return processes

                # 获取进程列表
                proc_needed = wintypes.UINT(0)
                proc_count = wintypes.UINT(0)
                reboot_reason = wintypes.DWORD()

                ret = RmGetList(session_handle, ctypes.byref(proc_needed),
                               ctypes.byref(proc_count), None, ctypes.byref(reboot_reason))

                if proc_needed.value > 0:
                    proc_info = (RM_PROCESS_INFO * proc_needed.value)()
                    proc_count = wintypes.UINT(proc_needed.value)

                    ret = RmGetList(session_handle, ctypes.byref(proc_needed),
                                   ctypes.byref(proc_count), proc_info, ctypes.byref(reboot_reason))

                    if ret == 0:
                        for i in range(proc_count.value):
                            processes.append({
                                'name': proc_info[i].strAppName,
                                'pid': proc_info[i].Process.dwProcessId,
                                'type': 'File',
                                'handle': '',
                                'path': file_path
                            })

            finally:
                RmEndSession(session_handle)

        except Exception:
            pass

        return processes

    def kill_process(self, pid: int, force: bool = False) -> bool:
        """
        终止进程

        Args:
            pid: 进程 ID
            force: 是否强制终止

        Returns:
            是否成功
        """
        try:
            if force:
                # 强制终止
                cmd = ['taskkill', '/F', '/PID', str(pid)]
            else:
                cmd = ['taskkill', '/PID', str(pid)]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.returncode == 0
        except Exception:
            return False

    def kill_all_locking_processes(self, force: bool = True) -> Dict:
        """
        终止所有锁定进程

        Returns:
            结果统计
        """
        results = {'success': 0, 'failed': 0, 'details': []}

        for proc in self.locking_processes:
            pid = proc['pid']
            name = proc['name']

            # 跳过系统关键进程
            if name.lower() in ['system', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe']:
                results['details'].append({
                    'pid': pid,
                    'name': name,
                    'success': False,
                    'reason': '系统关键进程，跳过'
                })
                results['failed'] += 1
                continue

            success = self.kill_process(pid, force)
            results['details'].append({
                'pid': pid,
                'name': name,
                'success': success,
                'reason': '已终止' if success else '终止失败'
            })

            if success:
                results['success'] += 1
            else:
                results['failed'] += 1

        return results

    def close_handle(self, pid: int, handle: str) -> bool:
        """
        关闭指定句柄 (使用 handle.exe -c)

        Args:
            pid: 进程 ID
            handle: 句柄值

        Returns:
            是否成功
        """
        if not self.handle_exe:
            return False

        try:
            cmd = [self.handle_exe, '-c', handle, '-p', str(pid), '-y', '-nobanner']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return 'closed' in result.stdout.lower() or result.returncode == 0
        except Exception:
            return False

    def delete_file(self, file_path: str, force: bool = False) -> Dict:
        """
        删除文件或文件夹

        Args:
            file_path: 文件路径
            force: 是否强制删除（先终止占用进程）

        Returns:
            删除结果
        """
        result = {
            'success': False,
            'path': file_path,
            'method': '',
            'error': ''
        }

        if not os.path.exists(file_path):
            result['error'] = '路径不存在'
            return result

        # 如果强制删除，先处理锁定进程
        if force:
            locking = self.find_locking_processes(file_path)
            if locking:
                self.kill_all_locking_processes(force=True)
                # 等待一下让系统释放句柄
                import time
                time.sleep(0.5)

        # 尝试删除
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                result['success'] = True
                result['method'] = 'os.remove'
            else:
                shutil.rmtree(file_path)
                result['success'] = True
                result['method'] = 'shutil.rmtree'
        except PermissionError as e:
            result['error'] = f'权限不足: {e}'
            # 尝试修改文件属性后删除
            try:
                self._remove_readonly(file_path)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                else:
                    shutil.rmtree(file_path)
                result['success'] = True
                result['method'] = '移除只读属性后删除'
            except Exception as e2:
                result['error'] = f'移除只读后仍失败: {e2}'
        except Exception as e:
            result['error'] = str(e)

        # 如果普通方法失败，尝试 cmd 的 del/rd
        if not result['success']:
            try:
                if os.path.isfile(file_path):
                    cmd = ['cmd', '/c', 'del', '/f', '/q', file_path]
                else:
                    cmd = ['cmd', '/c', 'rd', '/s', '/q', file_path]

                subprocess.run(cmd, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

                if not os.path.exists(file_path):
                    result['success'] = True
                    result['method'] = 'cmd del/rd'
                    result['error'] = ''
            except Exception:
                pass

        return result

    def schedule_delete_on_reboot(self, file_path: str) -> bool:
        """
        安排重启后删除（适用于顽固文件）

        使用 MoveFileEx API 标记文件在重启时删除
        """
        try:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            MoveFileExW = kernel32.MoveFileExW
            MoveFileExW.restype = wintypes.BOOL
            MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]

            MOVEFILE_DELAY_UNTIL_REBOOT = 0x4

            # 将目标设为 NULL 表示删除
            success = MoveFileExW(file_path, None, MOVEFILE_DELAY_UNTIL_REBOOT)

            return bool(success)
        except Exception:
            return False

    def _remove_readonly(self, path: str):
        """移除只读属性"""
        import stat

        if os.path.isfile(path):
            os.chmod(path, stat.S_IWRITE)
        else:
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    os.chmod(os.path.join(root, d), stat.S_IWRITE)
                for f in files:
                    os.chmod(os.path.join(root, f), stat.S_IWRITE)

    def get_file_info(self, file_path: str) -> Dict:
        """获取文件详细信息"""
        info = {
            'path': file_path,
            'exists': os.path.exists(file_path),
            'is_file': False,
            'is_dir': False,
            'size': 0,
            'size_str': '',
            'attributes': [],
            'owner': '',
        }

        if not info['exists']:
            return info

        try:
            info['is_file'] = os.path.isfile(file_path)
            info['is_dir'] = os.path.isdir(file_path)

            if info['is_file']:
                info['size'] = os.path.getsize(file_path)
                info['size_str'] = self._format_size(info['size'])

            # 获取文件属性
            attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
            if attrs != -1:
                if attrs & 0x1:
                    info['attributes'].append('只读')
                if attrs & 0x2:
                    info['attributes'].append('隐藏')
                if attrs & 0x4:
                    info['attributes'].append('系统')
                if attrs & 0x10:
                    info['attributes'].append('目录')
                if attrs & 0x20:
                    info['attributes'].append('归档')

        except Exception:
            pass

        return info

    @staticmethod
    def _format_size(size: int) -> str:
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}" if unit != 'B' else f"{size} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
