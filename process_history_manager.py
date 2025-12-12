#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程历史管理器
用于追踪已退出进程的信息，解决父进程已退出无法追溯的问题
"""

import psutil
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from event_log_reader import EventLogReader
from console_logger import console_log


class ProcessHistoryManager:
    """进程历史管理器"""

    def __init__(self):
        self.event_log_reader = EventLogReader()
        self.process_cache = {}  # PID -> 进程信息
        self._initialized = False

    def get_process_info(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        获取进程信息

        优先级：
        1. 缓存
        2. psutil（如果进程仍在运行）
        3. 事件日志

        Args:
            pid: 进程 ID

        Returns:
            进程信息字典
        """
        # 1. 检查缓存
        if pid in self.process_cache:
            cached = self.process_cache[pid]
            # 更新存活状态
            cached['is_alive'] = psutil.pid_exists(pid)
            return cached

        # 2. 尝试从 psutil 获取（进程仍在运行）
        if psutil.pid_exists(pid):
            try:
                proc = psutil.Process(pid)
                info = self._get_process_info_from_psutil(proc)
                if info:
                    self.process_cache[pid] = info
                    return info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # 3. 从事件日志获取
        event = self.event_log_reader.query_process_creation(pid)
        if event:
            info = self._convert_event_to_info(event)
            info['is_alive'] = False  # 从事件日志获取的，进程已退出
            self.process_cache[pid] = info
            return info

        return None

    def get_parent_info(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        获取父进程信息（即使父进程已退出）

        Args:
            pid: 子进程 ID

        Returns:
            父进程信息字典
        """
        # 先获取子进程信息，从中得到父进程 PID
        child_info = self.get_process_info(pid)
        if not child_info:
            return None

        parent_pid = child_info.get('parent_pid')
        if not parent_pid or parent_pid == 0:
            return None

        # 如果子进程信息来自事件日志，已经包含了父进程详细信息
        if child_info.get('source') in ('sysmon', 'security'):
            parent_name = child_info.get('parent_name')
            parent_exe = child_info.get('parent_exe_path')
            parent_cmdline = child_info.get('parent_cmdline')

            if parent_name or parent_exe:
                return {
                    'pid': parent_pid,
                    'name': parent_name or os.path.basename(parent_exe or ''),
                    'exe_path': parent_exe or '',
                    'cmdline': parent_cmdline or '',
                    'parent_pid': None,  # 需要进一步查询
                    'parent_name': None,
                    'parent_exe_path': None,
                    'parent_cmdline': None,
                    'user': None,
                    'create_time': None,
                    'is_alive': psutil.pid_exists(parent_pid),
                    'source': child_info.get('source') + '_parent'
                }

        # 否则，尝试获取父进程信息
        return self.get_process_info(parent_pid)

    def get_process_chain(self, pid: int, max_depth: int = 10) -> List[Dict[str, Any]]:
        """
        获取进程创建链（从目标进程追溯到根）

        Args:
            pid: 目标进程 ID
            max_depth: 最大追溯深度

        Returns:
            进程链列表，第一个是目标进程，最后一个是最早的祖先进程
        """
        chain = []
        visited = set()
        current_pid = pid

        for _ in range(max_depth):
            if current_pid in visited or current_pid == 0:
                break

            visited.add(current_pid)

            # 获取当前进程信息
            info = self.get_process_info(current_pid)
            if not info:
                # 尝试从事件日志获取
                event = self.event_log_reader.query_process_creation(current_pid)
                if event:
                    info = self._convert_event_to_info(event)
                    info['is_alive'] = psutil.pid_exists(current_pid)
                else:
                    # 无法获取信息，创建占位符
                    info = {
                        'pid': current_pid,
                        'name': f'Unknown (PID: {current_pid})',
                        'exe_path': '',
                        'cmdline': '',
                        'parent_pid': None,
                        'parent_name': None,
                        'parent_exe_path': None,
                        'parent_cmdline': None,
                        'user': None,
                        'create_time': None,
                        'is_alive': psutil.pid_exists(current_pid),
                        'source': 'unknown'
                    }

            chain.append(info)

            # 获取父进程 PID
            parent_pid = info.get('parent_pid')
            if not parent_pid or parent_pid == 0:
                break

            current_pid = parent_pid

        return chain

    def refresh_cache(self):
        """刷新缓存，添加当前所有活动进程"""
        console_log("正在刷新进程缓存...", "INFO")
        count = 0

        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                pid = proc.pid
                if pid not in self.process_cache:
                    info = self._get_process_info_from_psutil(proc)
                    if info:
                        self.process_cache[pid] = info
                        count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        console_log(f"缓存刷新完成，新增 {count} 个进程", "INFO")

    def load_from_event_log(self, hours: int = 24, max_events: int = 500):
        """
        从事件日志加载历史进程信息

        Args:
            hours: 查询最近多少小时
            max_events: 最大事件数
        """
        console_log(f"正在从事件日志加载历史进程（最近 {hours} 小时）...", "INFO")

        events = self.event_log_reader.query_all_process_creations(
            hours=hours, max_events=max_events
        )

        count = 0
        for event in events:
            info = self._convert_event_to_info(event)
            pid = info.get('pid')
            if pid and pid not in self.process_cache:
                info['is_alive'] = psutil.pid_exists(pid)
                self.process_cache[pid] = info
                count += 1

        console_log(f"从事件日志加载了 {count} 个历史进程记录", "INFO")

    def _get_process_info_from_psutil(self, proc: psutil.Process) -> Optional[Dict[str, Any]]:
        """从 psutil Process 对象获取进程信息"""
        try:
            pid = proc.pid

            # 获取基本信息
            name = proc.name()
            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe_path = ''

            try:
                cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = ''

            try:
                ppid = proc.ppid()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                ppid = 0

            try:
                user = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                user = ''

            try:
                create_time = datetime.fromtimestamp(proc.create_time())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                create_time = None

            # 尝试获取父进程信息
            parent_name = ''
            parent_exe_path = ''
            parent_cmdline = ''

            if ppid and ppid != 0:
                try:
                    parent_proc = psutil.Process(ppid)
                    parent_name = parent_proc.name()
                    try:
                        parent_exe_path = parent_proc.exe()
                    except:
                        pass
                    try:
                        parent_cmdline = ' '.join(parent_proc.cmdline()) if parent_proc.cmdline() else ''
                    except:
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            return {
                'pid': pid,
                'name': name,
                'exe_path': exe_path,
                'cmdline': cmdline,
                'parent_pid': ppid,
                'parent_name': parent_name,
                'parent_exe_path': parent_exe_path,
                'parent_cmdline': parent_cmdline,
                'user': user,
                'create_time': create_time,
                'is_alive': True,
                'source': 'psutil'
            }

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _convert_event_to_info(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """将事件日志数据转换为进程信息格式"""
        image = event.get('Image', '')
        parent_image = event.get('ParentImage', '')

        # 解析时间
        create_time = None
        time_str = event.get('TimeCreated')
        if time_str:
            try:
                create_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
            except:
                pass

        return {
            'pid': event.get('ProcessId'),
            'name': os.path.basename(image) if image else '',
            'exe_path': image,
            'cmdline': event.get('CommandLine', ''),
            'parent_pid': event.get('ParentProcessId'),
            'parent_name': os.path.basename(parent_image) if parent_image else '',
            'parent_exe_path': parent_image,
            'parent_cmdline': event.get('ParentCommandLine', ''),
            'user': event.get('User', ''),
            'create_time': create_time,
            'is_alive': False,  # 从事件日志获取的，假设已退出
            'source': event.get('source', 'event_log'),
            'integrity_level': event.get('IntegrityLevel', ''),
            'hashes': event.get('Hashes', '')
        }

    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        total = len(self.process_cache)
        alive = sum(1 for p in self.process_cache.values() if p.get('is_alive'))
        exited = total - alive

        sources = {}
        for p in self.process_cache.values():
            src = p.get('source', 'unknown')
            sources[src] = sources.get(src, 0) + 1

        return {
            'total': total,
            'alive': alive,
            'exited': exited,
            'by_source': sources
        }

    def clear_cache(self):
        """清除缓存"""
        self.process_cache.clear()
        self.event_log_reader.clear_cache()

    def get_data_source_info(self) -> Dict[str, Any]:
        """获取数据源可用性信息"""
        return self.event_log_reader.get_data_source_info()
