#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows 事件日志读取器
用于查询 Sysmon 和 Security 日志中的进程创建事件
"""

import subprocess
import json
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from console_logger import console_log


class EventLogReader:
    """Windows 事件日志读取器"""

    # Sysmon 事件 ID
    SYSMON_PROCESS_CREATE = 1
    SYSMON_PROCESS_TERMINATE = 5

    # Security 日志事件 ID
    SECURITY_PROCESS_CREATE = 4688

    def __init__(self):
        self._sysmon_available = None
        self._security_available = None
        self._cache = {}  # 缓存查询结果

    def check_sysmon_installed(self) -> bool:
        """检查 Sysmon 是否安装并运行"""
        if self._sysmon_available is not None:
            return self._sysmon_available

        try:
            # 检查 Sysmon 服务状态
            result = subprocess.run(
                ['sc', 'query', 'Sysmon64'],
                capture_output=True, text=True, timeout=5
            )
            if 'RUNNING' in result.stdout:
                self._sysmon_available = True
                return True

            # 尝试 32 位版本
            result = subprocess.run(
                ['sc', 'query', 'Sysmon'],
                capture_output=True, text=True, timeout=5
            )
            self._sysmon_available = 'RUNNING' in result.stdout
            return self._sysmon_available
        except Exception as e:
            console_log(f"检查 Sysmon 失败: {e}", "WARNING")
            self._sysmon_available = False
            return False

    def check_security_log_available(self) -> bool:
        """检查是否有权限读取 Security 日志"""
        if self._security_available is not None:
            return self._security_available

        try:
            # 尝试查询最近一条 Security 日志
            ps_script = '''
            try {
                Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null
                Write-Output "OK"
            } catch {
                Write-Output "FAIL"
            }
            '''
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True, text=True, timeout=10
            )
            self._security_available = 'OK' in result.stdout
            return self._security_available
        except Exception as e:
            console_log(f"检查 Security 日志权限失败: {e}", "WARNING")
            self._security_available = False
            return False

    def query_process_creation(self, pid: int, hours: int = 24) -> Optional[Dict[str, Any]]:
        """
        查询指定 PID 的进程创建事件

        优先使用 Sysmon（信息更丰富），否则使用 Security 日志

        Args:
            pid: 进程 ID
            hours: 查询最近多少小时的日志

        Returns:
            进程创建信息字典，包含父进程信息
        """
        # 检查缓存
        cache_key = f"pid_{pid}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = None

        # 优先使用 Sysmon
        if self.check_sysmon_installed():
            events = self.query_sysmon_event1(pid=pid, hours=hours)
            if events:
                result = events[0]  # 取最近的一条
                result['source'] = 'sysmon'

        # 备选 Security 日志
        if result is None and self.check_security_log_available():
            events = self.query_security_4688(pid=pid, hours=hours)
            if events:
                result = events[0]
                result['source'] = 'security'

        if result:
            self._cache[cache_key] = result

        return result

    def query_sysmon_event1(self, pid: int = None, hours: int = 24,
                           max_events: int = 100) -> List[Dict[str, Any]]:
        """
        查询 Sysmon 事件 ID 1（进程创建）

        Args:
            pid: 可选，指定查询的进程 ID
            hours: 查询最近多少小时的日志
            max_events: 最大返回事件数

        Returns:
            事件列表
        """
        # 构建 PowerShell 脚本
        if pid:
            # 查询特定 PID
            ps_script = f'''
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Microsoft-Windows-Sysmon/Operational';
    ID=1;
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {{
    $xml = [xml]$_.ToXml()
    $procId = ($xml.Event.EventData.Data | Where-Object Name -eq 'ProcessId').'#text'
    $procId -eq '{pid}'
}} | Select-Object -First 1

if ($events) {{
    $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{{
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            ProcessId = [int](($data | Where-Object Name -eq 'ProcessId').'#text')
            Image = ($data | Where-Object Name -eq 'Image').'#text'
            CommandLine = ($data | Where-Object Name -eq 'CommandLine').'#text'
            ParentProcessId = [int](($data | Where-Object Name -eq 'ParentProcessId').'#text')
            ParentImage = ($data | Where-Object Name -eq 'ParentImage').'#text'
            ParentCommandLine = ($data | Where-Object Name -eq 'ParentCommandLine').'#text'
            User = ($data | Where-Object Name -eq 'User').'#text'
            LogonId = ($data | Where-Object Name -eq 'LogonId').'#text'
            TerminalSessionId = ($data | Where-Object Name -eq 'TerminalSessionId').'#text'
            IntegrityLevel = ($data | Where-Object Name -eq 'IntegrityLevel').'#text'
            Hashes = ($data | Where-Object Name -eq 'Hashes').'#text'
            ParentUser = ($data | Where-Object Name -eq 'ParentUser').'#text'
        }}
    }} | ConvertTo-Json -Depth 3
}}
'''
        else:
            # 查询所有进程创建事件
            ps_script = f'''
Get-WinEvent -FilterHashtable @{{
    LogName='Microsoft-Windows-Sysmon/Operational';
    ID=1;
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents {max_events} -ErrorAction SilentlyContinue | ForEach-Object {{
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{{
        TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        ProcessId = [int](($data | Where-Object Name -eq 'ProcessId').'#text')
        Image = ($data | Where-Object Name -eq 'Image').'#text'
        CommandLine = ($data | Where-Object Name -eq 'CommandLine').'#text'
        ParentProcessId = [int](($data | Where-Object Name -eq 'ParentProcessId').'#text')
        ParentImage = ($data | Where-Object Name -eq 'ParentImage').'#text'
        ParentCommandLine = ($data | Where-Object Name -eq 'ParentCommandLine').'#text'
        User = ($data | Where-Object Name -eq 'User').'#text'
        IntegrityLevel = ($data | Where-Object Name -eq 'IntegrityLevel').'#text'
        Hashes = ($data | Where-Object Name -eq 'Hashes').'#text'
    }}
}} | ConvertTo-Json -Depth 3
'''

        return self._run_powershell(ps_script)

    def query_security_4688(self, pid: int = None, hours: int = 24,
                           max_events: int = 100) -> List[Dict[str, Any]]:
        """
        查询 Security 日志事件 4688（进程创建）

        注意：需要管理员权限，且需要启用审计策略

        Args:
            pid: 可选，指定查询的进程 ID
            hours: 查询最近多少小时的日志
            max_events: 最大返回事件数

        Returns:
            事件列表
        """
        if pid:
            ps_script = f'''
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security';
    ID=4688;
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {{
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $newPid = ($data | Where-Object Name -eq 'NewProcessId').'#text'
    # 4688 中 PID 是十六进制
    [int]$newPid -eq {pid}
}} | Select-Object -First 1

if ($events) {{
    $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{{
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            ProcessId = [int](($data | Where-Object Name -eq 'NewProcessId').'#text')
            Image = ($data | Where-Object Name -eq 'NewProcessName').'#text'
            CommandLine = ($data | Where-Object Name -eq 'CommandLine').'#text'
            ParentProcessId = [int](($data | Where-Object Name -eq 'ProcessId').'#text')
            ParentImage = ($data | Where-Object Name -eq 'ParentProcessName').'#text'
            ParentCommandLine = ''
            User = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
            TokenElevationType = ($data | Where-Object Name -eq 'TokenElevationType').'#text'
        }}
    }} | ConvertTo-Json -Depth 3
}}
'''
        else:
            ps_script = f'''
Get-WinEvent -FilterHashtable @{{
    LogName='Security';
    ID=4688;
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents {max_events} -ErrorAction SilentlyContinue | ForEach-Object {{
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{{
        TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        ProcessId = [int](($data | Where-Object Name -eq 'NewProcessId').'#text')
        Image = ($data | Where-Object Name -eq 'NewProcessName').'#text'
        CommandLine = ($data | Where-Object Name -eq 'CommandLine').'#text'
        ParentProcessId = [int](($data | Where-Object Name -eq 'ProcessId').'#text')
        ParentImage = ($data | Where-Object Name -eq 'ParentProcessName').'#text'
        ParentCommandLine = ''
        User = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }}
}} | ConvertTo-Json -Depth 3
'''

        return self._run_powershell(ps_script)

    def query_all_process_creations(self, hours: int = 1,
                                    max_events: int = 500) -> List[Dict[str, Any]]:
        """
        查询所有进程创建事件（用于构建进程历史缓存）

        Args:
            hours: 查询最近多少小时的日志
            max_events: 最大返回事件数

        Returns:
            事件列表
        """
        events = []

        if self.check_sysmon_installed():
            events = self.query_sysmon_event1(hours=hours, max_events=max_events)
            for e in events:
                e['source'] = 'sysmon'
        elif self.check_security_log_available():
            events = self.query_security_4688(hours=hours, max_events=max_events)
            for e in events:
                e['source'] = 'security'

        return events

    def _run_powershell(self, script: str) -> List[Dict[str, Any]]:
        """执行 PowerShell 脚本并解析 JSON 结果"""
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
                capture_output=True, text=True, timeout=30, encoding='utf-8'
            )

            if result.returncode != 0:
                if result.stderr:
                    console_log(f"PowerShell 错误: {result.stderr[:200]}", "WARNING")
                return []

            output = result.stdout.strip()
            if not output:
                return []

            # 解析 JSON
            try:
                data = json.loads(output)
                # 确保返回列表
                if isinstance(data, dict):
                    return [data]
                elif isinstance(data, list):
                    return data
                else:
                    return []
            except json.JSONDecodeError as e:
                console_log(f"JSON 解析失败: {e}", "WARNING")
                return []

        except subprocess.TimeoutExpired:
            console_log("PowerShell 查询超时", "WARNING")
            return []
        except Exception as e:
            console_log(f"执行 PowerShell 失败: {e}", "ERROR")
            return []

    def clear_cache(self):
        """清除缓存"""
        self._cache.clear()

    def get_data_source_info(self) -> Dict[str, Any]:
        """获取数据源可用性信息"""
        return {
            'sysmon_available': self.check_sysmon_installed(),
            'security_available': self.check_security_log_available(),
            'primary_source': 'sysmon' if self.check_sysmon_installed() else
                            ('security' if self.check_security_log_available() else 'none')
        }
