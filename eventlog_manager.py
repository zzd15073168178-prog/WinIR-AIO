#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows 事件日志管理器
用于查询和分析 Security、System、Sysmon 等日志
"""

import subprocess
import json
import re
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from console_logger import console_log


class EventLogManager:
    """Windows 事件日志管理器"""

    # 登录类型说明
    LOGON_TYPES = {
        '2': '交互式登录',
        '3': '网络登录',
        '4': '批处理登录',
        '5': '服务登录',
        '7': '解锁',
        '8': '网络明文',
        '9': '新凭据',
        '10': '远程交互(RDP)',
        '11': '缓存交互',
    }

    # Security 日志事件
    SECURITY_EVENTS = {
        4624: ('登录成功', 'logon'),
        4625: ('登录失败', 'logon'),
        4634: ('注销', 'logon'),
        4648: ('显式凭据登录', 'logon'),
        4672: ('特权登录', 'logon'),
        4688: ('进程创建', 'process'),
        4689: ('进程终止', 'process'),
        4720: ('账户创建', 'account'),
        4722: ('账户启用', 'account'),
        4723: ('密码修改尝试', 'account'),
        4724: ('密码重置', 'account'),
        4725: ('账户禁用', 'account'),
        4726: ('账户删除', 'account'),
        4732: ('加入管理员组', 'account'),
        4733: ('从管理员组移除', 'account'),
        4738: ('账户修改', 'account'),
        4776: ('NTLM认证', 'logon'),
    }

    # System 日志事件
    SYSTEM_EVENTS = {
        7045: ('服务安装', 'service'),
        7040: ('服务启动类型变更', 'service'),
        7036: ('服务状态变更', 'service'),
    }

    # Sysmon 日志事件
    SYSMON_EVENTS = {
        1: ('进程创建', 'process'),
        2: ('文件创建时间修改', 'file'),
        3: ('网络连接', 'network'),
        5: ('进程终止', 'process'),
        6: ('驱动加载', 'driver'),
        7: ('镜像加载', 'process'),
        8: ('CreateRemoteThread', 'injection'),
        10: ('进程访问', 'injection'),
        11: ('文件创建', 'file'),
        12: ('注册表操作', 'registry'),
        13: ('注册表值设置', 'registry'),
        14: ('注册表重命名', 'registry'),
        15: ('文件流创建', 'file'),
        22: ('DNS查询', 'network'),
    }

    def __init__(self):
        self._cache = {}
        self._has_admin = None
        self._has_sysmon = None

    def check_admin_rights(self) -> bool:
        """检查是否有管理员权限（读取 Security 日志需要）"""
        if self._has_admin is not None:
            return self._has_admin

        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null; Write-Output "OK"'],
                capture_output=True, text=True, timeout=10
            )
            self._has_admin = 'OK' in result.stdout
        except:
            self._has_admin = False

        return self._has_admin

    def check_sysmon_available(self) -> bool:
        """检查 Sysmon 日志是否可用"""
        if self._has_sysmon is not None:
            return self._has_sysmon

        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop | Out-Null; Write-Output "OK"'],
                capture_output=True, text=True, timeout=10
            )
            self._has_sysmon = 'OK' in result.stdout
        except:
            self._has_sysmon = False

        return self._has_sysmon

    def query_logon_events(self, hours: int = 24, include_failed: bool = True,
                          max_events: int = 500) -> List[Dict[str, Any]]:
        """
        查询登录事件（4624/4625）

        Args:
            hours: 查询最近多少小时
            include_failed: 是否包含登录失败事件
            max_events: 最大返回事件数

        Returns:
            登录事件列表
        """
        event_ids = '4624,4625' if include_failed else '4624'

        ps_script = f'''
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security';
    ID={event_ids};
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents {max_events} -ErrorAction SilentlyContinue

if ($events) {{
    $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{{
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId = $_.Id
            LogonType = ($data | Where-Object Name -eq 'LogonType').'#text'
            TargetUserName = ($data | Where-Object Name -eq 'TargetUserName').'#text'
            TargetDomainName = ($data | Where-Object Name -eq 'TargetDomainName').'#text'
            IpAddress = ($data | Where-Object Name -eq 'IpAddress').'#text'
            WorkstationName = ($data | Where-Object Name -eq 'WorkstationName').'#text'
            LogonProcessName = ($data | Where-Object Name -eq 'LogonProcessName').'#text'
            AuthenticationPackageName = ($data | Where-Object Name -eq 'AuthenticationPackageName').'#text'
            Status = ($data | Where-Object Name -eq 'Status').'#text'
            SubStatus = ($data | Where-Object Name -eq 'SubStatus').'#text'
            FailureReason = ($data | Where-Object Name -eq 'FailureReason').'#text'
        }}
    }} | ConvertTo-Json -Depth 3
}}
'''
        events = self._run_powershell(ps_script)

        # 添加事件类型描述
        for event in events:
            event['EventType'] = 'logon'
            event_id = event.get('EventId')
            if event_id == 4624:
                event['EventName'] = '登录成功'
            elif event_id == 4625:
                event['EventName'] = '登录失败'

            # 登录类型描述
            logon_type = str(event.get('LogonType', ''))
            event['LogonTypeDesc'] = self.LOGON_TYPES.get(logon_type, logon_type)

        return events

    def query_process_events(self, hours: int = 24, max_events: int = 500,
                            use_sysmon: bool = True) -> List[Dict[str, Any]]:
        """
        查询进程创建事件

        优先使用 Sysmon（信息更丰富），否则使用 Security 日志 4688

        Args:
            hours: 查询最近多少小时
            max_events: 最大返回事件数
            use_sysmon: 是否优先使用 Sysmon

        Returns:
            进程创建事件列表
        """
        if use_sysmon and self.check_sysmon_available():
            return self._query_sysmon_process(hours, max_events)
        else:
            return self._query_security_process(hours, max_events)

    def _query_sysmon_process(self, hours: int, max_events: int) -> List[Dict[str, Any]]:
        """查询 Sysmon 进程创建事件"""
        ps_script = f'''
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Microsoft-Windows-Sysmon/Operational';
    ID=1;
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents {max_events} -ErrorAction SilentlyContinue

if ($events) {{
    $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{{
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId = 1
            EventSource = 'Sysmon'
            ProcessId = ($data | Where-Object Name -eq 'ProcessId').'#text'
            Image = ($data | Where-Object Name -eq 'Image').'#text'
            CommandLine = ($data | Where-Object Name -eq 'CommandLine').'#text'
            User = ($data | Where-Object Name -eq 'User').'#text'
            ParentProcessId = ($data | Where-Object Name -eq 'ParentProcessId').'#text'
            ParentImage = ($data | Where-Object Name -eq 'ParentImage').'#text'
            ParentCommandLine = ($data | Where-Object Name -eq 'ParentCommandLine').'#text'
            IntegrityLevel = ($data | Where-Object Name -eq 'IntegrityLevel').'#text'
            Hashes = ($data | Where-Object Name -eq 'Hashes').'#text'
        }}
    }} | ConvertTo-Json -Depth 3
}}
'''
        events = self._run_powershell(ps_script)
        for event in events:
            event['EventType'] = 'process'
            event['EventName'] = '进程创建'
        return events

    def _query_security_process(self, hours: int, max_events: int) -> List[Dict[str, Any]]:
        """查询 Security 日志进程创建事件 4688"""
        ps_script = f'''
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security';
    ID=4688;
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents {max_events} -ErrorAction SilentlyContinue

if ($events) {{
    $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{{
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId = 4688
            EventSource = 'Security'
            ProcessId = ($data | Where-Object Name -eq 'NewProcessId').'#text'
            Image = ($data | Where-Object Name -eq 'NewProcessName').'#text'
            CommandLine = ($data | Where-Object Name -eq 'CommandLine').'#text'
            User = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
            ParentProcessId = ($data | Where-Object Name -eq 'ProcessId').'#text'
            ParentImage = ($data | Where-Object Name -eq 'ParentProcessName').'#text'
            TokenElevationType = ($data | Where-Object Name -eq 'TokenElevationType').'#text'
        }}
    }} | ConvertTo-Json -Depth 3
}}
'''
        events = self._run_powershell(ps_script)
        for event in events:
            event['EventType'] = 'process'
            event['EventName'] = '进程创建'
        return events

    def query_account_events(self, hours: int = 24, max_events: int = 200) -> List[Dict[str, Any]]:
        """
        查询账户变更事件

        Args:
            hours: 查询最近多少小时
            max_events: 最大返回事件数

        Returns:
            账户变更事件列表
        """
        ps_script = f'''
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security';
    ID=4720,4722,4723,4724,4725,4726,4732,4733,4738;
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents {max_events} -ErrorAction SilentlyContinue

if ($events) {{
    $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{{
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId = $_.Id
            TargetUserName = ($data | Where-Object Name -eq 'TargetUserName').'#text'
            TargetDomainName = ($data | Where-Object Name -eq 'TargetDomainName').'#text'
            SubjectUserName = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
            SubjectDomainName = ($data | Where-Object Name -eq 'SubjectDomainName').'#text'
            MemberName = ($data | Where-Object Name -eq 'MemberName').'#text'
            MemberSid = ($data | Where-Object Name -eq 'MemberSid').'#text'
            TargetSid = ($data | Where-Object Name -eq 'TargetSid').'#text'
            PrivilegeList = ($data | Where-Object Name -eq 'PrivilegeList').'#text'
        }}
    }} | ConvertTo-Json -Depth 3
}}
'''
        events = self._run_powershell(ps_script)

        # 添加事件描述
        event_names = {
            4720: '账户创建',
            4722: '账户启用',
            4723: '密码修改尝试',
            4724: '密码重置',
            4725: '账户禁用',
            4726: '账户删除',
            4732: '加入管理员组',
            4733: '从管理员组移除',
            4738: '账户修改',
        }

        for event in events:
            event['EventType'] = 'account'
            event['EventName'] = event_names.get(event.get('EventId'), '账户事件')

        return events

    def query_service_events(self, hours: int = 24, max_events: int = 200) -> List[Dict[str, Any]]:
        """
        查询服务相关事件

        Args:
            hours: 查询最近多少小时
            max_events: 最大返回事件数

        Returns:
            服务事件列表
        """
        ps_script = f'''
$events = Get-WinEvent -FilterHashtable @{{
    LogName='System';
    ID=7045,7040;
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents {max_events} -ErrorAction SilentlyContinue

if ($events) {{
    $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{{
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId = $_.Id
            ServiceName = ($data | Where-Object Name -eq 'ServiceName').'#text'
            ImagePath = ($data | Where-Object Name -eq 'ImagePath').'#text'
            ServiceType = ($data | Where-Object Name -eq 'ServiceType').'#text'
            StartType = ($data | Where-Object Name -eq 'StartType').'#text'
            AccountName = ($data | Where-Object Name -eq 'AccountName').'#text'
        }}
    }} | ConvertTo-Json -Depth 3
}}
'''
        events = self._run_powershell(ps_script)

        event_names = {
            7045: '服务安装',
            7040: '服务启动类型变更',
        }

        for event in events:
            event['EventType'] = 'service'
            event['EventName'] = event_names.get(event.get('EventId'), '服务事件')

        return events

    def query_sysmon_network(self, hours: int = 24, max_events: int = 500) -> List[Dict[str, Any]]:
        """
        查询 Sysmon 网络连接事件

        Args:
            hours: 查询最近多少小时
            max_events: 最大返回事件数

        Returns:
            网络连接事件列表
        """
        if not self.check_sysmon_available():
            return []

        ps_script = f'''
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Microsoft-Windows-Sysmon/Operational';
    ID=3;
    StartTime=(Get-Date).AddHours(-{hours})
}} -MaxEvents {max_events} -ErrorAction SilentlyContinue

if ($events) {{
    $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{{
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventId = 3
            Image = ($data | Where-Object Name -eq 'Image').'#text'
            User = ($data | Where-Object Name -eq 'User').'#text'
            Protocol = ($data | Where-Object Name -eq 'Protocol').'#text'
            SourceIp = ($data | Where-Object Name -eq 'SourceIp').'#text'
            SourcePort = ($data | Where-Object Name -eq 'SourcePort').'#text'
            DestinationIp = ($data | Where-Object Name -eq 'DestinationIp').'#text'
            DestinationPort = ($data | Where-Object Name -eq 'DestinationPort').'#text'
            DestinationHostname = ($data | Where-Object Name -eq 'DestinationHostname').'#text'
        }}
    }} | ConvertTo-Json -Depth 3
}}
'''
        events = self._run_powershell(ps_script)
        for event in events:
            event['EventType'] = 'network'
            event['EventName'] = '网络连接'
        return events

    def analyze_suspicious(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        分析事件并标记可疑项

        Args:
            events: 事件列表

        Returns:
            添加了可疑标记的事件列表
        """
        for event in events:
            suspicious_reasons = []
            event_type = event.get('EventType', '')

            # 登录事件分析
            if event_type == 'logon':
                suspicious_reasons.extend(self._analyze_logon_event(event))

            # 进程事件分析
            elif event_type == 'process':
                suspicious_reasons.extend(self._analyze_process_event(event))

            # 服务事件分析
            elif event_type == 'service':
                suspicious_reasons.extend(self._analyze_service_event(event))

            # 账户事件分析
            elif event_type == 'account':
                suspicious_reasons.extend(self._analyze_account_event(event))

            # 设置可疑标记
            event['is_suspicious'] = len(suspicious_reasons) > 0
            event['suspicious_reasons'] = suspicious_reasons

        return events

    def _analyze_logon_event(self, event: Dict[str, Any]) -> List[str]:
        """分析登录事件的可疑性"""
        reasons = []

        # 登录失败
        if event.get('EventId') == 4625:
            reasons.append('登录失败')

        # 非工作时间登录
        time_str = event.get('TimeCreated', '')
        if time_str:
            try:
                event_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                hour = event_time.hour
                if hour >= 22 or hour < 6:
                    reasons.append('非工作时间登录')
            except:
                pass

        # 远程登录 (RDP)
        logon_type = str(event.get('LogonType', ''))
        if logon_type == '10':
            reasons.append('RDP远程登录')

        # 外部 IP
        ip = event.get('IpAddress', '')
        if ip and ip != '-' and ip != '127.0.0.1' and ip != '::1':
            if not ip.startswith('192.168.') and not ip.startswith('10.') and not ip.startswith('172.'):
                reasons.append(f'外部IP: {ip}')

        # 敏感账户
        user = event.get('TargetUserName', '').lower()
        if user in ('administrator', 'admin', 'root', 'system'):
            if event.get('EventId') == 4625:
                reasons.append('敏感账户被尝试登录')

        return reasons

    def _analyze_process_event(self, event: Dict[str, Any]) -> List[str]:
        """分析进程事件的可疑性"""
        reasons = []

        image = (event.get('Image') or '').lower()
        cmdline = (event.get('CommandLine') or '').lower()
        parent = (event.get('ParentImage') or '').lower()

        # 敏感进程
        sensitive_procs = ['powershell', 'cmd.exe', 'wscript', 'cscript',
                          'mshta', 'regsvr32', 'rundll32', 'certutil',
                          'bitsadmin', 'msiexec']
        for proc in sensitive_procs:
            if proc in image:
                reasons.append(f'敏感进程: {proc}')
                break

        # 编码命令
        if '-enc' in cmdline or '-encodedcommand' in cmdline or '-e ' in cmdline:
            reasons.append('编码命令')

        # 下载行为
        download_patterns = ['downloadstring', 'downloadfile', 'invoke-webrequest',
                           'wget', 'curl', 'certutil', 'bitsadmin']
        for pattern in download_patterns:
            if pattern in cmdline:
                reasons.append('可能的下载行为')
                break

        # 从临时目录执行
        temp_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp',
                     '\\programdata\\', '\\users\\public\\']
        for path in temp_paths:
            if path in image:
                reasons.append('从临时目录执行')
                break

        # 可疑父进程
        suspicious_parents = ['winword', 'excel', 'powerpnt', 'outlook',
                            'wscript', 'cscript', 'mshta']
        for p in suspicious_parents:
            if p in parent:
                reasons.append(f'可疑父进程: {p}')
                break

        return reasons

    def _analyze_service_event(self, event: Dict[str, Any]) -> List[str]:
        """分析服务事件的可疑性"""
        reasons = []

        service_name = (event.get('ServiceName') or '').lower()
        image_path = (event.get('ImagePath') or '').lower()

        # 从临时目录安装的服务
        temp_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\', '\\users\\public\\']
        for path in temp_paths:
            if path in image_path:
                reasons.append('服务路径在临时目录')
                break

        # 随机服务名（包含大量数字或特殊字符）
        if service_name and len(service_name) > 8:
            digit_count = sum(1 for c in service_name if c.isdigit())
            if digit_count > len(service_name) * 0.4:
                reasons.append('服务名包含大量数字')

        # PowerShell 或 CMD 作为服务
        if 'powershell' in image_path or 'cmd.exe' in image_path:
            reasons.append('脚本类型服务')

        return reasons

    def _analyze_account_event(self, event: Dict[str, Any]) -> List[str]:
        """分析账户事件的可疑性"""
        reasons = []

        event_id = event.get('EventId')

        # 账户创建
        if event_id == 4720:
            reasons.append('新账户创建')

        # 加入管理员组
        if event_id == 4732:
            reasons.append('用户被加入管理员组')

        # 非工作时间
        time_str = event.get('TimeCreated', '')
        if time_str:
            try:
                event_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                hour = event_time.hour
                if hour >= 22 or hour < 6:
                    reasons.append('非工作时间操作')
            except:
                pass

        return reasons

    def _run_powershell(self, script: str) -> List[Dict[str, Any]]:
        """执行 PowerShell 脚本并解析 JSON 结果"""
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
                capture_output=True, text=True, timeout=60, encoding='utf-8'
            )

            if result.returncode != 0:
                if result.stderr:
                    console_log(f"PowerShell 错误: {result.stderr[:200]}", "WARNING")
                return []

            output = result.stdout.strip()
            if not output:
                return []

            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    return [data]
                elif isinstance(data, list):
                    return data
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

    def get_available_logs(self) -> Dict[str, bool]:
        """获取可用的日志源"""
        return {
            'security': self.check_admin_rights(),
            'system': True,  # System 日志通常可读
            'sysmon': self.check_sysmon_available(),
        }

    def get_event_summary(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """获取事件统计摘要"""
        summary = {
            'total': len(events),
            'suspicious': sum(1 for e in events if e.get('is_suspicious')),
            'by_type': {},
            'by_event_id': {},
        }

        for event in events:
            # 按类型统计
            event_type = event.get('EventType', 'unknown')
            summary['by_type'][event_type] = summary['by_type'].get(event_type, 0) + 1

            # 按事件ID统计
            event_id = event.get('EventId')
            if event_id:
                summary['by_event_id'][event_id] = summary['by_event_id'].get(event_id, 0) + 1

        return summary
