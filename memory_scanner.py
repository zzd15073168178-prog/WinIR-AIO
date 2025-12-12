#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进程内存扫描模块 - 扫描进程内存中的可疑字符串"""

import os
import re
import ctypes
from ctypes import wintypes
from typing import Dict, List, Callable, Optional, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import struct


@dataclass
class ScanResult:
    """扫描结果"""
    pid: int
    process_name: str
    category: str  # ip, url, domain, email, credential, c2, crypto, registry, file_path, custom
    value: str
    context: str  # 上下文
    address: int  # 内存地址
    risk_level: str  # low, medium, high, critical


class MemoryScanner:
    """进程内存扫描器"""

    # Windows API 常量
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    PAGE_READABLE = (0x02 | 0x04 | 0x20 | 0x40 | 0x80)  # PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY

    # 预定义的正则表达式模式
    PATTERNS = {
        'ipv4': {
            'pattern': rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'risk': 'medium',
            'description': 'IPv4 地址'
        },
        'ipv6': {
            'pattern': rb'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'risk': 'medium',
            'description': 'IPv6 地址'
        },
        'url': {
            'pattern': rb'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\x00"\'<>]*)?',
            'risk': 'medium',
            'description': 'URL'
        },
        'domain': {
            'pattern': rb'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|top|cn|ru|tk|ml|ga|cf|info|biz|cc|pw)\b',
            'risk': 'medium',
            'description': '可疑域名'
        },
        'email': {
            'pattern': rb'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'risk': 'low',
            'description': '邮箱地址'
        },
        'base64_long': {
            'pattern': rb'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
            'risk': 'medium',
            'description': 'Base64 编码数据'
        },
        'powershell': {
            'pattern': rb'(?i)(?:powershell|pwsh)(?:\.exe)?[^\x00]{0,100}(?:-enc|-e|-encoded|-command|-c)\s',
            'risk': 'high',
            'description': 'PowerShell 命令'
        },
        'cmd_exec': {
            'pattern': rb'(?i)cmd(?:\.exe)?[^\x00]{0,50}/c\s+[^\x00]+',
            'risk': 'high',
            'description': 'CMD 执行命令'
        },
        'credential_keyword': {
            'pattern': rb'(?i)(?:password|passwd|pwd|credential|secret|token|apikey|api_key|auth)[\s:=]+[^\s\x00]{4,50}',
            'risk': 'high',
            'description': '凭据关键字'
        },
        'private_key': {
            'pattern': rb'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'risk': 'critical',
            'description': '私钥'
        },
        'bitcoin_addr': {
            'pattern': rb'\b(?:1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b',
            'risk': 'medium',
            'description': '比特币地址'
        },
        'registry_path': {
            'pattern': rb'(?i)(?:HKEY_|HKLM\\|HKCU\\|HKU\\|HKCR\\)[^\x00\n]{10,100}',
            'risk': 'low',
            'description': '注册表路径'
        },
        'windows_path': {
            'pattern': rb'[A-Za-z]:\\(?:[^\\\x00\n]+\\)*[^\\\x00\n]+\.(?:exe|dll|bat|ps1|vbs|js|cmd|scr|pif)',
            'risk': 'low',
            'description': '可执行文件路径'
        },
        'unc_path': {
            'pattern': rb'\\\\[a-zA-Z0-9\.\-]+\\[^\x00\n]+',
            'risk': 'medium',
            'description': 'UNC 路径'
        },
        'shell_code': {
            'pattern': rb'(?:\xfc\xe8|\x60\x89|\xeb[\x00-\xff]\x5)',
            'risk': 'critical',
            'description': 'Shellcode 特征'
        },
        'mimikatz': {
            'pattern': rb'(?i)(?:mimikatz|sekurlsa|kerberos::list|privilege::debug)',
            'risk': 'critical',
            'description': 'Mimikatz 特征'
        },
        'cobalt_strike': {
            'pattern': rb'(?i)(?:beacon|cobaltstrike|\.sleeptime|\.jitter|\.watermark)',
            'risk': 'critical',
            'description': 'Cobalt Strike 特征'
        },
        'metasploit': {
            'pattern': rb'(?i)(?:meterpreter|metasploit|msf|payload)',
            'risk': 'high',
            'description': 'Metasploit 特征'
        },
    }

    # 可疑 C2 端口
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 443, 8080, 8443}

    def __init__(self):
        self.results: List[ScanResult] = []
        self.is_cancelled = False
        self.scanned_strings: Set[str] = set()  # 去重

        # 加载 Windows API
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.psapi = ctypes.WinDLL('psapi', use_last_error=True)
        self._setup_api()

    def _setup_api(self):
        """设置 Windows API"""
        # MEMORY_BASIC_INFORMATION 结构
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        self.MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION

        # OpenProcess
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

        # CloseHandle
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        # ReadProcessMemory
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]

        # VirtualQueryEx
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        self.kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
        ]

    def scan_process(self, pid: int, process_name: str = "",
                     categories: List[str] = None,
                     custom_patterns: Dict[str, str] = None,
                     progress_callback: Callable = None) -> List[ScanResult]:
        """
        扫描单个进程的内存

        Args:
            pid: 进程 ID
            process_name: 进程名称
            categories: 要扫描的类别列表，None 表示全部
            custom_patterns: 自定义正则表达式
            progress_callback: 进度回调

        Returns:
            扫描结果列表
        """
        results = []
        self.scanned_strings.clear()

        if categories is None:
            categories = list(self.PATTERNS.keys())

        # 打开进程
        access = self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION
        handle = self.kernel32.OpenProcess(access, False, pid)

        if not handle:
            if progress_callback:
                progress_callback(f"无法打开进程 {pid}: 权限不足")
            return results

        try:
            if progress_callback:
                progress_callback(f"正在扫描进程 {process_name} (PID: {pid})...")

            # 枚举内存区域
            address = 0
            mbi = self.MEMORY_BASIC_INFORMATION()
            regions_scanned = 0

            while True:
                if self.is_cancelled:
                    break

                ret = self.kernel32.VirtualQueryEx(
                    handle, ctypes.c_void_p(address),
                    ctypes.byref(mbi), ctypes.sizeof(mbi)
                )

                if ret == 0:
                    break

                # 检查是否是已提交的可读内存
                state = mbi.State or 0
                protect = mbi.Protect or 0
                if (state == self.MEM_COMMIT and
                    protect & self.PAGE_READABLE and
                    not protect & 0x100):  # 排除 PAGE_GUARD

                    region_size = mbi.RegionSize or 0
                    base_address = mbi.BaseAddress or 0

                    # 跳过无效区域
                    if region_size == 0 or base_address == 0:
                        address = base_address + region_size if region_size else address + 0x1000
                        continue

                    # 限制单个区域大小 (最大 10MB)
                    if region_size > 10 * 1024 * 1024:
                        region_size = 10 * 1024 * 1024

                    # 读取内存
                    try:
                        buffer = ctypes.create_string_buffer(region_size)
                        bytes_read = ctypes.c_size_t()

                        success = self.kernel32.ReadProcessMemory(
                            handle, ctypes.c_void_p(base_address),
                            buffer, region_size, ctypes.byref(bytes_read)
                        )
                    except Exception:
                        address = base_address + region_size
                        continue

                    if success and bytes_read.value > 0:
                        data = buffer.raw[:bytes_read.value]

                        # 扫描数据
                        region_results = self._scan_buffer(
                            data, base_address, pid, process_name,
                            categories, custom_patterns
                        )
                        results.extend(region_results)

                    regions_scanned += 1

                # 移动到下一个区域
                base = mbi.BaseAddress or 0
                size = mbi.RegionSize or 0
                address = base + size

                # 防止无限循环
                if address <= base or size == 0:
                    break

            if progress_callback:
                progress_callback(f"扫描完成: {regions_scanned} 个内存区域, {len(results)} 个发现")

        finally:
            self.kernel32.CloseHandle(handle)

        return results

    def _scan_buffer(self, data: bytes, base_address: int, pid: int,
                     process_name: str, categories: List[str],
                     custom_patterns: Dict[str, str] = None) -> List[ScanResult]:
        """扫描内存缓冲区"""
        results = []

        # 扫描预定义模式
        for cat_name in categories:
            if cat_name not in self.PATTERNS:
                continue

            pattern_info = self.PATTERNS[cat_name]
            pattern = pattern_info['pattern']

            try:
                for match in re.finditer(pattern, data):
                    value = match.group(0)

                    # 尝试解码
                    try:
                        value_str = value.decode('utf-8', errors='ignore').strip('\x00')
                    except:
                        value_str = value.decode('latin-1', errors='ignore').strip('\x00')

                    # 去重
                    if value_str in self.scanned_strings:
                        continue
                    self.scanned_strings.add(value_str)

                    # 过滤无效结果
                    if not self._is_valid_result(cat_name, value_str):
                        continue

                    # 获取上下文
                    start = max(0, match.start() - 20)
                    end = min(len(data), match.end() + 20)
                    context = data[start:end]
                    try:
                        context_str = context.decode('utf-8', errors='replace').replace('\x00', ' ')
                    except:
                        context_str = context.decode('latin-1', errors='replace').replace('\x00', ' ')

                    results.append(ScanResult(
                        pid=pid,
                        process_name=process_name,
                        category=cat_name,
                        value=value_str,
                        context=context_str.strip(),
                        address=base_address + match.start(),
                        risk_level=pattern_info['risk']
                    ))
            except Exception:
                pass

        # 扫描自定义模式
        if custom_patterns:
            for name, pattern_str in custom_patterns.items():
                try:
                    pattern = pattern_str.encode() if isinstance(pattern_str, str) else pattern_str
                    for match in re.finditer(pattern, data):
                        value = match.group(0)
                        try:
                            value_str = value.decode('utf-8', errors='ignore')
                        except:
                            value_str = value.decode('latin-1', errors='ignore')

                        if value_str in self.scanned_strings:
                            continue
                        self.scanned_strings.add(value_str)

                        results.append(ScanResult(
                            pid=pid,
                            process_name=process_name,
                            category='custom',
                            value=value_str,
                            context=f"自定义规则: {name}",
                            address=base_address + match.start(),
                            risk_level='medium'
                        ))
                except Exception:
                    pass

        return results

    def _is_valid_result(self, category: str, value: str) -> bool:
        """验证结果是否有效"""
        # 过滤太短的结果
        if len(value) < 4:
            return False

        # 过滤常见的误报
        if category == 'ipv4':
            # 过滤本地/保留地址
            if value.startswith(('127.', '0.0.', '255.255.', '0.0.0.')):
                return False
            # 过滤版本号格式
            parts = value.split('.')
            if all(p.isdigit() and int(p) < 20 for p in parts):
                return False

        if category == 'domain':
            # 过滤过短的域名
            if len(value) < 8:
                return False
            # 过滤常见的系统域名
            if any(d in value.lower() for d in ['microsoft.com', 'windows.com', 'windowsupdate.com']):
                return False

        if category == 'url':
            # 过滤常见的正常 URL
            if any(d in value.lower() for d in ['microsoft.com', 'windows.com', 'google.com', 'mozilla.org']):
                return False

        return True

    def scan_multiple_processes(self, processes: List[Dict],
                                categories: List[str] = None,
                                progress_callback: Callable = None,
                                max_workers: int = 2) -> List[ScanResult]:
        """
        扫描多个进程

        Args:
            processes: 进程列表 [{'pid': int, 'name': str}, ...]
            categories: 要扫描的类别
            progress_callback: 进度回调
            max_workers: 并行线程数

        Returns:
            所有扫描结果
        """
        self.results = []
        self.is_cancelled = False
        total = len(processes)

        for i, proc in enumerate(processes):
            if self.is_cancelled:
                break

            pid = proc.get('pid')
            name = proc.get('name', '')

            if progress_callback:
                progress_callback(f"[{i+1}/{total}] 扫描 {name} (PID: {pid})...")

            try:
                results = self.scan_process(pid, name, categories)
                self.results.extend(results)
            except Exception as e:
                if progress_callback:
                    progress_callback(f"  扫描失败: {e}")

        return self.results

    def cancel(self):
        """取消扫描"""
        self.is_cancelled = True

    def get_summary(self) -> Dict:
        """获取扫描摘要"""
        summary = {
            'total': len(self.results),
            'by_category': {},
            'by_risk': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'by_process': {}
        }

        for result in self.results:
            # 按类别统计
            cat = result.category
            if cat not in summary['by_category']:
                summary['by_category'][cat] = 0
            summary['by_category'][cat] += 1

            # 按风险等级统计
            risk = result.risk_level
            if risk in summary['by_risk']:
                summary['by_risk'][risk] += 1

            # 按进程统计
            proc = f"{result.process_name} ({result.pid})"
            if proc not in summary['by_process']:
                summary['by_process'][proc] = 0
            summary['by_process'][proc] += 1

        return summary

    def export_results(self, output_path: str, format_type: str = 'csv') -> bool:
        """导出结果"""
        try:
            if format_type == 'csv':
                import csv
                with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(['进程名', 'PID', '类别', '风险等级', '值', '内存地址', '上下文'])
                    for r in self.results:
                        writer.writerow([
                            r.process_name, r.pid, r.category, r.risk_level,
                            r.value, hex(r.address), r.context
                        ])

            elif format_type == 'json':
                import json
                data = [
                    {
                        'process_name': r.process_name,
                        'pid': r.pid,
                        'category': r.category,
                        'risk_level': r.risk_level,
                        'value': r.value,
                        'address': hex(r.address),
                        'context': r.context
                    }
                    for r in self.results
                ]
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)

            return True
        except Exception:
            return False

    @staticmethod
    def get_category_description(category: str) -> str:
        """获取类别描述"""
        if category in MemoryScanner.PATTERNS:
            return MemoryScanner.PATTERNS[category]['description']
        return category

    @staticmethod
    def get_risk_color(risk: str) -> str:
        """获取风险等级颜色"""
        colors = {
            'low': '#28a745',      # 绿色
            'medium': '#ffc107',   # 黄色
            'high': '#fd7e14',     # 橙色
            'critical': '#dc3545'  # 红色
        }
        return colors.get(risk, '#6c757d')
