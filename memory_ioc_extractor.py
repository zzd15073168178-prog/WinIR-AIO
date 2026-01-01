#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
内存 IOC 提取器 - 从进程内存中提取网络威胁指标

功能：
1. 提取 IPv4/IPv6 地址
2. 提取域名（支持可疑 TLD 检测）
3. 提取 URL（HTTP/HTTPS/FTP）
4. 提取邮箱地址
5. 自动过滤误报（本地地址、系统域名等）
6. IOC 风险评估
7. 支持导出为多种格式
"""

import re
import ctypes
from ctypes import wintypes
from typing import Dict, List, Set, Tuple, Callable, Optional
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import psutil
import json
import csv


@dataclass
class IOCResult:
    """IOC 提取结果"""
    ioc_type: str           # ipv4, ipv6, domain, url, email
    value: str              # IOC 值
    pid: int                # 进程 PID
    process_name: str       # 进程名
    process_path: str       # 进程路径
    address: int            # 内存地址
    context: str            # 上下文
    risk_level: str         # low, medium, high, critical
    risk_reason: str        # 风险原因
    network_connections: str = ""  # 进程网络连接
    timestamp: str = ""     # 发现时间


@dataclass
class IOCStats:
    """IOC 统计信息"""
    total: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    by_risk: Dict[str, int] = field(default_factory=dict)
    by_process: Dict[str, int] = field(default_factory=dict)
    unique_ips: Set[str] = field(default_factory=set)
    unique_domains: Set[str] = field(default_factory=set)
    unique_urls: Set[str] = field(default_factory=set)


class MemoryIOCExtractor:
    """
    内存 IOC 提取器

    从进程内存中提取网络威胁指标（IP、域名、URL、邮箱）
    """

    # Windows API 常量
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_READABLE_MASK = 0x06

    # 权限相关
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    # ==================== IOC 正则表达式 ====================

    # IPv4 地址 (更精确的匹配)
    IPV4_PATTERN = re.compile(
        rb'(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}'
        rb'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9.])'
    )

    # IPv6 地址 (简化版，匹配常见格式)
    IPV6_PATTERN = re.compile(
        rb'(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
        rb'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
        rb'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])',
        re.IGNORECASE
    )

    # 域名 (支持中文域名)
    DOMAIN_PATTERN = re.compile(
        rb'(?<![a-zA-Z0-9._-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        rb'(?:com|net|org|edu|gov|mil|int|info|biz|name|pro|aero|coop|museum|'
        rb'cn|uk|de|fr|jp|ru|br|in|au|it|nl|es|kr|mx|se|no|fi|dk|pl|be|at|ch|'
        rb'xyz|top|tk|ml|ga|cf|pw|cc|ws|vip|club|site|online|wang|shop|work|'
        rb'io|co|me|tv|ly|to|fm|am|gl|gd|gg|la|sx|hk|tw|sg|my)'
        rb'(?![a-zA-Z0-9._-])',
        re.IGNORECASE
    )

    # URL (HTTP/HTTPS/FTP)
    URL_PATTERN = re.compile(
        rb'(?:https?|ftp)://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        rb'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
        rb'(?::[0-9]{1,5})?'
        rb'(?:/[a-zA-Z0-9_.~!$&\'()*+,;=:@%/-]*)?'
        rb'(?:\?[a-zA-Z0-9_.~!$&\'()*+,;=:@%/?-]*)?',
        re.IGNORECASE
    )

    # 邮箱地址
    EMAIL_PATTERN = re.compile(
        rb'(?<![a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]+@'
        rb'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        rb'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?![a-zA-Z0-9._%+-])',
        re.IGNORECASE
    )

    # ==================== 可疑 TLD 列表 ====================

    # 高风险顶级域（常被恶意软件滥用）
    HIGH_RISK_TLDS = {
        'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'pw', 'cc', 'ws', 'su',
        'buzz', 'work', 'click', 'link', 'gq', 'fit', 'kim', 'men',
        'racing', 'download', 'review', 'country', 'stream', 'party',
        'cricket', 'science', 'date', 'faith', 'win', 'accountant',
    }

    # 中等风险顶级域
    MEDIUM_RISK_TLDS = {
        'vip', 'club', 'site', 'online', 'wang', 'shop', 'live',
        'space', 'tech', 'store', 'host', 'fun', 'press', 'news',
        'cloud', 'email', 'solutions', 'services', 'digital',
    }

    # ==================== 白名单 ====================

    # 系统/安全厂商域名白名单（减少误报）
    WHITELIST_DOMAINS = {
        # Microsoft
        'microsoft.com', 'windows.com', 'windowsupdate.com', 'live.com',
        'office.com', 'office365.com', 'outlook.com', 'azure.com',
        'msn.com', 'bing.com', 'msedge.net', 'aka.ms',
        # Google
        'google.com', 'googleapis.com', 'gstatic.com', 'google.cn',
        'googlesyndication.com', 'googleadservices.com', 'youtube.com',
        # Apple
        'apple.com', 'icloud.com', 'itunes.com',
        # 安全厂商
        'symantec.com', 'norton.com', 'mcafee.com', 'kaspersky.com',
        'avast.com', 'avg.com', 'bitdefender.com', 'eset.com',
        'trendmicro.com', 'sophos.com', 'malwarebytes.com',
        '360.cn', 'qihoo.com', 'huorong.cn',
        # CDN
        'cloudflare.com', 'akamai.com', 'akamaiedge.net', 'fastly.com',
        'cloudfront.net', 'azureedge.net',
        # 其他常见
        'github.com', 'githubusercontent.com', 'amazon.com', 'aws.com',
    }

    # 私有/本地 IP 范围
    PRIVATE_IP_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',  # Link-local
        '0.0.0.0/8',
        '224.0.0.0/4',     # Multicast
        '240.0.0.0/4',     # Reserved
    ]

    def __init__(self):
        self.results: List[IOCResult] = []
        self.stats = IOCStats()
        self.is_cancelled = False
        self._seen_iocs: Set[str] = set()  # 去重用

        # 加载 Windows API
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        self._setup_api()

        # 启用 SeDebugPrivilege
        self._debug_privilege_enabled = self._enable_se_debug_privilege()

        # 编译私有 IP 网络
        self._private_networks = [ipaddress.ip_network(r) for r in self.PRIVATE_IP_RANGES]

    def _setup_api(self):
        """设置 Windows API"""
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

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        self.LUID = LUID
        self.TOKEN_PRIVILEGES = TOKEN_PRIVILEGES

        # API 函数签名
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]

        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        self.kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
        ]

        self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
        ]

        self.advapi32.OpenProcessToken.restype = wintypes.BOOL
        self.advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
        ]

        self.advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
        self.advapi32.LookupPrivilegeValueW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)
        ]

        self.advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
        self.advapi32.AdjustTokenPrivileges.argtypes = [
            wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p
        ]

    def _enable_se_debug_privilege(self) -> bool:
        """启用 SeDebugPrivilege"""
        try:
            current_process = self.kernel32.GetCurrentProcess()
            token = wintypes.HANDLE()

            if not self.advapi32.OpenProcessToken(
                current_process,
                self.TOKEN_ADJUST_PRIVILEGES | self.TOKEN_QUERY,
                ctypes.byref(token)
            ):
                return False

            try:
                luid = self.LUID()
                if not self.advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                    return False

                tp = self.TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = self.SE_PRIVILEGE_ENABLED

                return self.advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
            finally:
                self.kernel32.CloseHandle(token)
        except:
            return False

    def _get_process_path(self, handle: wintypes.HANDLE) -> str:
        """获取进程路径"""
        try:
            buffer = ctypes.create_unicode_buffer(260)
            size = wintypes.DWORD(260)
            if self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return buffer.value
        except:
            pass
        return ""

    def _get_process_connections(self, pid: int) -> str:
        """获取进程网络连接"""
        try:
            proc = psutil.Process(pid)
            # 使用 net_connections 替代已废弃的 connections
            try:
                connections = proc.net_connections()
            except AttributeError:
                # 旧版本 psutil 回退
                connections = proc.connections()

            if not connections:
                return ""

            conn_strs = []
            for conn in connections[:5]:
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?"
                conn_strs.append(f"{local}->{remote}")

            return "; ".join(conn_strs)
        except:
            return ""

    def _is_private_ip(self, ip_str: str) -> bool:
        """检查是否为私有 IP"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self._private_networks:
                if ip in network:
                    return True
            return False
        except:
            return False

    def _is_whitelisted_domain(self, domain: str) -> bool:
        """检查是否在白名单中"""
        domain_lower = domain.lower()
        for whitelist in self.WHITELIST_DOMAINS:
            if domain_lower == whitelist or domain_lower.endswith('.' + whitelist):
                return True
        return False

    def _assess_ip_risk(self, ip_str: str) -> Tuple[str, str]:
        """评估 IP 风险"""
        if self._is_private_ip(ip_str):
            return 'low', '私有/本地 IP'

        # 检查是否为已知 CDN 或云服务商 IP（可扩展）
        # 这里简化处理，公网 IP 默认为 medium
        return 'medium', '公网 IP，建议进一步分析'

    def _assess_domain_risk(self, domain: str) -> Tuple[str, str]:
        """评估域名风险"""
        domain_lower = domain.lower()

        # 白名单
        if self._is_whitelisted_domain(domain_lower):
            return 'low', '已知安全域名'

        # 提取 TLD
        parts = domain_lower.split('.')
        if len(parts) >= 2:
            tld = parts[-1]

            if tld in self.HIGH_RISK_TLDS:
                return 'high', f'高风险顶级域 (.{tld})'

            if tld in self.MEDIUM_RISK_TLDS:
                return 'medium', f'中等风险顶级域 (.{tld})'

        # DGA 检测（简化版：检查域名熵值和长度）
        main_domain = parts[-2] if len(parts) >= 2 else domain
        if len(main_domain) > 15:
            # 计算字符多样性
            unique_chars = len(set(main_domain))
            if unique_chars > 10:
                return 'high', '疑似 DGA 生成域名（高熵值）'

        # 检查是否包含可疑关键词
        suspicious_keywords = ['malware', 'virus', 'hack', 'crack', 'warez',
                              'torrent', 'keygen', 'loader', 'crypter', 'rat',
                              'c2', 'cnc', 'botnet', 'ddos']
        for keyword in suspicious_keywords:
            if keyword in domain_lower:
                return 'critical', f'包含可疑关键词: {keyword}'

        return 'medium', '未知域名，建议分析'

    def _assess_url_risk(self, url: str) -> Tuple[str, str]:
        """评估 URL 风险"""
        url_lower = url.lower()

        # 提取域名
        try:
            # 简单提取域名
            if '://' in url:
                domain_part = url.split('://')[1].split('/')[0].split(':')[0]
            else:
                domain_part = url.split('/')[0].split(':')[0]

            domain_risk, domain_reason = self._assess_domain_risk(domain_part)

            # URL 特定检查
            suspicious_extensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1',
                                    '.vbs', '.js', '.hta', '.msi', '.jar']
            for ext in suspicious_extensions:
                if url_lower.endswith(ext):
                    return 'high', f'指向可执行文件 ({ext})'

            # 检查可疑路径
            suspicious_paths = ['/admin', '/shell', '/cmd', '/upload', '/backdoor',
                               '/webshell', '/config', '/debug']
            for path in suspicious_paths:
                if path in url_lower:
                    return 'high', f'包含可疑路径: {path}'

            # Base64 编码参数
            if '=' in url and len(url) > 100:
                # 可能包含 Base64 编码数据
                return 'medium', '可能包含编码数据'

            return domain_risk, domain_reason

        except:
            return 'medium', '无法解析 URL'

    def _get_context(self, data: bytes, pos: int, length: int) -> str:
        """获取匹配上下文"""
        context_start = max(0, pos - 30)
        context_end = min(len(data), pos + length + 30)
        context = data[context_start:context_end]

        try:
            text = context.decode('utf-8', errors='ignore')
        except:
            text = context.decode('latin-1', errors='ignore')

        # 过滤不可打印字符
        visible = ''.join(c if c.isprintable() or c in '\n\r\t' else ' ' for c in text)
        return re.sub(r'\s+', ' ', visible).strip()[:150]

    def extract_iocs(self,
                     target_pid: int = None,
                     ioc_types: List[str] = None,
                     include_private_ips: bool = False,
                     include_whitelisted: bool = False,
                     progress_callback: Callable = None) -> List[IOCResult]:
        """
        从进程内存中提取 IOC

        Args:
            target_pid: 目标 PID（None 表示所有进程）
            ioc_types: 要提取的 IOC 类型 ['ipv4', 'ipv6', 'domain', 'url', 'email']
            include_private_ips: 是否包含私有 IP
            include_whitelisted: 是否包含白名单域名
            progress_callback: 进度回调

        Returns:
            IOC 结果列表
        """
        self.results = []
        self.stats = IOCStats()
        self._seen_iocs = set()
        self.is_cancelled = False

        if ioc_types is None:
            ioc_types = ['ipv4', 'domain', 'url']  # 默认

        # 获取进程列表
        try:
            processes = list(psutil.process_iter(['pid', 'name']))
        except Exception as e:
            if progress_callback:
                progress_callback(f"无法获取进程列表: {e}")
            return self.results

        total = len(processes)

        for idx, proc in enumerate(processes):
            if self.is_cancelled:
                break

            try:
                pid = proc.info['pid']
                name = proc.info['name'] or "Unknown"

                if target_pid is not None and pid != target_pid:
                    continue

                if progress_callback:
                    progress_callback(f"[{idx + 1}/{total}] 扫描 {name} (PID: {pid})...")

                # 打开进程
                access = self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION
                handle = self.kernel32.OpenProcess(access, False, pid)

                if not handle:
                    continue

                try:
                    process_path = self._get_process_path(handle)
                    if not process_path:
                        try:
                            process_path = psutil.Process(pid).exe()
                        except:
                            process_path = name

                    connections = self._get_process_connections(pid)

                    # 扫描内存
                    self._scan_process_memory(
                        handle, pid, name, process_path, connections,
                        ioc_types, include_private_ips, include_whitelisted
                    )

                finally:
                    self.kernel32.CloseHandle(handle)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                if progress_callback:
                    progress_callback(f"  扫描失败: {e}")

        # 更新统计
        self._update_stats()

        if progress_callback:
            progress_callback(f"扫描完成，共提取 {len(self.results)} 个 IOC")

        return self.results

    def _scan_process_memory(self, handle: wintypes.HANDLE,
                             pid: int, name: str, path: str, connections: str,
                             ioc_types: List[str],
                             include_private_ips: bool,
                             include_whitelisted: bool):
        """扫描单个进程内存"""
        address = 0
        mbi = self.MEMORY_BASIC_INFORMATION()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        while True:
            if self.is_cancelled:
                break

            ret = self.kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address),
                ctypes.byref(mbi), ctypes.sizeof(mbi)
            )

            if ret == 0:
                break

            region_size = mbi.RegionSize or 0
            base_address = mbi.BaseAddress or 0

            if region_size == 0:
                break

            state = mbi.State or 0
            protect = mbi.Protect or 0

            if state == self.MEM_COMMIT and (protect & self.PAGE_READABLE_MASK) != 0:
                read_size = min(region_size, 10 * 1024 * 1024)  # 最大 10MB

                try:
                    buffer = ctypes.create_string_buffer(read_size)
                    bytes_read = ctypes.c_size_t()

                    success = self.kernel32.ReadProcessMemory(
                        handle, ctypes.c_void_p(base_address),
                        buffer, read_size, ctypes.byref(bytes_read)
                    )

                    if success and bytes_read.value > 0:
                        data = buffer.raw[:bytes_read.value]

                        # 提取各类 IOC
                        if 'ipv4' in ioc_types:
                            self._extract_ipv4(data, base_address, pid, name, path,
                                             connections, timestamp, include_private_ips)

                        if 'ipv6' in ioc_types:
                            self._extract_ipv6(data, base_address, pid, name, path,
                                             connections, timestamp)

                        if 'domain' in ioc_types:
                            self._extract_domains(data, base_address, pid, name, path,
                                                connections, timestamp, include_whitelisted)

                        if 'url' in ioc_types:
                            self._extract_urls(data, base_address, pid, name, path,
                                             connections, timestamp, include_whitelisted)

                        if 'email' in ioc_types:
                            self._extract_emails(data, base_address, pid, name, path,
                                               connections, timestamp)

                except Exception:
                    pass

            address = base_address + region_size
            if address < base_address:
                break

    def _extract_ipv4(self, data: bytes, base_addr: int, pid: int, name: str,
                      path: str, connections: str, timestamp: str, include_private: bool):
        """提取 IPv4 地址"""
        for match in self.IPV4_PATTERN.finditer(data):
            try:
                ip_str = match.group(0).decode('utf-8')

                # 去重
                ioc_key = f"ipv4:{ip_str}:{pid}"
                if ioc_key in self._seen_iocs:
                    continue
                self._seen_iocs.add(ioc_key)

                # 过滤私有 IP
                if not include_private and self._is_private_ip(ip_str):
                    continue

                # 验证 IP 格式
                try:
                    ipaddress.ip_address(ip_str)
                except:
                    continue

                risk_level, risk_reason = self._assess_ip_risk(ip_str)
                context = self._get_context(data, match.start(), len(match.group(0)))

                self.results.append(IOCResult(
                    ioc_type='ipv4',
                    value=ip_str,
                    pid=pid,
                    process_name=name,
                    process_path=path,
                    address=base_addr + match.start(),
                    context=context,
                    risk_level=risk_level,
                    risk_reason=risk_reason,
                    network_connections=connections,
                    timestamp=timestamp
                ))

            except Exception:
                continue

    def _extract_ipv6(self, data: bytes, base_addr: int, pid: int, name: str,
                      path: str, connections: str, timestamp: str):
        """提取 IPv6 地址"""
        for match in self.IPV6_PATTERN.finditer(data):
            try:
                ip_str = match.group(0).decode('utf-8')

                ioc_key = f"ipv6:{ip_str}:{pid}"
                if ioc_key in self._seen_iocs:
                    continue
                self._seen_iocs.add(ioc_key)

                # 验证
                try:
                    ipaddress.ip_address(ip_str)
                except:
                    continue

                context = self._get_context(data, match.start(), len(match.group(0)))

                self.results.append(IOCResult(
                    ioc_type='ipv6',
                    value=ip_str,
                    pid=pid,
                    process_name=name,
                    process_path=path,
                    address=base_addr + match.start(),
                    context=context,
                    risk_level='medium',
                    risk_reason='IPv6 地址',
                    network_connections=connections,
                    timestamp=timestamp
                ))

            except Exception:
                continue

    def _extract_domains(self, data: bytes, base_addr: int, pid: int, name: str,
                         path: str, connections: str, timestamp: str, include_whitelisted: bool):
        """提取域名"""
        for match in self.DOMAIN_PATTERN.finditer(data):
            try:
                domain = match.group(0).decode('utf-8').lower()

                # 过滤太短的域名
                if len(domain) < 4:
                    continue

                # 去重
                ioc_key = f"domain:{domain}:{pid}"
                if ioc_key in self._seen_iocs:
                    continue
                self._seen_iocs.add(ioc_key)

                # 过滤白名单
                if not include_whitelisted and self._is_whitelisted_domain(domain):
                    continue

                risk_level, risk_reason = self._assess_domain_risk(domain)
                context = self._get_context(data, match.start(), len(match.group(0)))

                self.results.append(IOCResult(
                    ioc_type='domain',
                    value=domain,
                    pid=pid,
                    process_name=name,
                    process_path=path,
                    address=base_addr + match.start(),
                    context=context,
                    risk_level=risk_level,
                    risk_reason=risk_reason,
                    network_connections=connections,
                    timestamp=timestamp
                ))

            except Exception:
                continue

    def _extract_urls(self, data: bytes, base_addr: int, pid: int, name: str,
                      path: str, connections: str, timestamp: str, include_whitelisted: bool):
        """提取 URL"""
        for match in self.URL_PATTERN.finditer(data):
            try:
                url = match.group(0).decode('utf-8')

                # 去重
                ioc_key = f"url:{url}:{pid}"
                if ioc_key in self._seen_iocs:
                    continue
                self._seen_iocs.add(ioc_key)

                # 过滤白名单
                if not include_whitelisted:
                    try:
                        domain = url.split('://')[1].split('/')[0].split(':')[0]
                        if self._is_whitelisted_domain(domain):
                            continue
                    except:
                        pass

                risk_level, risk_reason = self._assess_url_risk(url)
                context = self._get_context(data, match.start(), len(match.group(0)))

                self.results.append(IOCResult(
                    ioc_type='url',
                    value=url,
                    pid=pid,
                    process_name=name,
                    process_path=path,
                    address=base_addr + match.start(),
                    context=context,
                    risk_level=risk_level,
                    risk_reason=risk_reason,
                    network_connections=connections,
                    timestamp=timestamp
                ))

            except Exception:
                continue

    def _extract_emails(self, data: bytes, base_addr: int, pid: int, name: str,
                        path: str, connections: str, timestamp: str):
        """提取邮箱地址"""
        for match in self.EMAIL_PATTERN.finditer(data):
            try:
                email = match.group(0).decode('utf-8').lower()

                # 去重
                ioc_key = f"email:{email}:{pid}"
                if ioc_key in self._seen_iocs:
                    continue
                self._seen_iocs.add(ioc_key)

                # 评估风险（基于域名）
                domain = email.split('@')[1] if '@' in email else ''
                if domain:
                    risk_level, risk_reason = self._assess_domain_risk(domain)
                else:
                    risk_level, risk_reason = 'low', '邮箱地址'

                context = self._get_context(data, match.start(), len(match.group(0)))

                self.results.append(IOCResult(
                    ioc_type='email',
                    value=email,
                    pid=pid,
                    process_name=name,
                    process_path=path,
                    address=base_addr + match.start(),
                    context=context,
                    risk_level=risk_level,
                    risk_reason=risk_reason,
                    network_connections=connections,
                    timestamp=timestamp
                ))

            except Exception:
                continue

    def _update_stats(self):
        """更新统计信息"""
        self.stats = IOCStats()
        self.stats.total = len(self.results)

        for r in self.results:
            # 按类型统计
            self.stats.by_type[r.ioc_type] = self.stats.by_type.get(r.ioc_type, 0) + 1

            # 按风险统计
            self.stats.by_risk[r.risk_level] = self.stats.by_risk.get(r.risk_level, 0) + 1

            # 按进程统计
            proc_key = f"{r.process_name} ({r.pid})"
            self.stats.by_process[proc_key] = self.stats.by_process.get(proc_key, 0) + 1

            # 唯一值
            if r.ioc_type == 'ipv4' or r.ioc_type == 'ipv6':
                self.stats.unique_ips.add(r.value)
            elif r.ioc_type == 'domain':
                self.stats.unique_domains.add(r.value)
            elif r.ioc_type == 'url':
                self.stats.unique_urls.add(r.value)

    def get_high_risk_iocs(self) -> List[IOCResult]:
        """获取高风险 IOC"""
        return [r for r in self.results if r.risk_level in ('high', 'critical')]

    def cancel(self):
        """取消扫描"""
        self.is_cancelled = True

    def is_debug_privilege_enabled(self) -> bool:
        """检查 SeDebugPrivilege"""
        return self._debug_privilege_enabled

    def export_json(self, file_path: str) -> bool:
        """导出为 JSON"""
        try:
            data = {
                'scan_time': datetime.now().isoformat(),
                'stats': {
                    'total': self.stats.total,
                    'by_type': self.stats.by_type,
                    'by_risk': self.stats.by_risk,
                    'unique_ips': list(self.stats.unique_ips),
                    'unique_domains': list(self.stats.unique_domains),
                    'unique_urls': list(self.stats.unique_urls),
                },
                'iocs': [
                    {
                        'type': r.ioc_type,
                        'value': r.value,
                        'pid': r.pid,
                        'process_name': r.process_name,
                        'process_path': r.process_path,
                        'address': hex(r.address),
                        'context': r.context,
                        'risk_level': r.risk_level,
                        'risk_reason': r.risk_reason,
                        'network_connections': r.network_connections,
                        'timestamp': r.timestamp,
                    }
                    for r in self.results
                ]
            }

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            return True
        except:
            return False

    def export_csv(self, file_path: str) -> bool:
        """导出为 CSV"""
        try:
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'IOC类型', 'IOC值', 'PID', '进程名', '进程路径',
                    '内存地址', '上下文', '风险等级', '风险原因',
                    '网络连接', '发现时间'
                ])

                for r in self.results:
                    writer.writerow([
                        r.ioc_type, r.value, r.pid, r.process_name, r.process_path,
                        hex(r.address), r.context, r.risk_level, r.risk_reason,
                        r.network_connections, r.timestamp
                    ])

            return True
        except:
            return False

    def export_ioc_list(self, file_path: str, ioc_type: str = None) -> bool:
        """导出纯 IOC 列表（用于威胁情报平台）"""
        try:
            iocs = set()
            for r in self.results:
                if ioc_type is None or r.ioc_type == ioc_type:
                    iocs.add(r.value)

            with open(file_path, 'w', encoding='utf-8') as f:
                for ioc in sorted(iocs):
                    f.write(ioc + '\n')

            return True
        except:
            return False


# ==================== 命令行测试 ====================

if __name__ == "__main__":
    import sys

    def progress(msg):
        print(msg)

    extractor = MemoryIOCExtractor()
    print(f"SeDebugPrivilege: {extractor.is_debug_privilege_enabled()}")

    # 解析参数
    ioc_types = ['ipv4', 'domain', 'url']
    target_pid = None

    if len(sys.argv) > 1:
        if sys.argv[1].isdigit():
            target_pid = int(sys.argv[1])
            print(f"\n仅扫描 PID: {target_pid}")
        else:
            ioc_types = sys.argv[1].split(',')

    print(f"IOC 类型: {ioc_types}")
    print("-" * 60)

    # 执行扫描
    results = extractor.extract_iocs(
        target_pid=target_pid,
        ioc_types=ioc_types,
        include_private_ips=False,
        include_whitelisted=False,
        progress_callback=progress
    )

    # 打印统计
    print("\n" + "=" * 60)
    print("扫描统计:")
    print("=" * 60)
    print(f"总计: {extractor.stats.total} 个 IOC")
    print(f"按类型: {extractor.stats.by_type}")
    print(f"按风险: {extractor.stats.by_risk}")
    print(f"唯一 IP: {len(extractor.stats.unique_ips)}")
    print(f"唯一域名: {len(extractor.stats.unique_domains)}")
    print(f"唯一 URL: {len(extractor.stats.unique_urls)}")

    # 打印高风险 IOC
    high_risk = extractor.get_high_risk_iocs()
    if high_risk:
        print("\n" + "=" * 60)
        print(f"高风险 IOC ({len(high_risk)} 个):")
        print("=" * 60)
        for r in high_risk[:20]:
            print(f"[{r.risk_level.upper()}] {r.ioc_type}: {r.value}")
            print(f"  进程: {r.process_name} (PID: {r.pid})")
            print(f"  原因: {r.risk_reason}")
            print()

    # 导出
    if results:
        extractor.export_json("ioc_results.json")
        extractor.export_csv("ioc_results.csv")
        extractor.export_ioc_list("ioc_list.txt")
        print("\n已导出: ioc_results.json, ioc_results.csv, ioc_list.txt")
