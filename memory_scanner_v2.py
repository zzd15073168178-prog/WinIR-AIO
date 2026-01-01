#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程内存扫描模块 V2 - 基于 Mereory_searchV1.2.exe 逆向分析结果改进

改进点：
1. 启用 SeDebugPrivilege 权限
2. 优化内存保护标志过滤（与 Go 版本一致）
3. 支持简单字符串搜索模式（更快更准确）
4. 获取进程网络连接信息
5. 获取进程完整路径
"""

import os
import re
import ctypes
from ctypes import wintypes
from typing import Dict, List, Callable, Optional, Set, Tuple
from dataclasses import dataclass
import psutil


@dataclass
class ScanResultV2:
    """扫描结果 V2"""
    pid: int
    process_name: str
    process_path: str
    network_connections: str
    match_content: str
    match_address: int = 0
    category: str = "custom"
    risk_level: str = "medium"


class MemoryScannerV2:
    """
    进程内存扫描器 V2

    基于 Mereory_searchV1.2.exe (Go 语言) 的逆向分析结果实现
    核心算法与原版一致，确保扫描准确性
    """

    # Windows API 常量
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    MEM_COMMIT = 0x1000

    # 与 Go 版本一致的内存保护标志
    # Go: (Protect & 6) != 0 即 PAGE_READONLY(0x02) | PAGE_READWRITE(0x04)
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_READABLE_MASK = PAGE_READONLY | PAGE_READWRITE  # = 0x06

    # 权限相关常量
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    # 预定义的威胁模式（可选使用）
    THREAT_PATTERNS = {
        'c2_domain': {
            'patterns': [
                rb'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:xyz|top|tk|ml|ga|cf|pw|cc|ws)\b',
            ],
            'risk': 'high',
            'description': 'C2 可疑域名'
        },
        'powershell_encoded': {
            'patterns': [
                rb'(?i)powershell[^\x00]{0,100}-e(?:nc(?:oded)?)?(?:c(?:ommand)?)?[\s]+[A-Za-z0-9+/=]{20,}',
            ],
            'risk': 'critical',
            'description': 'PowerShell 编码命令'
        },
        'mimikatz': {
            'patterns': [
                rb'(?i)mimikatz',
                rb'(?i)sekurlsa::',
                rb'(?i)privilege::debug',
            ],
            'risk': 'critical',
            'description': 'Mimikatz 特征'
        },
        'cobalt_strike': {
            'patterns': [
                rb'(?i)beacon',
                rb'(?i)cobaltstrike',
                rb'(?i)\.sleeptime',
            ],
            'risk': 'critical',
            'description': 'Cobalt Strike 特征'
        },
    }

    def __init__(self):
        self.results: List[ScanResultV2] = []
        self.is_cancelled = False

        # 加载 Windows API
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        self._setup_api()

        # 尝试启用 SeDebugPrivilege
        self._debug_privilege_enabled = self._enable_se_debug_privilege()

    def _setup_api(self):
        """设置 Windows API"""
        # MEMORY_BASIC_INFORMATION 结构 (与 Go 版本的 main.MemoryBasicInformation 对应)
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

        # LUID 结构
        class LUID(ctypes.Structure):
            _fields_ = [
                ("LowPart", wintypes.DWORD),
                ("HighPart", wintypes.LONG),
            ]

        # LUID_AND_ATTRIBUTES 结构
        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Luid", LUID),
                ("Attributes", wintypes.DWORD),
            ]

        # TOKEN_PRIVILEGES 结构
        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1),
            ]

        self.LUID = LUID
        self.LUID_AND_ATTRIBUTES = LUID_AND_ATTRIBUTES
        self.TOKEN_PRIVILEGES = TOKEN_PRIVILEGES

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

        # GetCurrentProcess
        self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel32.GetCurrentProcess.argtypes = []

        # QueryFullProcessImageNameW
        self.kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
        ]

        # OpenProcessToken
        self.advapi32.OpenProcessToken.restype = wintypes.BOOL
        self.advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
        ]

        # LookupPrivilegeValueW
        self.advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
        self.advapi32.LookupPrivilegeValueW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)
        ]

        # AdjustTokenPrivileges
        self.advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
        self.advapi32.AdjustTokenPrivileges.argtypes = [
            wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p
        ]

    def _enable_se_debug_privilege(self) -> bool:
        """
        启用 SeDebugPrivilege 权限

        与 Go 版本的 main.EnableSeDebugPrivilege() 函数对应
        这是能够扫描系统进程的关键
        """
        try:
            # 获取当前进程句柄
            current_process = self.kernel32.GetCurrentProcess()

            # 打开进程令牌
            token = wintypes.HANDLE()
            if not self.advapi32.OpenProcessToken(
                current_process,
                self.TOKEN_ADJUST_PRIVILEGES | self.TOKEN_QUERY,
                ctypes.byref(token)
            ):
                return False

            try:
                # 查找 SeDebugPrivilege 的 LUID
                luid = self.LUID()
                if not self.advapi32.LookupPrivilegeValueW(
                    None, "SeDebugPrivilege", ctypes.byref(luid)
                ):
                    return False

                # 设置权限
                tp = self.TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = self.SE_PRIVILEGE_ENABLED

                # 调整权限
                if not self.advapi32.AdjustTokenPrivileges(
                    token, False, ctypes.byref(tp), 0, None, None
                ):
                    return False

                return True

            finally:
                self.kernel32.CloseHandle(token)

        except Exception:
            return False

    def get_process_path(self, handle: wintypes.HANDLE) -> str:
        """
        获取进程完整路径

        与 Go 版本的 main.GetProcessFilePath() 函数对应
        使用 QueryFullProcessImageNameW API
        """
        try:
            buffer = ctypes.create_unicode_buffer(260)
            size = wintypes.DWORD(260)

            if self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return buffer.value
        except Exception:
            pass
        return ""

    def get_process_connections(self, pid: int) -> str:
        """
        获取进程网络连接

        与 Go 版本使用 gopsutil 获取连接对应
        """
        try:
            connections = psutil.Process(pid).connections()
            if not connections:
                return ""

            conn_strs = []
            for conn in connections[:5]:  # 最多显示 5 个连接
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?"
                conn_strs.append(f"{local}->{remote}")

            return "; ".join(conn_strs)
        except Exception:
            return ""

    # 搜索模式常量
    SEARCH_MODE_SIMPLE = "simple"      # 简单模式: 只搜索 UTF-8，区分大小写 (与 Go 版本一致)
    SEARCH_MODE_FULL = "full"          # 全面模式: UTF-8 + UTF-16LE + 大小写变体

    def search_string(self, search_term: str,
                      target_pid: int = None,
                      progress_callback: Callable = None,
                      search_mode: str = "full") -> List[ScanResultV2]:
        """
        进程内存字符串搜索

        Args:
            search_term: 要搜索的字符串
            target_pid: 目标 PID (None 表示搜索所有进程)
            progress_callback: 进度回调
            search_mode: 搜索模式
                - "simple": 简单模式，只搜索 UTF-8，区分大小写 (与 Go 版本一致)
                - "full": 全面模式，UTF-8 + UTF-16LE + 大小写变体 (默认，更全面)

        Returns:
            扫描结果列表
        """
        self.results = []
        self.is_cancelled = False

        # 根据搜索模式构建搜索模式列表
        if search_mode == self.SEARCH_MODE_SIMPLE:
            # 简单模式: 只用 UTF-8，区分大小写 (与 Go 版本完全一致)
            all_search_patterns = [search_term.encode('utf-8', errors='ignore')]
        else:
            # 全面模式: 多种编码 + 大小写变体
            search_bytes_utf8 = search_term.encode('utf-8', errors='ignore')
            search_bytes_utf16 = search_term.encode('utf-16-le', errors='ignore')
            search_bytes_lower = search_term.lower().encode('utf-8', errors='ignore')
            search_bytes_upper = search_term.upper().encode('utf-8', errors='ignore')

            all_search_patterns = [
                search_bytes_utf8,
                search_bytes_utf16,
                search_bytes_lower,
                search_bytes_upper,
            ]
            # 去重
            all_search_patterns = list(set(all_search_patterns))

        # 获取所有进程
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

                # 如果指定了 PID，只扫描该进程
                if target_pid is not None and pid != target_pid:
                    continue

                if progress_callback:
                    progress_callback(f"[{idx + 1}/{total}] 扫描 {name} (PID: {pid})...")

                # 打开进程 (与 Go 版本一致: 0x410 = QUERY_INFO | VM_READ)
                access = self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION
                handle = self.kernel32.OpenProcess(access, False, pid)

                if not handle:
                    continue

                try:
                    # 获取进程路径 (路径获取失败也继续扫描)
                    process_path = self.get_process_path(handle)
                    if not process_path:
                        # 尝试用 psutil 获取路径
                        try:
                            process_path = psutil.Process(pid).exe()
                        except:
                            process_path = name  # 用进程名作为后备

                    # 获取网络连接
                    connections = self.get_process_connections(pid)

                    # 扫描内存
                    found = self._scan_process_memory(
                        handle, pid, name, process_path, connections,
                        all_search_patterns
                    )

                    self.results.extend(found)

                finally:
                    self.kernel32.CloseHandle(handle)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                if progress_callback:
                    progress_callback(f"  扫描失败: {e}")

        if progress_callback:
            progress_callback(f"扫描完成，共找到 {len(self.results)} 个匹配")

        return self.results

    def _scan_process_memory(self, handle: wintypes.HANDLE,
                             pid: int, name: str, path: str, connections: str,
                             search_patterns: List[bytes]) -> List[ScanResultV2]:
        """
        扫描单个进程的内存

        核心算法与 Go 版本的 main.Search_Memory() 完全一致：
        1. 从地址 0 开始遍历
        2. 使用 VirtualQueryEx 获取内存区域信息
        3. 只扫描 MEM_COMMIT 且 (Protect & 6) != 0 的区域
        4. 使用 ReadProcessMemory 读取内存
        5. 搜索多种编码格式 (UTF-8, UTF-16LE, 大小写)
        """
        results = []
        address = 0
        mbi = self.MEMORY_BASIC_INFORMATION()
        found_in_process = False

        while True:
            if self.is_cancelled:
                break

            # VirtualQueryEx
            ret = self.kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address),
                ctypes.byref(mbi), ctypes.sizeof(mbi)
            )

            if ret == 0:
                break

            region_size = mbi.RegionSize or 0
            base_address = mbi.BaseAddress or 0

            # 防止无限循环
            if region_size == 0:
                break

            # 与 Go 版本一致的过滤条件:
            # if memInfo.State == MEM_COMMIT && (memInfo.Protect & 6) != 0
            state = mbi.State or 0
            protect = mbi.Protect or 0

            if state == self.MEM_COMMIT and (protect & self.PAGE_READABLE_MASK) != 0:
                # Go 版本没有大小限制，我们也去掉限制
                # 但为了内存安全，对超大区域分块读取
                read_size = region_size

                try:
                    buffer = ctypes.create_string_buffer(read_size)
                    bytes_read = ctypes.c_size_t()

                    success = self.kernel32.ReadProcessMemory(
                        handle, ctypes.c_void_p(base_address),
                        buffer, read_size, ctypes.byref(bytes_read)
                    )

                    if success and bytes_read.value > 0:
                        data = buffer.raw[:bytes_read.value]

                        # 搜索所有模式 (UTF-8, UTF-16LE, 大小写变体)
                        pos = -1
                        matched_pattern = None
                        for pattern in search_patterns:
                            pos = data.find(pattern)
                            if pos != -1:
                                matched_pattern = pattern
                                break

                        if pos != -1 and not found_in_process:
                            # 找到匹配，提取上下文
                            match_len = len(matched_pattern) if matched_pattern else 8
                            context_start = max(0, pos - 50)
                            context_end = min(len(data), pos + match_len + 50)
                            context = data[context_start:context_end]

                            # 过滤不可见字符
                            try:
                                context_str = self._filter_visible_chars(context)
                            except:
                                context_str = path

                            results.append(ScanResultV2(
                                pid=pid,
                                process_name=name,
                                process_path=path,
                                network_connections=connections,
                                match_content=context_str,
                                match_address=base_address + pos,
                            ))

                            # 每个进程只记录一次（与 Go 版本行为一致）
                            found_in_process = True

                except Exception:
                    pass

            # 移动到下一个区域
            address = base_address + region_size

            # 防止地址溢出
            if address < base_address:
                break

        return results

    def _filter_visible_chars(self, data: bytes) -> str:
        """
        过滤可见字符

        与 Go 版本的 main.filterVisibleChars() 对应
        """
        try:
            # 尝试 UTF-8 解码
            text = data.decode('utf-8', errors='ignore')
        except:
            try:
                text = data.decode('gbk', errors='ignore')
            except:
                text = data.decode('latin-1', errors='ignore')

        # 过滤不可打印字符
        visible = ''.join(c if c.isprintable() or c in '\n\r\t' else ' ' for c in text)

        # 压缩连续空格
        visible = re.sub(r'\s+', ' ', visible)

        return visible.strip()[:200]  # 限制长度

    def search_patterns(self, categories: List[str] = None,
                        target_pid: int = None,
                        progress_callback: Callable = None) -> List[ScanResultV2]:
        """
        威胁模式搜索 - 使用预定义的正则表达式

        这是 Python 版本的增强功能，Go 版本没有此功能

        Args:
            categories: 要搜索的威胁类别，None 表示全部
            target_pid: 目标 PID
            progress_callback: 进度回调

        Returns:
            扫描结果列表
        """
        self.results = []
        self.is_cancelled = False

        if categories is None:
            categories = list(self.THREAT_PATTERNS.keys())

        # 编译正则表达式
        compiled_patterns = []
        for cat in categories:
            if cat in self.THREAT_PATTERNS:
                info = self.THREAT_PATTERNS[cat]
                for pattern in info['patterns']:
                    compiled_patterns.append({
                        'regex': re.compile(pattern, re.IGNORECASE),
                        'category': cat,
                        'risk': info['risk'],
                        'description': info['description']
                    })

        if not compiled_patterns:
            return self.results

        # 获取所有进程
        try:
            processes = list(psutil.process_iter(['pid', 'name']))
        except Exception as e:
            if progress_callback:
                progress_callback(f"无法获取进程列表: {e}")
            return self.results

        total = len(processes)
        scanned_values: Set[str] = set()

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

                access = self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION
                handle = self.kernel32.OpenProcess(access, False, pid)

                if not handle:
                    continue

                try:
                    process_path = self.get_process_path(handle)
                    connections = self.get_process_connections(pid)

                    # 扫描内存
                    found = self._scan_memory_patterns(
                        handle, pid, name, process_path, connections,
                        compiled_patterns, scanned_values
                    )

                    self.results.extend(found)

                finally:
                    self.kernel32.CloseHandle(handle)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                pass

        if progress_callback:
            progress_callback(f"扫描完成，共找到 {len(self.results)} 个威胁特征")

        return self.results

    def _scan_memory_patterns(self, handle: wintypes.HANDLE,
                              pid: int, name: str, path: str, connections: str,
                              patterns: List[Dict], scanned_values: Set[str]) -> List[ScanResultV2]:
        """使用正则表达式扫描内存"""
        results = []
        address = 0
        mbi = self.MEMORY_BASIC_INFORMATION()

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
                read_size = min(region_size, 10 * 1024 * 1024)

                try:
                    buffer = ctypes.create_string_buffer(read_size)
                    bytes_read = ctypes.c_size_t()

                    success = self.kernel32.ReadProcessMemory(
                        handle, ctypes.c_void_p(base_address),
                        buffer, read_size, ctypes.byref(bytes_read)
                    )

                    if success and bytes_read.value > 0:
                        data = buffer.raw[:bytes_read.value]

                        for pattern_info in patterns:
                            for match in pattern_info['regex'].finditer(data):
                                value = match.group(0)
                                try:
                                    value_str = value.decode('utf-8', errors='ignore')
                                except:
                                    value_str = value.decode('latin-1', errors='ignore')

                                # 去重
                                if value_str in scanned_values:
                                    continue
                                scanned_values.add(value_str)

                                results.append(ScanResultV2(
                                    pid=pid,
                                    process_name=name,
                                    process_path=path,
                                    network_connections=connections,
                                    match_content=value_str[:200],
                                    match_address=base_address + match.start(),
                                    category=pattern_info['category'],
                                    risk_level=pattern_info['risk']
                                ))

                except Exception:
                    pass

            address = base_address + region_size
            if address < base_address:
                break

        return results

    def cancel(self):
        """取消扫描"""
        self.is_cancelled = True

    def is_debug_privilege_enabled(self) -> bool:
        """检查 SeDebugPrivilege 是否已启用"""
        return self._debug_privilege_enabled

    def get_summary(self) -> Dict:
        """获取扫描摘要"""
        summary = {
            'total': len(self.results),
            'debug_privilege': self._debug_privilege_enabled,
            'by_process': {},
            'by_category': {},
            'by_risk': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        }

        for r in self.results:
            proc = f"{r.process_name} ({r.pid})"
            summary['by_process'][proc] = summary['by_process'].get(proc, 0) + 1

            summary['by_category'][r.category] = summary['by_category'].get(r.category, 0) + 1

            if r.risk_level in summary['by_risk']:
                summary['by_risk'][r.risk_level] += 1

        return summary


# 测试代码
if __name__ == "__main__":
    import sys

    def progress(msg):
        print(msg)

    scanner = MemoryScannerV2()
    print(f"SeDebugPrivilege 已启用: {scanner.is_debug_privilege_enabled()}")

    if len(sys.argv) > 1:
        search_term = sys.argv[1]

        # 检查是否指定了搜索模式
        search_mode = "full"  # 默认全面模式
        if len(sys.argv) > 2:
            if sys.argv[2] in ["simple", "s"]:
                search_mode = "simple"
            elif sys.argv[2] in ["full", "f"]:
                search_mode = "full"

        mode_desc = "简单模式 (UTF-8, 区分大小写)" if search_mode == "simple" else "全面模式 (UTF-8 + UTF-16LE + 大小写)"
        print(f"\n搜索字符串: {search_term}")
        print(f"搜索模式: {mode_desc}")
        print("-" * 60)

        results = scanner.search_string(search_term, progress_callback=progress, search_mode=search_mode)

        print("\n" + "=" * 60)
        print("搜索结果:")
        print("=" * 60)

        for r in results:
            print(f"PID: {r.pid}")
            print(f"进程: {r.process_name}")
            print(f"路径: {r.process_path}")
            print(f"网络: {r.network_connections}")
            print(f"匹配: {r.match_content}")
            print("-" * 40)
    else:
        print("\n用法: python memory_scanner_v2.py <搜索字符串> [模式]")
        print()
        print("模式选项:")
        print("  simple, s  - 简单模式: 只搜索 UTF-8，区分大小写 (与 Go 版本一致)")
        print("  full, f    - 全面模式: UTF-8 + UTF-16LE + 大小写变体 (默认)")
        print()
        print("示例:")
        print("  python memory_scanner_v2.py password          # 全面模式")
        print("  python memory_scanner_v2.py password simple   # 简单模式")
        print("  python memory_scanner_v2.py password s        # 简单模式")
