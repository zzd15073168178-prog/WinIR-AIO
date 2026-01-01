#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yara 规则扫描模块 - 使用 Yara 规则扫描进程内存和文件"""

import os
import sys
import ctypes
from ctypes import wintypes
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
import tempfile

# 尝试导入 yara
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


def get_resource_path(relative_path):
    """获取资源文件路径，支持 PyInstaller 打包"""
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller 打包后的临时目录
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


@dataclass
class YaraMatch:
    """Yara 匹配结果"""
    rule_name: str          # 规则名称
    rule_tags: List[str]    # 规则标签
    rule_meta: Dict         # 规则元数据
    strings: List[Dict]     # 匹配的字符串
    target: str             # 扫描目标（进程名或文件路径）
    target_type: str        # 目标类型：process / file
    pid: int = 0            # 进程 ID（如果是进程扫描）


class YaraScanner:
    """Yara 规则扫描器"""

    # Windows API 常量
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    PAGE_READABLE = (0x02 | 0x04 | 0x20 | 0x40 | 0x80)

    # 内置规则 - 常见恶意软件特征
    BUILTIN_RULES = '''
rule Mimikatz_Strings {
    meta:
        description = "Mimikatz credential dumping tool"
        author = "Security Tool"
        severity = "critical"
        reference = "https://github.com/gentilkiwi/mimikatz"
    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa" ascii wide nocase
        $s3 = "kerberos::list" ascii wide nocase
        $s4 = "privilege::debug" ascii wide nocase
        $s5 = "lsadump::sam" ascii wide nocase
        $s6 = "sekurlsa::logonpasswords" ascii wide nocase
        $s7 = "gentilkiwi" ascii wide nocase
    condition:
        2 of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike Beacon payload"
        author = "Security Tool"
        severity = "critical"
        reference = "https://www.cobaltstrike.com/"
    strings:
        $s1 = "beacon.dll" ascii wide nocase
        $s2 = "beacon.x64.dll" ascii wide nocase
        $s3 = "%s as %s\\%s: %d" ascii wide
        $s4 = "could not spawn" ascii wide
        $s5 = "could not open process token" ascii wide
        $s6 = "ReflectiveLoader" ascii wide
        $s7 = ".sleeptime" ascii wide
        $s8 = ".jitter" ascii wide
        $beacon = { 69 68 69 68 69 6B 69 6B }
    condition:
        3 of them
}

rule Metasploit_Meterpreter {
    meta:
        description = "Metasploit Meterpreter payload"
        author = "Security Tool"
        severity = "critical"
        reference = "https://www.metasploit.com/"
    strings:
        $s1 = "meterpreter" ascii wide nocase
        $s2 = "metasploit" ascii wide nocase
        $s3 = "stdapi_" ascii wide
        $s4 = "priv_" ascii wide
        $s5 = "ext_server" ascii wide
        $s6 = "metsrv.dll" ascii wide nocase
        $s7 = "reverse_tcp" ascii wide nocase
    condition:
        2 of them
}

rule PowerShell_Encoded_Command {
    meta:
        description = "PowerShell encoded/obfuscated command"
        author = "Security Tool"
        severity = "high"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-encoded" ascii wide nocase
        $enc3 = "-e " ascii wide nocase
        $enc4 = "FromBase64String" ascii wide nocase
        $enc5 = "[Convert]::" ascii wide nocase
        $bypass1 = "-exec bypass" ascii wide nocase
        $bypass2 = "-executionpolicy bypass" ascii wide nocase
        $bypass3 = "Set-ExecutionPolicy" ascii wide nocase
        $hidden = "-w hidden" ascii wide nocase
        $noprofile = "-nop" ascii wide nocase
    condition:
        ($ps1 or $ps2) and (2 of ($enc*) or 2 of ($bypass*) or $hidden or $noprofile)
}

rule Suspicious_Shellcode {
    meta:
        description = "Suspicious shellcode patterns"
        author = "Security Tool"
        severity = "critical"
    strings:
        $sc1 = { FC E8 }           // cld; call
        $sc2 = { 60 89 E5 }        // pushad; mov ebp, esp
        $sc3 = { E8 00 00 00 00 }  // call $+5 (get EIP)
        $sc4 = { 64 A1 30 00 00 00 }  // mov eax, fs:[0x30] (PEB access)
        $sc5 = { 64 8B 0D 30 00 00 00 }  // mov ecx, fs:[0x30]
        $sc6 = { 31 C0 64 8B 40 30 }  // xor eax,eax; mov eax, fs:[eax+0x30]
        $sc7 = { EB ?? 5? }        // jmp short; pop reg (GetPC)
    condition:
        2 of them
}

rule Webshell_Generic {
    meta:
        description = "Generic webshell patterns"
        author = "Security Tool"
        severity = "high"
    strings:
        $php1 = "<?php" ascii nocase
        $php2 = "eval(" ascii nocase
        $php3 = "base64_decode(" ascii nocase
        $php4 = "system(" ascii nocase
        $php5 = "shell_exec(" ascii nocase
        $php6 = "passthru(" ascii nocase
        $php7 = "exec(" ascii nocase
        $asp1 = "<%@ " ascii nocase
        $asp2 = "Request(" ascii nocase
        $asp3 = "Execute(" ascii nocase
        $jsp1 = "Runtime.getRuntime()" ascii nocase
        $jsp2 = "ProcessBuilder" ascii nocase
    condition:
        ($php1 and 2 of ($php*)) or ($asp1 and $asp2 and $asp3) or (any of ($jsp*))
}

rule Ransomware_Indicators {
    meta:
        description = "Ransomware indicators"
        author = "Security Tool"
        severity = "critical"
    strings:
        $ransom1 = "Your files have been encrypted" ascii wide nocase
        $ransom2 = "bitcoin" ascii wide nocase
        $ransom3 = "decrypt" ascii wide nocase
        $ransom4 = "ransom" ascii wide nocase
        $ransom5 = ".onion" ascii wide nocase
        $ransom6 = "pay" ascii wide nocase
        $ext1 = ".locked" ascii wide nocase
        $ext2 = ".encrypted" ascii wide nocase
        $ext3 = ".crypted" ascii wide nocase
        $shadow = "vssadmin" ascii wide nocase
        $shadow2 = "wmic shadowcopy" ascii wide nocase
    condition:
        3 of ($ransom*) or (any of ($ext*) and any of ($shadow*))
}

rule Keylogger_Indicators {
    meta:
        description = "Keylogger indicators"
        author = "Security Tool"
        severity = "high"
    strings:
        $api1 = "GetAsyncKeyState" ascii wide
        $api2 = "SetWindowsHookEx" ascii wide
        $api3 = "GetKeyboardState" ascii wide
        $api4 = "GetKeyState" ascii wide
        $api5 = "RegisterHotKey" ascii wide
        $log1 = "keylog" ascii wide nocase
        $log2 = "keystroke" ascii wide nocase
        $hook = "WH_KEYBOARD" ascii wide
    condition:
        3 of ($api*) or any of ($log*) or $hook
}

rule Credential_Stealer {
    meta:
        description = "Credential stealing indicators"
        author = "Security Tool"
        severity = "high"
    strings:
        $browser1 = "Login Data" ascii wide
        $browser2 = "logins.json" ascii wide
        $browser3 = "cookies.sqlite" ascii wide
        $browser4 = "Chrome" ascii wide
        $browser5 = "Firefox" ascii wide
        $browser6 = "Edge" ascii wide
        $cred1 = "CredEnumerate" ascii wide
        $cred2 = "CryptUnprotectData" ascii wide
        $cred3 = "vaultcli" ascii wide
        $mail1 = "outlook" ascii wide nocase
        $mail2 = "thunderbird" ascii wide nocase
    condition:
        (2 of ($browser*) and any of ($cred*)) or (any of ($mail*) and any of ($cred*))
}

rule Suspicious_Network_Indicators {
    meta:
        description = "Suspicious network indicators"
        author = "Security Tool"
        severity = "medium"
    strings:
        $socket1 = "WSAStartup" ascii wide
        $socket2 = "socket" ascii wide
        $socket3 = "connect" ascii wide
        $socket4 = "bind" ascii wide
        $http1 = "HttpSendRequest" ascii wide
        $http2 = "InternetOpen" ascii wide
        $http3 = "URLDownloadToFile" ascii wide
        $dns1 = "DnsQuery" ascii wide
        $dns2 = "gethostbyname" ascii wide
        $port1 = ":4444" ascii wide
        $port2 = ":5555" ascii wide
        $port3 = ":1234" ascii wide
        $port4 = ":31337" ascii wide
    condition:
        (3 of ($socket*) and any of ($port*)) or (2 of ($http*)) or any of ($port*) or any of ($dns*)
}

rule Process_Injection_Indicators {
    meta:
        description = "Process injection indicators"
        author = "Security Tool"
        severity = "high"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide
        $api5 = "RtlCreateUserThread" ascii wide
        $api6 = "QueueUserAPC" ascii wide
        $api7 = "SetThreadContext" ascii wide
        $api8 = "NtUnmapViewOfSection" ascii wide
    condition:
        3 of them
}

rule Persistence_Registry {
    meta:
        description = "Registry persistence indicators"
        author = "Security Tool"
        severity = "medium"
    strings:
        $reg1 = "CurrentVersion\\Run" ascii wide nocase
        $reg2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $reg3 = "Winlogon\\Shell" ascii wide nocase
        $reg4 = "Winlogon\\Userinit" ascii wide nocase
        $reg5 = "Explorer\\Shell Folders" ascii wide nocase
        $reg6 = "Image File Execution Options" ascii wide nocase
        $reg7 = "AppInit_DLLs" ascii wide nocase
        $reg8 = "Services\\" ascii wide nocase
    condition:
        2 of them
}

rule UAC_Bypass_Indicators {
    meta:
        description = "UAC bypass indicators"
        author = "Security Tool"
        severity = "high"
    strings:
        $fodhelper = "fodhelper" ascii wide nocase
        $eventvwr = "eventvwr" ascii wide nocase
        $sdclt = "sdclt" ascii wide nocase
        $cmstp = "cmstp" ascii wide nocase
        $computerdefaults = "computerdefaults" ascii wide nocase
        $slui = "slui" ascii wide nocase
        $env1 = "ms-settings" ascii wide nocase
        $env2 = "shell\\open\\command" ascii wide nocase
    condition:
        any of them
}

rule Suspicious_Strings_Generic {
    meta:
        description = "Generic suspicious strings"
        author = "Security Tool"
        severity = "low"
    strings:
        $cmd1 = "cmd.exe /c" ascii wide nocase
        $cmd2 = "command.com" ascii wide nocase
        $del1 = "del /f" ascii wide nocase
        $del2 = "rmdir /s" ascii wide nocase
        $net1 = "net user" ascii wide nocase
        $net2 = "net localgroup" ascii wide nocase
        $task = "schtasks" ascii wide nocase
        $wmi = "wmic" ascii wide nocase
        $reg = "reg add" ascii wide nocase
    condition:
        3 of them
}
'''

    def __init__(self):
        self.results: List[YaraMatch] = []
        self.is_cancelled = False
        self.compiled_rules = None
        self.custom_rules_path: Optional[str] = None
        self.rules_loaded = False

        # 加载 Windows API
        if os.name == 'nt':
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self._setup_api()

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

    @staticmethod
    def is_available() -> bool:
        """检查 yara-python 是否可用"""
        return YARA_AVAILABLE

    def load_builtin_rules(self) -> bool:
        """加载内置规则（优先从文件加载，支持打包）"""
        if not YARA_AVAILABLE:
            print("yara-python 未安装")
            return False

        try:
            # 优先尝试从文件加载（支持 PyInstaller 打包）
            rules_file = get_resource_path(os.path.join('rules', 'builtin.yar'))
            print(f"尝试加载规则文件: {rules_file}")

            if os.path.exists(rules_file):
                print(f"规则文件存在，正在编译...")
                self.compiled_rules = yara.compile(filepath=rules_file)
                self.rules_loaded = True
                print("从文件加载规则成功")
                return True
            else:
                print(f"规则文件不存在: {rules_file}")

            # 如果文件不存在，从内置字符串加载
            print("尝试从内置字符串加载规则...")
            self.compiled_rules = yara.compile(source=self.BUILTIN_RULES)
            self.rules_loaded = True
            print("从内置字符串加载规则成功")
            return True
        except yara.Error as e:
            print(f"编译规则失败: {e}")
            # 尝试从内置字符串作为后备
            try:
                print("尝试从内置字符串加载作为后备...")
                self.compiled_rules = yara.compile(source=self.BUILTIN_RULES)
                self.rules_loaded = True
                print("从内置字符串加载规则成功（后备）")
                return True
            except yara.Error as e2:
                print(f"内置字符串加载也失败: {e2}")
                return False
        except Exception as e:
            print(f"加载规则时发生未知错误: {e}")
            return False

    def load_rules_from_file(self, file_path: str) -> bool:
        """从文件加载规则"""
        if not YARA_AVAILABLE:
            return False

        if not os.path.exists(file_path):
            return False

        try:
            self.compiled_rules = yara.compile(filepath=file_path)
            self.custom_rules_path = file_path
            self.rules_loaded = True
            return True
        except yara.Error as e:
            print(f"编译规则文件失败: {e}")
            return False

    def load_rules_from_directory(self, dir_path: str) -> bool:
        """从目录加载所有 .yar/.yara 规则文件"""
        if not YARA_AVAILABLE:
            return False

        if not os.path.isdir(dir_path):
            return False

        filepaths = {}
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                if f.endswith(('.yar', '.yara')):
                    filepath = os.path.join(root, f)
                    # 使用文件名作为命名空间
                    namespace = os.path.splitext(f)[0]
                    filepaths[namespace] = filepath

        if not filepaths:
            return False

        try:
            self.compiled_rules = yara.compile(filepaths=filepaths)
            self.custom_rules_path = dir_path
            self.rules_loaded = True
            return True
        except yara.Error as e:
            print(f"编译规则目录失败: {e}")
            return False

    def load_combined_rules(self, custom_path: Optional[str] = None) -> bool:
        """加载内置规则 + 自定义规则"""
        if not YARA_AVAILABLE:
            return False

        sources = {'builtin': self.BUILTIN_RULES}

        if custom_path:
            if os.path.isfile(custom_path):
                try:
                    with open(custom_path, 'r', encoding='utf-8') as f:
                        sources['custom'] = f.read()
                except Exception:
                    pass
            elif os.path.isdir(custom_path):
                for root, dirs, files in os.walk(custom_path):
                    for f in files:
                        if f.endswith(('.yar', '.yara')):
                            filepath = os.path.join(root, f)
                            try:
                                with open(filepath, 'r', encoding='utf-8') as file:
                                    namespace = os.path.splitext(f)[0]
                                    sources[namespace] = file.read()
                            except Exception:
                                pass

        try:
            self.compiled_rules = yara.compile(sources=sources)
            self.rules_loaded = True
            return True
        except yara.Error as e:
            print(f"编译组合规则失败: {e}")
            return False

    def scan_file(self, file_path: str, timeout: int = 60) -> List[YaraMatch]:
        """扫描文件"""
        if not self.compiled_rules:
            return []

        results = []

        try:
            matches = self.compiled_rules.match(file_path, timeout=timeout)

            for match in matches:
                result = YaraMatch(
                    rule_name=match.rule,
                    rule_tags=list(match.tags),
                    rule_meta=dict(match.meta),
                    strings=self._format_strings(match.strings),
                    target=file_path,
                    target_type='file',
                    pid=0
                )
                results.append(result)
                self.results.append(result)

        except yara.Error as e:
            print(f"扫描文件失败: {e}")

        return results

    def scan_process(self, pid: int, process_name: str = "",
                     progress_callback: Callable = None) -> List[YaraMatch]:
        """扫描进程内存"""
        if not self.compiled_rules:
            return []

        results = []

        # 打开进程
        access = self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION
        handle = self.kernel32.OpenProcess(access, False, pid)

        if not handle:
            if progress_callback:
                progress_callback(f"无法打开进程 {pid}: 权限不足")
            return results

        try:
            # 读取进程内存
            memory_data = self._read_process_memory(handle, progress_callback)

            if memory_data:
                # 写入临时文件进行扫描（yara-python 不直接支持内存扫描）
                with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
                    tmp.write(memory_data)
                    tmp_path = tmp.name

                try:
                    matches = self.compiled_rules.match(tmp_path, timeout=120)

                    for match in matches:
                        result = YaraMatch(
                            rule_name=match.rule,
                            rule_tags=list(match.tags),
                            rule_meta=dict(match.meta),
                            strings=self._format_strings(match.strings),
                            target=process_name or f"PID:{pid}",
                            target_type='process',
                            pid=pid
                        )
                        results.append(result)
                        self.results.append(result)

                finally:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass

        finally:
            self.kernel32.CloseHandle(handle)

        return results

    def _read_process_memory(self, handle, progress_callback: Callable = None) -> bytes:
        """读取进程内存"""
        all_data = bytearray()
        address = 0
        mbi = self.MEMORY_BASIC_INFORMATION()
        max_size = 100 * 1024 * 1024  # 最大读取 100MB

        while len(all_data) < max_size:
            if self.is_cancelled:
                break

            ret = self.kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address),
                ctypes.byref(mbi), ctypes.sizeof(mbi)
            )

            if ret == 0:
                break

            state = mbi.State or 0
            protect = mbi.Protect or 0

            if (state == self.MEM_COMMIT and
                protect & self.PAGE_READABLE and
                not protect & 0x100):

                region_size = mbi.RegionSize or 0
                base_address = mbi.BaseAddress or 0

                if region_size == 0 or base_address == 0:
                    address = base_address + region_size if region_size else address + 0x1000
                    continue

                # 限制单个区域大小
                if region_size > 10 * 1024 * 1024:
                    region_size = 10 * 1024 * 1024

                try:
                    buffer = ctypes.create_string_buffer(region_size)
                    bytes_read = ctypes.c_size_t()

                    success = self.kernel32.ReadProcessMemory(
                        handle, ctypes.c_void_p(base_address),
                        buffer, region_size, ctypes.byref(bytes_read)
                    )

                    if success and bytes_read.value > 0:
                        all_data.extend(buffer.raw[:bytes_read.value])

                except Exception:
                    pass

            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            address = base + size

            if address <= base or size == 0:
                break

        return bytes(all_data)

    def scan_directory(self, dir_path: str, extensions: List[str] = None,
                       progress_callback: Callable = None) -> List[YaraMatch]:
        """扫描目录中的文件"""
        if not self.compiled_rules:
            return []

        if extensions is None:
            extensions = ['.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs', '.js',
                         '.php', '.asp', '.aspx', '.jsp', '.jar', '.py', '.sh']

        results = []
        files_to_scan = []

        # 收集文件
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                if any(f.lower().endswith(ext) for ext in extensions):
                    files_to_scan.append(os.path.join(root, f))

        total = len(files_to_scan)

        for i, file_path in enumerate(files_to_scan):
            if self.is_cancelled:
                break

            if progress_callback:
                progress_callback(f"[{i+1}/{total}] 扫描: {os.path.basename(file_path)}")

            try:
                file_results = self.scan_file(file_path)
                results.extend(file_results)
            except Exception:
                pass

        return results

    def _format_strings(self, strings) -> List[Dict]:
        """格式化匹配字符串"""
        result = []
        for s in strings:
            try:
                # yara-python 4.x 格式
                if hasattr(s, 'identifier'):
                    result.append({
                        'offset': s.instances[0].offset if s.instances else 0,
                        'identifier': s.identifier,
                        'data': str(s.instances[0].matched_data[:50]) if s.instances else ''
                    })
                else:
                    # 旧版格式 (offset, identifier, data)
                    result.append({
                        'offset': s[0],
                        'identifier': s[1],
                        'data': str(s[2][:50]) if len(s[2]) > 50 else str(s[2])
                    })
            except Exception:
                pass
        return result

    def cancel(self):
        """取消扫描"""
        self.is_cancelled = True

    def reset(self):
        """重置扫描器"""
        self.results = []
        self.is_cancelled = False

    def get_summary(self) -> Dict:
        """获取扫描摘要"""
        summary = {
            'total_matches': len(self.results),
            'by_rule': {},
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_target_type': {'file': 0, 'process': 0}
        }

        for result in self.results:
            # 按规则统计
            if result.rule_name not in summary['by_rule']:
                summary['by_rule'][result.rule_name] = 0
            summary['by_rule'][result.rule_name] += 1

            # 按严重程度统计
            severity = result.rule_meta.get('severity', 'medium')
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1

            # 按目标类型统计
            if result.target_type in summary['by_target_type']:
                summary['by_target_type'][result.target_type] += 1

        return summary

    def export_results(self, output_path: str, format_type: str = 'json') -> bool:
        """导出结果"""
        try:
            if format_type == 'json':
                import json
                data = []
                for r in self.results:
                    data.append({
                        'rule_name': r.rule_name,
                        'rule_tags': r.rule_tags,
                        'rule_meta': r.rule_meta,
                        'strings': r.strings,
                        'target': r.target,
                        'target_type': r.target_type,
                        'pid': r.pid
                    })
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)

            elif format_type == 'csv':
                import csv
                with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(['规则名称', '严重程度', '标签', '目标', '类型', 'PID', '描述'])
                    for r in self.results:
                        writer.writerow([
                            r.rule_name,
                            r.rule_meta.get('severity', 'unknown'),
                            ', '.join(r.rule_tags),
                            r.target,
                            r.target_type,
                            r.pid,
                            r.rule_meta.get('description', '')
                        ])

            return True
        except Exception:
            return False

    def get_builtin_rule_info(self) -> List[Dict]:
        """获取内置规则信息"""
        rules_info = [
            {'name': 'Mimikatz_Strings', 'severity': 'critical', 'description': 'Mimikatz 凭据转储工具'},
            {'name': 'CobaltStrike_Beacon', 'severity': 'critical', 'description': 'Cobalt Strike Beacon 载荷'},
            {'name': 'Metasploit_Meterpreter', 'severity': 'critical', 'description': 'Metasploit Meterpreter 载荷'},
            {'name': 'PowerShell_Encoded_Command', 'severity': 'high', 'description': 'PowerShell 编码/混淆命令'},
            {'name': 'Suspicious_Shellcode', 'severity': 'critical', 'description': '可疑 Shellcode 特征'},
            {'name': 'Webshell_Generic', 'severity': 'high', 'description': '通用 Webshell 检测'},
            {'name': 'Ransomware_Indicators', 'severity': 'critical', 'description': '勒索软件指标'},
            {'name': 'Keylogger_Indicators', 'severity': 'high', 'description': '键盘记录器指标'},
            {'name': 'Credential_Stealer', 'severity': 'high', 'description': '凭据窃取指标'},
            {'name': 'Suspicious_Network_Indicators', 'severity': 'medium', 'description': '可疑网络指标'},
            {'name': 'Process_Injection_Indicators', 'severity': 'high', 'description': '进程注入指标'},
            {'name': 'Persistence_Registry', 'severity': 'medium', 'description': '注册表持久化指标'},
            {'name': 'UAC_Bypass_Indicators', 'severity': 'high', 'description': 'UAC 绕过指标'},
            {'name': 'Suspicious_Strings_Generic', 'severity': 'low', 'description': '通用可疑字符串'},
        ]
        return rules_info
