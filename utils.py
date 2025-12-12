#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
辅助函数模块
包含通用的辅助函数
"""

import os
import ctypes
import psutil
from constants import (
    PROCMON_LOGS_DIR, SUSPICIOUS_PORTS, SUSPICIOUS_PROCESSES,
    SYSTEM_PROCESSES, SUSPICIOUS_PATH_KEYWORDS, SUSPICIOUS_EXTENSIONS,
    SYSTEM_DIRECTORIES
)


# ==================== 权限检查 ====================

def is_admin():
    """检查是否以管理员身份运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# ==================== 目录管理 ====================

def ensure_logs_directory():
    """确保日志目录存在"""
    if not os.path.exists(PROCMON_LOGS_DIR):
        os.makedirs(PROCMON_LOGS_DIR)


def ensure_directory(directory):
    """确保指定目录存在"""
    if not os.path.exists(directory):
        os.makedirs(directory)


# ==================== 进程相关 ====================

def is_system_process(proc_name):
    """判断是否为系统进程"""
    return proc_name.lower() in [p.lower() for p in SYSTEM_PROCESSES]


def is_suspicious_process_name(proc_name):
    """判断进程名是否可疑"""
    return proc_name.lower() in [p.lower() for p in SUSPICIOUS_PROCESSES]


def get_process_info(pid):
    """获取进程详细信息"""
    try:
        proc = psutil.Process(pid)
        return {
            'pid': pid,
            'name': proc.name(),
            'exe': proc.exe(),
            'cmdline': ' '.join(proc.cmdline()),
            'cwd': proc.cwd(),
            'status': proc.status(),
            'username': proc.username(),
            'create_time': proc.create_time(),
            'cpu_percent': proc.cpu_percent(),
            'memory_percent': proc.memory_percent(),
            'num_threads': proc.num_threads(),
            'num_handles': proc.num_handles() if hasattr(proc, 'num_handles') else 0,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def get_process_parent(pid):
    """获取进程的父进程"""
    try:
        proc = psutil.Process(pid)
        return proc.ppid()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def get_process_children(pid):
    """获取进程的子进程列表"""
    try:
        proc = psutil.Process(pid)
        return [child.pid for child in proc.children(recursive=False)]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


# ==================== 网络相关 ====================

def is_suspicious_port(port):
    """判断端口是否可疑"""
    return int(port) in SUSPICIOUS_PORTS


def is_local_ip(ip):
    """判断是否为本地IP"""
    return ip.startswith('127.') or ip.startswith('192.168.') or \
           ip.startswith('10.') or ip.startswith('172.') or \
           ip == '0.0.0.0' or ip == '::1' or ip == '::'


# ==================== 路径相关 ====================

def is_suspicious_path(path):
    """判断路径是否可疑"""
    if not path:
        return False
    
    path_upper = path.upper()
    
    # 检查可疑路径关键词
    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if keyword in path_upper:
            return True
    
    return False


def is_suspicious_extension(filename):
    """判断文件扩展名是否可疑"""
    if not filename:
        return False
    
    ext = os.path.splitext(filename)[1].lower()
    return ext in SUSPICIOUS_EXTENSIONS


def is_system_directory(path):
    """判断路径是否在系统目录"""
    if not path:
        return False
    
    path_upper = path.upper()
    
    for sys_dir in SYSTEM_DIRECTORIES:
        if path_upper.startswith(sys_dir):
            return True
    
    return False


# ==================== 输入验证 ====================

def validate_pid_input(pid_str):
    """验证PID输入"""
    if not pid_str:
        return False, "请输入进程PID"
    
    try:
        pid = int(pid_str)
        if pid <= 0:
            return False, "PID必须大于0"
        
        # 检查进程是否存在
        if not psutil.pid_exists(pid):
            return False, f"进程 {pid} 不存在"
        
        return True, ""
    except ValueError:
        return False, "PID必须是数字"


# ==================== 文件操作 ====================

def create_procmon_log_path(pid):
    """创建Procmon日志文件路径"""
    ensure_logs_directory()
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return os.path.join(PROCMON_LOGS_DIR, f'procmon_{pid}_{timestamp}')


def get_file_size_str(size_bytes):
    """将字节大小转换为可读字符串"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


# ==================== 时间格式化 ====================

def format_timestamp(timestamp):
    """格式化时间戳"""
    from datetime import datetime
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def get_current_timestamp():
    """获取当前时间戳字符串"""
    from datetime import datetime
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# ==================== 文件信息获取 ====================

def get_file_info(file_path):
    """获取文件详细信息"""
    if not os.path.exists(file_path):
        return None

    try:
        stat_info = os.stat(file_path)
        from datetime import datetime

        return {
            'path': file_path,
            'size': stat_info.st_size,
            'size_str': get_file_size_str(stat_info.st_size),
            'created': datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'modified': datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'accessed': datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
        }
    except Exception as e:
        return None


def get_file_version_info(file_path):
    """获取文件版本信息（Windows PE文件）"""
    try:
        import win32api
        import pywintypes

        try:
            info = win32api.GetFileVersionInfo(file_path, '\\')
            ms = info['FileVersionMS']
            ls = info['FileVersionLS']
            version = f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"

            # 获取字符串信息
            lang, codepage = win32api.GetFileVersionInfo(file_path, '\\VarFileInfo\\Translation')[0]

            string_info = {}
            for name in ['CompanyName', 'FileDescription', 'FileVersion', 'InternalName',
                        'LegalCopyright', 'OriginalFilename', 'ProductName', 'ProductVersion']:
                try:
                    string_key = f'\\StringFileInfo\\{lang:04X}{codepage:04X}\\{name}'
                    string_info[name] = win32api.GetFileVersionInfo(file_path, string_key)
                except:
                    string_info[name] = 'N/A'

            return {
                'version': version,
                'company': string_info.get('CompanyName', 'N/A'),
                'description': string_info.get('FileDescription', 'N/A'),
                'product': string_info.get('ProductName', 'N/A'),
                'copyright': string_info.get('LegalCopyright', 'N/A'),
                'original_filename': string_info.get('OriginalFilename', 'N/A'),
            }
        except pywintypes.error:
            return None
    except ImportError:
        # 如果没有安装pywin32，返回简化版本
        return None


def get_file_signature_info(file_path):
    """获取文件数字签名信息"""
    try:
        import subprocess
        import os

        # 安全验证：检查路径是否存在且是文件
        if not file_path or not isinstance(file_path, str):
            return {
                'status': 'Error',
                'signed': False,
                'signer': 'N/A',
                'issuer': 'N/A'
            }

        # 规范化路径
        safe_path = os.path.normpath(file_path)

        # 检查文件是否存在
        if not os.path.isfile(safe_path):
            return {
                'status': 'FileNotFound',
                'signed': False,
                'signer': 'N/A',
                'issuer': 'N/A'
            }

        # 使用 PowerShell 的 -LiteralPath 参数避免通配符展开
        # 并且使用转义的单引号来防止命令注入
        # 单引号内只有单引号本身需要转义（用两个单引号）
        escaped_path = safe_path.replace("'", "''")

        # 使用 PowerShell 脚本块形式，更安全
        ps_script = f'''
        $path = '{escaped_path}'
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        if ($sig.Status -eq "Valid") {{
            Write-Output "Valid"
            Write-Output $sig.SignerCertificate.Subject
            Write-Output $sig.SignerCertificate.Issuer
        }} else {{
            Write-Output $sig.Status
        }}
        '''

        result = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0 and result.stdout:
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 1:
                status = lines[0].strip()
                if status == 'Valid' and len(lines) >= 3:
                    return {
                        'status': 'Valid',
                        'signed': True,
                        'signer': lines[1].strip(),
                        'issuer': lines[2].strip()
                    }
                else:
                    return {
                        'status': status,
                        'signed': False,
                        'signer': 'N/A',
                        'issuer': 'N/A'
                    }

        return {
            'status': 'Unknown',
            'signed': False,
            'signer': 'N/A',
            'issuer': 'N/A'
        }
    except Exception as e:
        return {
            'status': 'Error',
            'signed': False,
            'signer': 'N/A',
            'issuer': 'N/A'
        }


def get_file_hashes(file_path):
    """计算文件的哈希值（MD5, SHA1, SHA256）"""
    import hashlib

    hashes = {
        'md5': 'N/A',
        'sha1': 'N/A',
        'sha256': 'N/A',
        'error': None
    }

    try:
        # 创建哈希对象
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        # 读取文件并计算哈希（分块读取以支持大文件）
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)  # 8KB 块
                if not chunk:
                    break
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)

        hashes['md5'] = md5_hash.hexdigest().upper()
        hashes['sha1'] = sha1_hash.hexdigest().upper()
        hashes['sha256'] = sha256_hash.hexdigest().upper()

    except Exception as e:
        hashes['error'] = str(e)

    return hashes


def get_file_pe_info(file_path):
    """获取PE文件的额外信息（架构、入口点等）"""
    pe_info = {
        'is_pe': False,
        'architecture': 'N/A',
        'subsystem': 'N/A',
        'entry_point': 'N/A',
        'image_base': 'N/A',
        'error': None
    }

    try:
        with open(file_path, 'rb') as f:
            # 检查 MZ 头
            if f.read(2) != b'MZ':
                return pe_info

            pe_info['is_pe'] = True

            # 读取 PE 头位置
            f.seek(0x3C)
            pe_offset = int.from_bytes(f.read(4), 'little')

            # 检查 PE 签名
            f.seek(pe_offset)
            if f.read(4) != b'PE\x00\x00':
                return pe_info

            # 读取机器类型
            machine = int.from_bytes(f.read(2), 'little')
            if machine == 0x14c:
                pe_info['architecture'] = 'x86 (32-bit)'
            elif machine == 0x8664:
                pe_info['architecture'] = 'x64 (64-bit)'
            elif machine == 0x1c0:
                pe_info['architecture'] = 'ARM'
            elif machine == 0xaa64:
                pe_info['architecture'] = 'ARM64'
            else:
                pe_info['architecture'] = f'Unknown (0x{machine:X})'

            # 跳过其他字段到 Optional Header
            f.seek(pe_offset + 24)

            # 读取 Optional Header Magic
            magic = int.from_bytes(f.read(2), 'little')

            if magic == 0x10b:  # PE32
                # 跳到 Subsystem (offset 68 from Optional Header start)
                f.seek(pe_offset + 24 + 68)
                subsystem = int.from_bytes(f.read(2), 'little')

                # 读取 ImageBase (offset 28)
                f.seek(pe_offset + 24 + 28)
                image_base = int.from_bytes(f.read(4), 'little')
                pe_info['image_base'] = f'0x{image_base:08X}'

                # 读取 AddressOfEntryPoint (offset 16)
                f.seek(pe_offset + 24 + 16)
                entry_point = int.from_bytes(f.read(4), 'little')
                pe_info['entry_point'] = f'0x{entry_point:08X}'

            elif magic == 0x20b:  # PE32+
                # 跳到 Subsystem (offset 68 from Optional Header start)
                f.seek(pe_offset + 24 + 68)
                subsystem = int.from_bytes(f.read(2), 'little')

                # 读取 ImageBase (offset 24)
                f.seek(pe_offset + 24 + 24)
                image_base = int.from_bytes(f.read(8), 'little')
                pe_info['image_base'] = f'0x{image_base:016X}'

                # 读取 AddressOfEntryPoint (offset 16)
                f.seek(pe_offset + 24 + 16)
                entry_point = int.from_bytes(f.read(4), 'little')
                pe_info['entry_point'] = f'0x{entry_point:08X}'

            # 子系统映射
            subsystem_map = {
                1: 'Native',
                2: 'Windows GUI',
                3: 'Windows CUI (Console)',
                5: 'OS/2 CUI',
                7: 'POSIX CUI',
                9: 'Windows CE GUI',
                10: 'EFI Application',
                16: 'Windows Boot Application'
            }
            pe_info['subsystem'] = subsystem_map.get(subsystem, f'Unknown ({subsystem})')

    except Exception as e:
        pe_info['error'] = str(e)

    return pe_info


def get_dll_detailed_info(dll_path):
    """获取DLL的详细信息（整合所有信息）"""
    info = {
        'path': dll_path,
        'exists': os.path.exists(dll_path),
        'file_info': None,
        'version_info': None,
        'signature_info': None,
        'hashes': None,
        'pe_info': None
    }

    if not info['exists']:
        return info

    # 获取基本文件信息
    info['file_info'] = get_file_info(dll_path)

    # 获取版本信息
    info['version_info'] = get_file_version_info(dll_path)

    # 获取签名信息
    info['signature_info'] = get_file_signature_info(dll_path)

    # 获取哈希值
    info['hashes'] = get_file_hashes(dll_path)

    # 获取PE信息
    info['pe_info'] = get_file_pe_info(dll_path)

    return info

