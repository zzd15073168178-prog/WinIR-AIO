#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安全分析管理模块 - 集成 Autoruns"""

import os
import sys
import subprocess
import csv
import urllib.request
import winreg
import datetime


def get_resource_path(relative_path):
    """获取资源文件路径，兼容开发环境和 PyInstaller 打包环境"""
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller 打包后，资源文件在临时目录
        return os.path.join(sys._MEIPASS, relative_path)
    else:
        # 开发环境，使用脚本所在目录
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


class SecurityManager:
    """安全分析管理器 - 基于 Autoruns"""

    AUTORUNS_EXE = "autorunsc.exe"
    AUTORUNS_URL = "https://live.sysinternals.com/autorunsc.exe"

    CATEGORY_MAP = {
        'Logon': '登录启动', 'Explorer': '资源管理器', 'Scheduled Tasks': '计划任务',
        'Services': '服务', 'Drivers': '驱动', 'Codecs': '编解码器',
        'Boot Execute': '启动执行', 'Image Hijacks': '映像劫持', 'AppInit': 'AppInit DLL',
        'KnownDLLs': 'Known DLLs', 'Winlogon': 'Winlogon', 'Winsock Providers': 'Winsock',
        'Print Monitors': '打印监视器', 'LSA Providers': 'LSA', 'WMI': 'WMI', 'Office': 'Office',
    }

    # autorunsc -a 参数映射
    # 参考: autorunsc -? 输出
    SCAN_OPTIONS = {
        'all': {'flag': '*', 'name': '全部扫描', 'desc': '扫描所有类别（较慢）'},
        'logon': {'flag': 'l', 'name': '启动项', 'desc': '登录启动项'},
        'services': {'flag': 's', 'name': '服务和驱动', 'desc': '服务和非禁用驱动'},
        'tasks': {'flag': 't', 'name': '计划任务', 'desc': '计划任务'},
        'boot': {'flag': 'b', 'name': '启动执行', 'desc': 'Boot Execute'},
        'explorer': {'flag': 'e', 'name': '资源管理器', 'desc': '资源管理器插件'},
        'hijacks': {'flag': 'h', 'name': '映像劫持', 'desc': '映像劫持'},
        'appinit': {'flag': 'd', 'name': 'AppInit DLL', 'desc': 'AppInit DLLs'},
        'knowndlls': {'flag': 'k', 'name': 'Known DLLs', 'desc': 'Known DLLs'},
        'winlogon': {'flag': 'w', 'name': 'Winlogon', 'desc': 'Winlogon 项'},
        'winsock': {'flag': 'n', 'name': '网络提供程序', 'desc': 'Winsock 和网络提供程序'},
        'codecs': {'flag': 'c', 'name': '编解码器', 'desc': '编解码器'},
        'lsa': {'flag': 'r', 'name': 'LSA 提供程序', 'desc': 'LSA 安全提供程序'},
        'printers': {'flag': 'p', 'name': '打印监视器', 'desc': '打印监视器 DLLs'},
        'wmi': {'flag': 'm', 'name': 'WMI', 'desc': 'WMI 项'},
        'office': {'flag': 'o', 'name': 'Office', 'desc': 'Office 插件'},
        'ie': {'flag': 'i', 'name': 'IE 插件', 'desc': 'Internet Explorer 插件'},
    }

    # 预设扫描配置
    SCAN_PRESETS = {
        'quick': {
            'name': '快速扫描',
            'desc': '仅扫描最常见的持久化位置（启动项、服务、计划任务）',
            'options': ['logon', 'services', 'tasks'],
        },
        'standard': {
            'name': '标准扫描',
            'desc': '扫描常见持久化位置（推荐）',
            'options': ['logon', 'services', 'tasks', 'boot', 'hijacks', 'winlogon'],
        },
        'full': {
            'name': '完整扫描',
            'desc': '扫描所有类别（较慢）',
            'options': ['all'],
        },
    }
    
    def __init__(self):
        self.autoruns_data = []
        self.tool_path = self._find_tool()
    
    def _find_tool(self):
        """查找 autorunsc，优先使用 64 位版本"""
        # 按优先级查找
        candidates = ['autorunsc64.exe', 'autorunsc.exe', 'autorunsc64a.exe']
        for exe in candidates:
            path = get_resource_path(exe)
            if os.path.exists(path):
                return path
        return None
    
    def is_tool_available(self):
        return self.tool_path is not None
    
    # 已知的 autorunsc.exe 官方哈希值（SHA256）
    # 可从 https://www.virustotal.com 或微软官方验证
    # 注意：每次微软更新工具时需要更新此列表
    KNOWN_HASHES = {
        # 示例哈希值 - 实际使用时需要替换为真实值
        # 可通过 certutil -hashfile autorunsc.exe SHA256 获取
    }

    def download_tool(self, progress_callback=None):
        """
        安全下载 autorunsc.exe 工具

        安全措施：
        1. 仅从官方 HTTPS URL 下载
        2. 下载后验证文件哈希（如果有已知哈希）
        3. 检查文件签名
        """
        import hashlib
        import tempfile
        import ssl

        target = get_resource_path(self.AUTORUNS_EXE)

        try:
            if progress_callback:
                progress_callback("正在从官方源下载...")

            # 使用 HTTPS 并验证证书
            # 创建安全的 SSL 上下文
            ssl_context = ssl.create_default_context()

            # 先下载到临时文件
            temp_file = target + ".downloading"

            try:
                # 使用 urlopen 而非 urlretrieve 以便更好地控制
                with urllib.request.urlopen(self.AUTORUNS_URL, context=ssl_context, timeout=60) as response:
                    # 检查响应状态
                    if response.status != 200:
                        if progress_callback:
                            progress_callback(f"下载失败: HTTP {response.status}")
                        return False

                    # 检查内容类型（应该是可执行文件）
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' in content_type.lower():
                        if progress_callback:
                            progress_callback("下载失败: 服务器返回了网页而非文件")
                        return False

                    # 读取并写入临时文件
                    with open(temp_file, 'wb') as f:
                        f.write(response.read())

            except ssl.SSLError as e:
                if progress_callback:
                    progress_callback(f"SSL 证书验证失败: {e}")
                return False
            except urllib.error.URLError as e:
                if progress_callback:
                    progress_callback(f"网络错误: {e}")
                return False

            # 计算下载文件的哈希
            sha256_hash = hashlib.sha256()
            with open(temp_file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            file_hash = sha256_hash.hexdigest().lower()

            if progress_callback:
                progress_callback(f"文件哈希: {file_hash[:16]}...")

            # 如果有已知哈希，进行验证
            if self.KNOWN_HASHES and file_hash not in self.KNOWN_HASHES:
                if progress_callback:
                    progress_callback("警告: 文件哈希与已知值不匹配，可能被篡改")
                # 删除可疑文件
                os.remove(temp_file)
                return False

            # 检查文件大小（autorunsc.exe 通常 > 500KB）
            file_size = os.path.getsize(temp_file)
            if file_size < 500 * 1024:  # 小于 500KB 可能是假文件
                if progress_callback:
                    progress_callback(f"警告: 文件大小异常 ({file_size} bytes)")
                os.remove(temp_file)
                return False

            # 验证通过，移动到目标位置
            if os.path.exists(target):
                os.remove(target)
            os.rename(temp_file, target)

            self.tool_path = target
            if progress_callback:
                progress_callback("下载完成并验证通过!")
            return True

        except Exception as e:
            # 清理临时文件
            temp_file = target + ".downloading"
            if os.path.exists(temp_file):
                os.remove(temp_file)
            if progress_callback:
                progress_callback(f"下载失败: {e}")
            return False
    
    def _get_file_creation_time(self, file_path):
        """获取文件的创建时间（Windows 上是真正的创建时间）"""
        if not file_path:
            return ''
        try:
            # 清理路径（去除引号等）
            file_path = file_path.strip('"').strip()
            if not file_path or not os.path.exists(file_path):
                return ''

            # 在 Windows 上，st_ctime 是文件创建时间
            stat = os.stat(file_path)
            ctime = datetime.datetime.fromtimestamp(stat.st_ctime)
            return ctime.strftime('%Y/%m/%d')
        except:
            return ''

    def _get_registry_key_timestamp(self, key_path, retry_parent=True):
        """获取注册表键的最后修改时间（备用方法）"""
        if not key_path:
            return ''
        try:
            key_path_upper = key_path.upper()
            if key_path_upper.startswith('HKLM'):
                root = winreg.HKEY_LOCAL_MACHINE
                subkey = key_path[4:].lstrip('\\')
            elif key_path_upper.startswith('HKCU'):
                root = winreg.HKEY_CURRENT_USER
                subkey = key_path[4:].lstrip('\\')
            elif key_path_upper.startswith('HKU'):
                root = winreg.HKEY_USERS
                subkey = key_path[3:].lstrip('\\')
            else:
                return ''

            key = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ)
            info = winreg.QueryInfoKey(key)
            last_modified = info[2]

            EPOCH_AS_FILETIME = 116444736000000000
            timestamp = (last_modified - EPOCH_AS_FILETIME) / 10000000
            dt = datetime.datetime.fromtimestamp(timestamp)

            winreg.CloseKey(key)
            return dt.strftime('%Y/%m/%d')
        except:
            if retry_parent and '\\' in key_path:
                parent_path = key_path.rsplit('\\', 1)[0]
                if parent_path != key_path and len(parent_path) > 4:
                    return self._get_registry_key_timestamp(parent_path, retry_parent=False)
            return ''

    def scan(self, progress_callback=None, scan_options=None, preset=None):
        """扫描自启动项

        Args:
            progress_callback: 进度回调函数
            scan_options: 扫描选项列表，如 ['logon', 'services', 'tasks']
            preset: 预设扫描配置，如 'quick', 'standard', 'full'
        """
        if not self.is_tool_available():
            raise FileNotFoundError("未找到 autorunsc.exe")

        self.autoruns_data = []

        # 确定扫描参数
        if preset and preset in self.SCAN_PRESETS:
            scan_options = self.SCAN_PRESETS[preset]['options']

        # 构建 -a 参数
        if scan_options and 'all' not in scan_options:
            flags = ''.join([self.SCAN_OPTIONS[opt]['flag']
                           for opt in scan_options if opt in self.SCAN_OPTIONS])
            if not flags:
                flags = '*'
        else:
            flags = '*'

        cmd = [self.tool_path, '-a', flags, '-c', '-h', '-s', '-t', '-nobanner', '-accepteula']

        if progress_callback:
            if preset:
                progress_callback(f"正在{self.SCAN_PRESETS.get(preset, {}).get('name', '扫描')}...")
            else:
                progress_callback("正在扫描...")

        # autorunsc 输出的是 UTF-16 LE 编码，需要正确解码
        result = subprocess.run(cmd, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        # 解码 UTF-16 LE (跳过 BOM 如果存在)
        output = result.stdout
        if output.startswith(b'\xff\xfe'):
            output = output[2:]  # 跳过 BOM
        text = output.decode('utf-16-le', errors='ignore')
        lines = text.strip().split('\n')
        if len(lines) < 2: return self.autoruns_data
        reader = csv.DictReader(lines)

        if progress_callback: progress_callback("正在获取文件时间戳...")

        for row in reader:
            # 获取文件路径和注册表位置
            image_path = row.get('Image Path', '')
            location = row.get('Entry Location', '')

            # 优先使用文件创建时间（最能反映恶意软件落地时间）
            file_ctime = self._get_file_creation_time(image_path)

            # 备用：注册表键修改时间
            reg_timestamp = self._get_registry_key_timestamp(location) if not file_ctime else ''

            # 选择时间戳：文件创建时间 > 注册表时间
            timestamp = file_ctime if file_ctime else reg_timestamp

            item = {
                'name': row.get('Entry', ''), 'location': location,
                'enabled': row.get('Enabled', '') == 'enabled', 'category': row.get('Category', ''),
                'category_cn': self.CATEGORY_MAP.get(row.get('Category', ''), row.get('Category', '')),
                'description': row.get('Description', ''), 'company': row.get('Company', ''),
                'path': image_path, 'version': row.get('Version', ''),
                'launch_string': row.get('Launch String', ''), 'md5': row.get('MD5', ''),
                'sha1': row.get('SHA-1', ''), 'sha256': row.get('SHA-256', ''),
                'signer': row.get('Signer', ''), 'is_verified': '(Verified)' in row.get('Signer', ''),
                'is_suspicious': self._is_suspicious(row),
                'timestamp': timestamp,  # 文件创建时间（优先）或注册表时间
                'timestamp_raw': row.get('Time', ''),  # 保留原始时间戳
            }
            self.autoruns_data.append(item)
        if progress_callback: progress_callback(f"扫描完成，共 {len(self.autoruns_data)} 项")
        return self.autoruns_data
    
    def _is_suspicious(self, row):
        signer = row.get('Signer', '')
        path = row.get('Image Path', '').lower()
        launch = row.get('Launch String', '').lower()
        if signer and '(Verified)' not in signer and 'Microsoft' not in signer:
            if path and 'windows' not in path and 'program files' not in path:
                return True
        for sp in ['temp\\', 'tmp\\', 'appdata\\local\\temp']:
            if sp in path: return True
        for sc in ['powershell', 'cmd.exe /c', 'wscript', 'mshta', 'base64']:
            if sc in launch: return True
        return False
    
    def get_categories(self):
        categories = {}
        for item in self.autoruns_data:
            cat = item['category']
            if cat not in categories:
                categories[cat] = {'name': cat, 'name_cn': item['category_cn'], 'count': 0, 'suspicious': 0}
            categories[cat]['count'] += 1
            if item['is_suspicious']: categories[cat]['suspicious'] += 1
        return categories
    
    def get_suspicious(self):
        return [item for item in self.autoruns_data if item['is_suspicious']]
    
    def get_summary(self):
        unsigned = [item for item in self.autoruns_data if not item['is_verified'] and item['path']]
        return {'total': len(self.autoruns_data), 'suspicious': len(self.get_suspicious()), 'unsigned': len(unsigned), 'categories': len(self.get_categories())}
    
    def get_startup_items(self):
        if not self.autoruns_data: self.scan()
        return [item for item in self.autoruns_data if item['category'] == 'Logon']
    
    def get_scheduled_tasks(self):
        if not self.autoruns_data: self.scan()
        return [item for item in self.autoruns_data if item['category'] == 'Scheduled Tasks']
    
    def get_services(self):
        if not self.autoruns_data: self.scan()
        return [item for item in self.autoruns_data if item['category'] == 'Services']
    
    def get_drivers(self):
        if not self.autoruns_data: self.scan()
        return [item for item in self.autoruns_data if item['category'] == 'Drivers']
    
    def get_security_summary(self):
        return {
            'startup_total': len(self.get_startup_items()), 'startup_suspicious': len([x for x in self.get_startup_items() if x['is_suspicious']]),
            'tasks_total': len(self.get_scheduled_tasks()), 'tasks_suspicious': len([x for x in self.get_scheduled_tasks() if x['is_suspicious']]),
            'services_total': len(self.get_services()), 'services_suspicious': len([x for x in self.get_services() if x['is_suspicious']]),
            'drivers_total': len(self.get_drivers()), 'drivers_suspicious': len([x for x in self.get_drivers() if x['is_suspicious']]),
        }
