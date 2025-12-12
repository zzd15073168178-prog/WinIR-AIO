#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
持久化机制检测模块
监控常见的恶意软件持久化手段
"""

import subprocess
import os
import winreg
import json
from datetime import datetime

# 需要监控的常见注册表持久化路径
REGISTRY_RUN_PATHS = [
    # 64位视图
    (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunServices'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnceEx'),
    (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunServices'),
    (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'),
    (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'),
    # 32位视图
    (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunServices'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx'),
]

STARTUP_APPROVED_PATHS = [
    (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'),
    (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'),
    (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'),
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'),
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'),
]

ACTIVE_SETUP_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Active Setup\Installed Components'),
    (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Active Setup\Installed Components'),
]

APPINIT_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'),
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'),
]


class PersistenceDetector:
    """持久化机制检测器

    通过快照对比的方式，检测样本运行前后的持久化项变化
    """

    def __init__(self):
        self.initial_snapshot = None
        self.final_snapshot = None
        self.changes = []

    # ==================== 主要方法 ====================

    def take_snapshot(self):
        """获取系统当前的持久化项快照"""
        snapshot = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'registry_run_keys': self._get_registry_run_keys(),
            'scheduled_tasks': self._get_scheduled_tasks(),
            'services': self._get_services(),
            'startup_folders': self._get_startup_folder_items(),
            'startup_approved': self._get_startup_approved_items(),
            'wmi_subscriptions': self._get_wmi_subscriptions(),
            'wmi_consumers': self._get_wmi_consumers(),
            'wmi_bindings': self._get_wmi_bindings(),
            'winlogon_keys': self._get_winlogon_keys(),
            'image_hijacks': self._get_image_file_hijacks(),
            'browser_extensions': self._get_browser_extensions(),
            'active_setup': self._get_active_setup_components(),
            'appinit_settings': self._get_appinit_settings(),
        }
        return snapshot

    def take_initial_snapshot(self):
        """在样本运行前获取初始快照"""
        print("[持久化检测] 正在获取初始快照...")
        self.initial_snapshot = self.take_snapshot()
        print(f"[持久化检测] 初始快照已获取")
        return self.initial_snapshot

    def take_final_snapshot(self):
        """在样本运行后获取最终快照"""
        print("[持久化检测] 正在获取最终快照...")
        self.final_snapshot = self.take_snapshot()
        print(f"[持久化检测] 最终快照已获取")
        return self.final_snapshot

    def detect_changes(self):
        """对比两次快照，检测持久化项的变化"""
        if not self.initial_snapshot or not self.final_snapshot:
            return []

        print("[持久化检测] 正在分析变化...")
        self.changes = []

        # 对比各类持久化项
        self._compare_registry_run_keys()
        self._compare_scheduled_tasks()
        self._compare_services()
        self._compare_startup_folders()
        self._compare_startup_approved()
        self._compare_wmi_subscriptions()
        self._compare_wmi_consumers()
        self._compare_wmi_bindings()
        self._compare_winlogon_keys()
        self._compare_image_hijacks()
        self._compare_browser_extensions()
        self._compare_active_setup_components()
        self._compare_appinit_settings()

        print(f"[持久化检测] 检测到 {len(self.changes)} 个变化")
        return self.changes

    # ==================== 注册表 Run 键检测 ====================

    def _get_registry_run_keys(self):
        """获取所有注册表启动项"""
        run_keys = []

        for hive, path in REGISTRY_RUN_PATHS:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        run_keys.append({
                            'hive': self._get_hive_name(hive),
                            'path': path,
                            'name': name,
                            'value': value,
                            'full_path': f"{self._get_hive_name(hive)}\\{path}\\{name}"
                        })
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(key)
            except FileNotFoundError:
                # 某些键可能不存在
                continue
            except Exception as e:
                print(f"[持久化检测] 读取注册表失败 {path}: {e}")
                continue

        return run_keys

    def _compare_registry_run_keys(self):
        """对比注册表Run键的变化"""
        initial = {item['full_path']: item for item in self.initial_snapshot['registry_run_keys']}
        final = {item['full_path']: item for item in self.final_snapshot['registry_run_keys']}

        # 新增或修改的项
        for full_path, item in final.items():
            if full_path not in initial:
                self.changes.append({
                    'type': 'Registry Run Key',
                    'action': 'Created',
                    'location': item['full_path'],
                    'value': item['value'],
                    'severity': 'critical',
                    'description': f"新增注册表启动项: {item['name']} -> {item['value']}"
                })
            elif initial[full_path]['value'] != item['value']:
                self.changes.append({
                    'type': 'Registry Run Key',
                    'action': 'Modified',
                    'location': item['full_path'],
                    'old_value': initial[full_path]['value'],
                    'new_value': item['value'],
                    'severity': 'warning',
                    'description': f"修改注册表启动项: {item['name']}"
                })

        # 删除的项
        for full_path, item in initial.items():
            if full_path not in final:
                self.changes.append({
                    'type': 'Registry Run Key',
                    'action': 'Deleted',
                    'location': item['full_path'],
                    'value': item['value'],
                    'severity': 'info',
                    'description': f"注册表启动项被删除: {item['name']}"
                })

    # ==================== 计划任务检测 ====================

    def _get_scheduled_tasks(self):
        """获取所有计划任务"""
        tasks = []

        try:
            # 使用 schtasks 命令获取任务列表
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'CSV', '/v', '/nh'],
                capture_output=True,
                text=True,
                encoding='gbk',  # Windows中文系统使用GBK编码
                errors='ignore',
                timeout=30
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if not line.strip():
                        continue

                    # CSV格式解析
                    parts = self._parse_csv_line(line)
                    if len(parts) >= 9:
                        task_name = parts[0].strip('"')
                        task_to_run = parts[8].strip('"') if len(parts) > 8 else ''

                        # 过滤掉系统默认任务
                        if task_name and not task_name.startswith('\\Microsoft\\'):
                            task_info = {
                                'name': task_name,
                                'command': task_to_run,
                                'status': parts[2].strip('"') if len(parts) > 2 else '',
                                'author': parts[6].strip('"') if len(parts) > 6 else '',
                                'schedule': parts[16].strip('"') if len(parts) > 16 else '',
                                'schedule_type': parts[17].strip('"') if len(parts) > 17 else '',
                                'start_time': parts[18].strip('"') if len(parts) > 18 else '',
                                'start_date': parts[19].strip('"') if len(parts) > 19 else '',
                                'enabled_state': parts[10].strip('"') if len(parts) > 10 else '',
                                'raw': line.strip()
                            }
                            tasks.append(task_info)
        except subprocess.TimeoutExpired:
            print("[持久化检测] 获取计划任务超时")
        except Exception as e:
            print(f"[持久化检测] 获取计划任务失败: {e}")

        return tasks

    def _parse_csv_line(self, line):
        """简单的CSV解析（处理带引号的字段）"""
        parts = []
        current = ''
        in_quotes = False

        for char in line:
            if char == '"':
                in_quotes = not in_quotes
                current += char
            elif char == ',' and not in_quotes:
                parts.append(current)
                current = ''
            else:
                current += char

        if current:
            parts.append(current)

        return parts

    def _compare_scheduled_tasks(self):
        """对比计划任务的变化"""
        initial = {task['name']: task for task in self.initial_snapshot['scheduled_tasks']}
        final = {task['name']: task for task in self.final_snapshot['scheduled_tasks']}

        # 新增的任务
        for name, task in final.items():
            if name not in initial:
                self.changes.append({
                    'type': 'Scheduled Task',
                    'action': 'Created',
                    'location': name,
                    'value': task['command'],
                    'severity': 'critical',
                    'description': f"新增计划任务: {name} -> {task['command']}"
                })
            else:
                fields_to_check = ['command', 'author', 'schedule', 'schedule_type', 'start_time', 'start_date', 'enabled_state']
                modified = any(initial[name].get(field) != task.get(field) for field in fields_to_check)
                if modified:
                    self.changes.append({
                        'type': 'Scheduled Task',
                        'action': 'Modified',
                        'location': name,
                        'severity': 'warning',
                        'old_value': {field: initial[name].get(field) for field in fields_to_check},
                        'new_value': {field: task.get(field) for field in fields_to_check},
                        'description': f"计划任务被修改: {name}"
                    })

        # 删除的任务
        for name, task in initial.items():
            if name not in final:
                self.changes.append({
                    'type': 'Scheduled Task',
                    'action': 'Deleted',
                    'location': name,
                    'value': task.get('command', ''),
                    'severity': 'warning',
                    'description': f"计划任务被删除: {name}"
                })

    # ==================== Windows 服务检测 ====================

    def _get_services(self):
        """获取所有Windows服务"""
        services = []

        try:
            # 使用 sc query 获取服务列表
            result = subprocess.run(
                ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=30
            )

            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_service = {}

                for line in lines:
                    line = line.strip()

                    if line.startswith('SERVICE_NAME:'):
                        if current_service:
                            details = self._get_service_details(current_service['name'])
                            current_service.update(details)
                            services.append(current_service)
                        current_service = {'name': line.split(':', 1)[1].strip()}

                    elif line.startswith('DISPLAY_NAME:'):
                        current_service['display_name'] = line.split(':', 1)[1].strip()

                    elif line.startswith('STATE'):
                        parts = line.split()
                        if len(parts) >= 3:
                            current_service['state'] = parts[3]

                if current_service:
                    details = self._get_service_details(current_service['name'])
                    current_service.update(details)
                    services.append(current_service)

            # 只保留用户安装的服务（可选：过滤系统服务）
            # services = [s for s in services if not self._is_system_service(s['name'])]

        except subprocess.TimeoutExpired:
            print("[持久化检测] 获取服务列表超时")
        except Exception as e:
            print(f"[持久化检测] 获取服务列表失败: {e}")

        return services

    def _get_service_details(self, service_name):
        """获取服务的详细信息"""
        details = {
            'binary_path': '',
            'start_type': '',
            'service_type': ''
        }

        try:
            result = subprocess.run(
                ['sc', 'qc', service_name],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if 'BINARY_PATH_NAME' in line:
                        details['binary_path'] = line.split(':', 1)[1].strip()
                    elif 'START_TYPE' in line:
                        details['start_type'] = line.split(':', 1)[1].strip()
                    elif 'TYPE' in line and 'SERVICE_TYPE' in line:
                        # TYPE行包含两部分，如 "TYPE : 10  WIN32_OWN_PROCESS"
                        details['service_type'] = line.split(':', 1)[1].strip()
        except Exception:
            pass

        return details

    def _compare_services(self):
        """对比服务的变化"""
        initial = {svc['name']: svc for svc in self.initial_snapshot['services']}
        final = {svc['name']: svc for svc in self.final_snapshot['services']}

        # 新增/修改的服务
        for name, svc in final.items():
            if name not in initial:
                self.changes.append({
                    'type': 'Windows Service',
                    'action': 'Created',
                    'location': name,
                    'value': svc.get('binary_path', ''),
                    'severity': 'critical',
                    'description': f"新增Windows服务: {name} ({svc.get('display_name', 'N/A')})"
                })
            else:
                fields = ['display_name', 'state', 'binary_path', 'start_type', 'service_type']
                if any(initial[name].get(field, '') != svc.get(field, '') for field in fields):
                    self.changes.append({
                        'type': 'Windows Service',
                        'action': 'Modified',
                        'location': name,
                        'severity': 'warning',
                        'old_value': {field: initial[name].get(field, '') for field in fields},
                        'new_value': {field: svc.get(field, '') for field in fields},
                        'description': f"Windows服务配置被修改: {name}"
                    })

        # 删除的服务
        for name, svc in initial.items():
            if name not in final:
                self.changes.append({
                    'type': 'Windows Service',
                    'action': 'Deleted',
                    'location': name,
                    'value': svc.get('binary_path', ''),
                    'severity': 'warning',
                    'description': f"Windows服务被删除: {name}"
                })

    # ==================== 启动文件夹检测 ====================

    def _get_startup_folder_items(self):
        """获取启动文件夹中的所有文件"""
        items = []

        # 启动文件夹路径
        startup_paths = [
            os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'),
        ]

        for folder in startup_paths:
            if os.path.exists(folder):
                try:
                    for item in os.listdir(folder):
                        item_path = os.path.join(folder, item)
                        items.append({
                            'folder': folder,
                            'name': item,
                            'path': item_path,
                            'is_file': os.path.isfile(item_path)
                        })
                except Exception as e:
                    print(f"[持久化检测] 读取启动文件夹失败 {folder}: {e}")

        return items

    def _get_startup_approved_items(self):
        """获取StartupApproved中的启动项状态（可记录禁用/启用情况）"""
        approved = []

        for hive, path in STARTUP_APPROVED_PATHS:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                i = 0

                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(key, i)
                        data_repr = self._format_reg_data(value)

                        approved.append({
                            'hive': self._get_hive_name(hive),
                            'path': path,
                            'name': name,
                            'type': value_type,
                            'data': data_repr,
                            'full_path': f"{self._get_hive_name(hive)}\\{path}\\{name}"
                        })
                        i += 1
                    except WindowsError:
                        break

                winreg.CloseKey(key)
            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"[持久化检测] 读取StartupApproved失败: {path}: {e}")

        return approved

    def _compare_startup_folders(self):
        """对比启动文件夹的变化"""
        initial = {item['path']: item for item in self.initial_snapshot['startup_folders']}
        final = {item['path']: item for item in self.final_snapshot['startup_folders']}

        # 新增的项
        for path, item in final.items():
            if path not in initial:
                self.changes.append({
                    'type': 'Startup Folder',
                    'action': 'Created',
                    'location': item['folder'],
                    'value': item['name'],
                    'severity': 'critical',
                    'description': f"启动文件夹新增文件: {item['name']}"
                })

        # 删除的项
        for path, item in initial.items():
            if path not in final:
                self.changes.append({
                    'type': 'Startup Folder',
                    'action': 'Deleted',
                    'location': item['folder'],
                    'value': item['name'],
                    'severity': 'warning',
                    'description': f"启动文件夹文件被删除: {item['name']}"
                })

    def _compare_startup_approved(self):
        """对比StartupApproved项的变化（禁用/启用状态）"""
        initial = {item['full_path']: item for item in self.initial_snapshot.get('startup_approved', [])}
        final = {item['full_path']: item for item in self.final_snapshot.get('startup_approved', [])}

        for full_path, item in final.items():
            if full_path not in initial:
                self.changes.append({
                    'type': 'Startup Approved',
                    'action': 'Created',
                    'location': full_path,
                    'value': item['data'],
                    'severity': 'warning',
                    'description': f"StartupApproved新增记录: {item['name']}"
                })
            elif initial[full_path]['data'] != item['data']:
                self.changes.append({
                    'type': 'Startup Approved',
                    'action': 'Modified',
                    'location': full_path,
                    'old_value': initial[full_path]['data'],
                    'new_value': item['data'],
                    'severity': 'warning',
                    'description': f"StartupApproved状态变化: {item['name']}"
                })

    # ==================== Active Setup 检测 ====================

    def _get_active_setup_components(self):
        """获取Active Setup已安装组件"""
        components = []

        for hive, base_path in ACTIVE_SETUP_PATHS:
            try:
                base_key = winreg.OpenKey(hive, base_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(base_key, i)
                        sub_path = f"{base_path}\\{sub_name}"
                        try:
                            sub_key = winreg.OpenKey(hive, sub_path, 0, winreg.KEY_READ)
                            values = {}
                            j = 0
                            while True:
                                try:
                                    value_name, value_data, _ = winreg.EnumValue(sub_key, j)
                                    values[value_name] = self._format_reg_data(value_data)
                                    j += 1
                                except WindowsError:
                                    break
                            winreg.CloseKey(sub_key)
                            components.append({
                                'hive': self._get_hive_name(hive),
                                'path': base_path,
                                'name': sub_name,
                                'full_path': f"{self._get_hive_name(hive)}\\{base_path}\\{sub_name}",
                                'values': values
                            })
                        except Exception as sub_error:
                            print(f"[持久化检测] 读取Active Setup组件失败: {sub_path}: {sub_error}")
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(base_key)
            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"[持久化检测] 读取Active Setup失败: {base_path}: {e}")

        return components

    def _compare_active_setup_components(self):
        """对比Active Setup组件"""
        initial = {item['full_path']: item for item in self.initial_snapshot.get('active_setup', [])}
        final = {item['full_path']: item for item in self.final_snapshot.get('active_setup', [])}

        for full_path, item in final.items():
            if full_path not in initial:
                self.changes.append({
                    'type': 'Active Setup',
                    'action': 'Created',
                    'location': full_path,
                    'value': item['values'],
                    'severity': 'warning',
                    'description': f"新增Active Setup组件: {item['name']}"
                })
            elif initial[full_path]['values'] != item['values']:
                self.changes.append({
                    'type': 'Active Setup',
                    'action': 'Modified',
                    'location': full_path,
                    'old_value': initial[full_path]['values'],
                    'new_value': item['values'],
                    'severity': 'warning',
                    'description': f"Active Setup组件被修改: {item['name']}"
                })

    # ==================== AppInit_DLLs 检测 ====================

    def _get_appinit_settings(self):
        """获取AppInit_DLLs相关配置"""
        settings = []

        for hive, path in APPINIT_PATHS:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                values = {}
                for value_name in ['AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs']:
                    try:
                        value_data, _ = winreg.QueryValueEx(key, value_name)
                        values[value_name] = self._format_reg_data(value_data)
                    except FileNotFoundError:
                        values[value_name] = None
                winreg.CloseKey(key)
                settings.append({
                    'hive': self._get_hive_name(hive),
                    'path': path,
                    'full_path': f"{self._get_hive_name(hive)}\\{path}",
                    'values': values
                })
            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"[持久化检测] 读取AppInit设置失败: {path}: {e}")

        return settings

    def _compare_appinit_settings(self):
        """对比AppInit设置"""
        initial = {item['full_path']: item for item in self.initial_snapshot.get('appinit_settings', [])}
        final = {item['full_path']: item for item in self.final_snapshot.get('appinit_settings', [])}

        for full_path, item in final.items():
            if full_path not in initial:
                self.changes.append({
                    'type': 'AppInit DLLs',
                    'action': 'Created',
                    'location': full_path,
                    'value': item['values'],
                    'severity': 'critical',
                    'description': f"检测到AppInit_DLLs配置: {full_path}"
                })
            elif initial[full_path]['values'] != item['values']:
                self.changes.append({
                    'type': 'AppInit DLLs',
                    'action': 'Modified',
                    'location': full_path,
                    'old_value': initial[full_path]['values'],
                    'new_value': item['values'],
                    'severity': 'critical',
                    'description': f"AppInit_DLLs配置被修改: {full_path}"
                })

        for full_path, item in initial.items():
            if full_path not in final:
                self.changes.append({
                    'type': 'AppInit DLLs',
                    'action': 'Deleted',
                    'location': full_path,
                    'value': item['values'],
                    'severity': 'warning',
                    'description': f"AppInit_DLLs配置被删除: {full_path}"
                })

        for full_path, item in initial.items():
            if full_path not in final:
                self.changes.append({
                    'type': 'Active Setup',
                    'action': 'Deleted',
                    'location': full_path,
                    'value': item['values'],
                    'severity': 'info',
                    'description': f"Active Setup组件被删除: {item['name']}"
                })

        for full_path, item in initial.items():
            if full_path not in final:
                self.changes.append({
                    'type': 'Startup Approved',
                    'action': 'Deleted',
                    'location': full_path,
                    'value': item['data'],
                    'severity': 'info',
                    'description': f"StartupApproved记录被删除: {item['name']}"
                })

    # ==================== WMI 事件订阅检测 ====================

    def _get_wmi_subscriptions(self):
        """获取WMI事件订阅（高级持久化技术）"""
        subscriptions = []

        try:
            # 查询 EventFilter
            result = subprocess.run(
                ['wmic', '/namespace:\\\\root\\subscription', 'path', '__EventFilter', 'get', 'Name,Query', '/format:csv'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=20
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # 跳过标题行
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 3:
                            subscriptions.append({
                                'type': 'EventFilter',
                                'name': parts[1].strip(),
                                'query': parts[2].strip() if len(parts) > 2 else ''
                            })
        except subprocess.TimeoutExpired:
            print("[持久化检测] 获取WMI订阅超时")
        except Exception as e:
            print(f"[持久化检测] 获取WMI订阅失败: {e}")

        return subscriptions

    def _get_wmi_consumers(self):
        """获取常见WMI事件消费者"""
        consumers = []
        consumer_types = [
            ('CommandLineEventConsumer', ['Name', 'CommandLineTemplate']),
            ('ActiveScriptEventConsumer', ['Name', 'ScriptFileName', 'ScriptText', 'ScriptingEngine']),
            ('LogFileEventConsumer', ['Name', 'FileName', 'Text']),
            ('NTEventLogEventConsumer', ['Name', 'SourceName']),
        ]

        for consumer_type, fields in consumer_types:
            try:
                query_fields = ','.join(fields)
                result = subprocess.run(
                    ['wmic', '/namespace:\\\\root\\subscription', 'path', consumer_type, 'get', query_fields, '/format:csv'],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='ignore',
                    timeout=20
                )

                if result.returncode != 0:
                    continue

                lines = [line for line in result.stdout.strip().split('\n') if line.strip()]
                if len(lines) <= 1:
                    continue

                for line in lines[1:]:
                    parts = self._parse_csv_line(line)
                    if len(parts) < 2:
                        continue

                    data = {}
                    for idx, field in enumerate(fields, start=1):
                        if idx < len(parts):
                            data[field] = parts[idx].strip('"')
                    entry_name = data.get('Name', f'{consumer_type}_unknown')

                    consumers.append({
                        'type': consumer_type,
                        'name': entry_name,
                        'data': data
                    })
            except subprocess.TimeoutExpired:
                print(f"[持久化检测] 获取WMI消费者超时: {consumer_type}")
            except Exception as e:
                print(f"[持久化检测] 获取WMI消费者失败: {consumer_type}: {e}")

        return consumers

    def _get_wmi_bindings(self):
        """获取Filter与Consumer的绑定关系"""
        bindings = []

        try:
            result = subprocess.run(
                ['wmic', '/namespace:\\\\root\\subscription', 'path', '__FilterToConsumerBinding', 'get', 'Filter,Consumer', '/format:csv'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=20
            )

            if result.returncode != 0:
                return bindings

            lines = [line for line in result.stdout.strip().split('\n') if line.strip()]
            if len(lines) <= 1:
                return bindings

            for line in lines[1:]:
                parts = self._parse_csv_line(line)
                if len(parts) < 3:
                    continue
                filter_name = parts[1].strip('"')
                consumer_name = parts[2].strip('"')
                bindings.append({
                    'filter': filter_name,
                    'consumer': consumer_name,
                    'binding': f"{filter_name}->{consumer_name}"
                })
        except subprocess.TimeoutExpired:
            print("[持久化检测] 获取WMI绑定超时")
        except Exception as e:
            print(f"[持久化检测] 获取WMI绑定失败: {e}")

        return bindings

    def _compare_wmi_subscriptions(self):
        """对比WMI订阅的变化"""
        initial = {sub['name']: sub for sub in self.initial_snapshot['wmi_subscriptions']}
        final = {sub['name']: sub for sub in self.final_snapshot['wmi_subscriptions']}

        # 新增/修改
        for name, sub in final.items():
            if name not in initial:
                self.changes.append({
                    'type': 'WMI Event Subscription',
                    'action': 'Created',
                    'location': name,
                    'value': sub['query'],
                    'severity': 'critical',
                    'description': f"新增WMI事件订阅: {name} (高级持久化技术！)"
                })
            elif initial[name].get('query') != sub.get('query'):
                self.changes.append({
                    'type': 'WMI Event Subscription',
                    'action': 'Modified',
                    'location': name,
                    'old_value': initial[name].get('query', ''),
                    'new_value': sub.get('query', ''),
                    'severity': 'warning',
                    'description': f"WMI订阅查询语句被修改: {name}"
                })

        # 删除
        for name, sub in initial.items():
            if name not in final:
                self.changes.append({
                    'type': 'WMI Event Subscription',
                    'action': 'Deleted',
                    'location': name,
                    'value': sub.get('query', ''),
                    'severity': 'warning',
                    'description': f"WMI事件订阅被删除: {name}"
                })

    def _compare_wmi_consumers(self):
        """对比WMI消费者的变化"""
        initial = {f"{item['type']}::{item['name']}": item for item in self.initial_snapshot.get('wmi_consumers', [])}
        final = {f"{item['type']}::{item['name']}": item for item in self.final_snapshot.get('wmi_consumers', [])}

        for key, item in final.items():
            if key not in initial:
                self.changes.append({
                    'type': 'WMI Event Consumer',
                    'action': 'Created',
                    'location': key,
                    'value': item['data'],
                    'severity': 'critical',
                    'description': f"新增WMI消费者: {item['type']}::{item['name']}"
                })
            elif initial[key]['data'] != item['data']:
                self.changes.append({
                    'type': 'WMI Event Consumer',
                    'action': 'Modified',
                    'location': key,
                    'old_value': initial[key]['data'],
                    'new_value': item['data'],
                    'severity': 'warning',
                    'description': f"WMI消费者被修改: {item['type']}::{item['name']}"
                })

        for key, item in initial.items():
            if key not in final:
                self.changes.append({
                    'type': 'WMI Event Consumer',
                    'action': 'Deleted',
                    'location': key,
                    'value': item['data'],
                    'severity': 'warning',
                    'description': f"WMI消费者被删除: {item['type']}::{item['name']}"
                })

    def _compare_wmi_bindings(self):
        """对比WMI Filter与Consumer的绑定"""
        initial = {item['binding']: item for item in self.initial_snapshot.get('wmi_bindings', [])}
        final = {item['binding']: item for item in self.final_snapshot.get('wmi_bindings', [])}

        for binding, item in final.items():
            if binding not in initial:
                self.changes.append({
                    'type': 'WMI Binding',
                    'action': 'Created',
                    'location': binding,
                    'value': item,
                    'severity': 'critical',
                    'description': f"新增WMI绑定: {binding}"
                })

        for binding, item in initial.items():
            if binding not in final:
                self.changes.append({
                    'type': 'WMI Binding',
                    'action': 'Deleted',
                    'location': binding,
                    'value': item,
                    'severity': 'warning',
                    'description': f"WMI绑定被删除: {binding}"
                })

    # ==================== Winlogon 键检测 ====================

    def _get_winlogon_keys(self):
        """获取Winlogon相关的注册表键"""
        winlogon_items = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
                0,
                winreg.KEY_READ
            )

            # 读取所有值
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    # 只关注可能被劫持的项
                    if name.lower() in ['shell', 'userinit', 'taskman', 'system']:
                        winlogon_items.append({
                            'name': name,
                            'value': value
                        })
                    i += 1
                except WindowsError:
                    break

            winreg.CloseKey(key)
        except Exception as e:
            print(f"[持久化检测] 读取Winlogon键失败: {e}")

        return winlogon_items

    def _compare_winlogon_keys(self):
        """对比Winlogon键的变化"""
        initial = {item['name']: item for item in self.initial_snapshot['winlogon_keys']}
        final = {item['name']: item for item in self.final_snapshot['winlogon_keys']}

        base_path = r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'

        # 新增/修改
        for name, item in final.items():
            location = f'{base_path}\\{name}'
            if name not in initial:
                self.changes.append({
                    'type': 'Winlogon Hijack',
                    'action': 'Created',
                    'location': location,
                    'value': item['value'],
                    'severity': 'critical',
                    'description': f"Winlogon新增关键项: {name}"
                })
            elif initial[name]['value'] != item['value']:
                self.changes.append({
                    'type': 'Winlogon Hijack',
                    'action': 'Modified',
                    'location': location,
                    'old_value': initial[name]['value'],
                    'new_value': item['value'],
                    'severity': 'critical',
                    'description': f"Winlogon键被修改: {name} (严重！)"
                })

        # 删除
        for name, item in initial.items():
            if name not in final:
                self.changes.append({
                    'type': 'Winlogon Hijack',
                    'action': 'Deleted',
                    'location': f'{base_path}\\{name}',
                    'value': item['value'],
                    'severity': 'warning',
                    'description': f"Winlogon关键项被删除: {name}"
                })

    # ==================== 映像劫持检测 (IFEO) ====================

    def _get_image_file_hijacks(self):
        """获取映像文件执行选项（IFEO）劫持"""
        hijacks = []

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                0,
                winreg.KEY_READ
            )

            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)

                    try:
                        debugger, _ = winreg.QueryValueEx(subkey, 'Debugger')
                        hijacks.append({
                            'target': subkey_name,
                            'debugger': debugger
                        })
                    except FileNotFoundError:
                        pass

                    winreg.CloseKey(subkey)
                    i += 1
                except WindowsError:
                    break

            winreg.CloseKey(key)
        except Exception as e:
            print(f"[持久化检测] 读取IFEO失败: {e}")

        return hijacks

    def _compare_image_hijacks(self):
        """对比IFEO劫持的变化"""
        initial = {item['target']: item for item in self.initial_snapshot['image_hijacks']}
        final = {item['target']: item for item in self.final_snapshot['image_hijacks']}

        # 新增/修改
        for target, item in final.items():
            if target not in initial:
                self.changes.append({
                    'type': 'IFEO Hijack',
                    'action': 'Created',
                    'location': target,
                    'value': item['debugger'],
                    'severity': 'critical',
                    'description': f"新增映像劫持: {target} -> {item['debugger']}"
                })
            elif initial[target]['debugger'] != item['debugger']:
                self.changes.append({
                    'type': 'IFEO Hijack',
                    'action': 'Modified',
                    'location': target,
                    'old_value': initial[target]['debugger'],
                    'new_value': item['debugger'],
                    'severity': 'critical',
                    'description': f"映像劫持配置被修改: {target}"
                })

        # 删除
        for target, item in initial.items():
            if target not in final:
                self.changes.append({
                    'type': 'IFEO Hijack',
                    'action': 'Deleted',
                    'location': target,
                    'value': item['debugger'],
                    'severity': 'warning',
                    'description': f"映像劫持被删除: {target}"
                })

    # ==================== 浏览器扩展检测 ====================

    def _get_browser_extensions(self):
        """获取浏览器扩展（Chrome）"""
        extensions = []

        # Chrome扩展路径
        chrome_ext_path = os.path.expandvars(
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions'
        )

        if os.path.exists(chrome_ext_path):
            try:
                for ext_id in os.listdir(chrome_ext_path):
                    ext_path = os.path.join(chrome_ext_path, ext_id)
                    if os.path.isdir(ext_path):
                        extensions.append({
                            'browser': 'Chrome',
                            'id': ext_id,
                            'path': ext_path
                        })
            except Exception as e:
                print(f"[持久化检测] 读取Chrome扩展失败: {e}")

        return extensions

    def _compare_browser_extensions(self):
        """对比浏览器扩展的变化"""
        initial = {ext['id']: ext for ext in self.initial_snapshot['browser_extensions']}
        final = {ext['id']: ext for ext in self.final_snapshot['browser_extensions']}

        # 新增/删除
        for ext_id, ext in final.items():
            if ext_id not in initial:
                self.changes.append({
                    'type': 'Browser Extension',
                    'action': 'Created',
                    'location': ext['browser'],
                    'value': ext_id,
                    'severity': 'warning',
                    'description': f"新增{ext['browser']}扩展: {ext_id}"
                })

        for ext_id, ext in initial.items():
            if ext_id not in final:
                self.changes.append({
                    'type': 'Browser Extension',
                    'action': 'Deleted',
                    'location': ext['browser'],
                    'value': ext_id,
                    'severity': 'info',
                    'description': f"{ext['browser']}扩展被删除: {ext_id}"
                })

    # ==================== 工具方法 ====================

    def _get_hive_name(self, hive):
        """获取注册表根键名称"""
        hive_names = {
            winreg.HKEY_LOCAL_MACHINE: 'HKLM',
            winreg.HKEY_CURRENT_USER: 'HKCU',
            winreg.HKEY_CLASSES_ROOT: 'HKCR',
            winreg.HKEY_USERS: 'HKU',
        }
        return hive_names.get(hive, 'UNKNOWN')

    def _format_reg_data(self, value):
        """统一格式化注册表数据，便于比较与展示"""
        if isinstance(value, bytes):
            return value.hex()
        return str(value)

    def export_changes(self, filepath):
        """导出检测到的变化到JSON文件"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump({
                    'initial_snapshot_time': self.initial_snapshot['timestamp'],
                    'final_snapshot_time': self.final_snapshot['timestamp'],
                    'total_changes': len(self.changes),
                    'changes': self.changes
                }, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"[持久化检测] 导出失败: {e}")
            return False

    def get_summary(self):
        """获取检测摘要"""
        if not self.changes:
            return "未检测到持久化机制变化"

        summary = {
            'total': len(self.changes),
            'critical': len([c for c in self.changes if c['severity'] == 'critical']),
            'warning': len([c for c in self.changes if c['severity'] == 'warning']),
            'by_type': {}
        }

        for change in self.changes:
            change_type = change['type']
            summary['by_type'][change_type] = summary['by_type'].get(change_type, 0) + 1

        return summary


# ==================== 测试代码 ====================

if __name__ == '__main__':
    """测试持久化检测器"""

    print("=" * 70)
    print("持久化检测器 - 测试模式")
    print("=" * 70)

    detector = PersistenceDetector()

    # 获取快照
    print("\n[1] 获取系统快照...")
    snapshot = detector.take_snapshot()

    print(f"\n快照统计:")
    print(f"  - 注册表Run键: {len(snapshot['registry_run_keys'])} 个")
    print(f"  - 计划任务: {len(snapshot['scheduled_tasks'])} 个")
    print(f"  - Windows服务: {len(snapshot['services'])} 个")
    print(f"  - 启动文件夹项: {len(snapshot['startup_folders'])} 个")
    print(f"  - WMI订阅: {len(snapshot['wmi_subscriptions'])} 个")
    print(f"  - Winlogon键: {len(snapshot['winlogon_keys'])} 个")
    print(f"  - IFEO劫持: {len(snapshot['image_hijacks'])} 个")
    print(f"  - 浏览器扩展: {len(snapshot['browser_extensions'])} 个")

    # 显示部分内容
    print("\n[2] 注册表Run键示例 (前5个):")
    for item in snapshot['registry_run_keys'][:5]:
        print(f"  {item['full_path']}")
        print(f"    -> {item['value']}")

    print("\n[3] 计划任务示例 (前5个):")
    for task in snapshot['scheduled_tasks'][:5]:
        print(f"  {task['name']}")
        print(f"    -> {task['command']}")

    print("\n" + "=" * 70)
    print("测试完成！")
    print("=" * 70)
