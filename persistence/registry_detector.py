#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
注册表持久化检测模块
"""

import winreg


# 注册表路径常量
REGISTRY_RUN_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'),
]

STARTUP_APPROVED_PATHS = [
    (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'),
]

ACTIVE_SETUP_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Active Setup\Installed Components'),
    (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Active Setup\Installed Components'),
]

APPINIT_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'),
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'),
]


class RegistryDetector:
    """注册表持久化检测器"""
    
    def get_run_keys(self):
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
            except (FileNotFoundError, Exception):
                continue
        
        return run_keys
    
    def get_startup_approved(self):
        """获取StartupApproved中的启动项状态"""
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
            except (FileNotFoundError, Exception):
                continue
        
        return approved
    
    def get_active_setup(self):
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
                        except Exception:
                            pass
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(base_key)
            except (FileNotFoundError, Exception):
                continue
        
        return components
    
    def get_appinit_settings(self):
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
            except (FileNotFoundError, Exception):
                continue
        
        return settings
    
    def get_winlogon_keys(self):
        """获取Winlogon相关的注册表键"""
        winlogon_items = []
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
                0,
                winreg.KEY_READ
            )
            
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if name.lower() in ['shell', 'userinit', 'taskman', 'system']:
                        winlogon_items.append({
                            'name': name,
                            'value': value
                        })
                    i += 1
                except WindowsError:
                    break
            
            winreg.CloseKey(key)
        except Exception:
            pass
        
        return winlogon_items
    
    def get_image_hijacks(self):
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
        except Exception:
            pass
        
        return hijacks
    
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
        """统一格式化注册表数据"""
        if isinstance(value, bytes):
            return value.hex()
        return str(value)