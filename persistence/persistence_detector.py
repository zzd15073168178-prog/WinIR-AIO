#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
持久化机制检测模块 - 主类
监控常见的恶意软件持久化手段
"""

import json
from datetime import datetime
from .registry_detector import RegistryDetector
from .scheduled_task_detector import ScheduledTaskDetector
from .service_detector import ServiceDetector
from .wmi_detector import WMIDetector
from .system_detector import SystemDetector
from .browser_detector import BrowserDetector


class PersistenceDetector:
    """持久化机制检测器（重构版）

    通过快照对比的方式，检测样本运行前后的持久化项变化
    """

    def __init__(self):
        self.initial_snapshot = None
        self.final_snapshot = None
        self.changes = []
        
        # 初始化子检测器
        self.registry_detector = RegistryDetector()
        self.scheduled_task_detector = ScheduledTaskDetector()
        self.service_detector = ServiceDetector()
        self.wmi_detector = WMIDetector()
        self.system_detector = SystemDetector()
        self.browser_detector = BrowserDetector()

    # ==================== 主要方法 ====================

    def take_snapshot(self):
        """获取系统当前的持久化项快照"""
        snapshot = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'registry_run_keys': self.registry_detector.get_run_keys(),
            'scheduled_tasks': self.scheduled_task_detector.get_tasks(),
            'services': self.service_detector.get_services(),
            'startup_folders': self.system_detector.get_startup_folders(),
            'startup_approved': self.system_detector.get_startup_approved(),
            'wmi_subscriptions': self.wmi_detector.get_subscriptions(),
            'wmi_consumers': self.wmi_detector.get_consumers(),
            'wmi_bindings': self.wmi_detector.get_bindings(),
            'winlogon_keys': self.registry_detector.get_winlogon_keys(),
            'image_hijacks': self.registry_detector.get_image_hijacks(),
            'browser_extensions': self.browser_detector.get_extensions(),
            'active_setup': self.registry_detector.get_active_setup(),
            'appinit_settings': self.registry_detector.get_appinit_settings(),
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

    # ==================== 对比方法 ====================

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

    def _compare_services(self):
        """对比服务的变化"""
        initial = {svc['name']: svc for svc in self.initial_snapshot['services']}
        final = {svc['name']: svc for svc in self.final_snapshot['services']}

        # 新增的服务
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

    def _compare_startup_approved(self):
        """对比StartupApproved项的变化"""
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

    def _compare_wmi_subscriptions(self):
        """对比WMI订阅的变化"""
        initial = {sub['name']: sub for sub in self.initial_snapshot['wmi_subscriptions']}
        final = {sub['name']: sub for sub in self.final_snapshot['wmi_subscriptions']}

        # 新增的订阅
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

    def _compare_wmi_bindings(self):
        """对比WMI绑定"""
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

    def _compare_winlogon_keys(self):
        """对比Winlogon键的变化"""
        initial = {item['name']: item for item in self.initial_snapshot['winlogon_keys']}
        final = {item['name']: item for item in self.final_snapshot['winlogon_keys']}

        base_path = r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'

        for name, item in final.items():
            location = f'{base_path}\{name}'
            if name not in initial:
                self.changes.append({
                    'type': 'Winlogon Hijack',
                    'action': 'Created',
                    'location': location,
                    'value': item['value'],
                    'severity': 'critical',
                    'description': f"Winlogon新增关键项: {name}"
                })

    def _compare_image_hijacks(self):
        """对比IFEO劫持的变化"""
        initial = {item['target']: item for item in self.initial_snapshot['image_hijacks']}
        final = {item['target']: item for item in self.final_snapshot['image_hijacks']}

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

    def _compare_browser_extensions(self):
        """对比浏览器扩展的变化"""
        initial = {ext['id']: ext for ext in self.initial_snapshot['browser_extensions']}
        final = {ext['id']: ext for ext in self.final_snapshot['browser_extensions']}

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

    # ==================== 工具方法 ====================

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

    print("\n" + "=" * 70)
    print("测试完成！")
    print("=" * 70)