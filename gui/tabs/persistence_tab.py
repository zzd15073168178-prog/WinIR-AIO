#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""持久化检测选项卡 - 检测恶意软件持久化机制"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import os
from datetime import datetime

from .base_tab import BaseTab


class PersistenceTab(BaseTab):
    """持久化检测选项卡

    功能：
    - 获取系统持久化项快照
    - 对比初始/最终快照检测变化
    - 检测 13 种持久化机制
    - 导出检测报告
    """

    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.current_snapshot = None
        self.display_mode = 'snapshot'  # 'snapshot' or 'changes'
        super().__init__(parent, manager, "持久化检测")

    def setup_ui(self):
        """设置UI"""
        # ============== 顶部工具栏 ==============
        toolbar = ttk.Frame(self.frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        # 快照按钮组
        ttk.Label(toolbar, text="快照:").pack(side=tk.LEFT, padx=(0, 3))
        ttk.Button(toolbar, text="获取快照",
                   command=self.take_snapshot).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="初始快照",
                   command=self.take_initial_snapshot).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="最终快照",
                   command=self.take_final_snapshot).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        # 检测按钮
        ttk.Button(toolbar, text="对比检测",
                   command=self.detect_changes).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        # 导出和清空
        ttk.Button(toolbar, text="导出报告",
                   command=self.export_report).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="清空",
                   command=self.clear_results).pack(side=tk.LEFT, padx=2)

        # ============== 快照状态栏 ==============
        status_frame = ttk.Frame(self.frame)
        status_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(status_frame, text="快照状态:").pack(side=tk.LEFT, padx=5)

        self.initial_status = ttk.Label(status_frame, text="初始: 无", foreground='gray')
        self.initial_status.pack(side=tk.LEFT, padx=10)

        self.final_status = ttk.Label(status_frame, text="最终: 无", foreground='gray')
        self.final_status.pack(side=tk.LEFT, padx=10)

        self.change_status = ttk.Label(status_frame, text="")
        self.change_status.pack(side=tk.LEFT, padx=10)

        # ============== 过滤选项 ==============
        filter_frame = ttk.Frame(self.frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(filter_frame, text="显示:").pack(side=tk.LEFT, padx=5)

        self.display_var = tk.StringVar(value='all')
        ttk.Radiobutton(filter_frame, text="全部", variable=self.display_var,
                       value='all', command=self.refresh_display).pack(side=tk.LEFT, padx=3)
        ttk.Radiobutton(filter_frame, text="严重", variable=self.display_var,
                       value='critical', command=self.refresh_display).pack(side=tk.LEFT, padx=3)
        ttk.Radiobutton(filter_frame, text="警告", variable=self.display_var,
                       value='warning', command=self.refresh_display).pack(side=tk.LEFT, padx=3)
        ttk.Radiobutton(filter_frame, text="信息", variable=self.display_var,
                       value='info', command=self.refresh_display).pack(side=tk.LEFT, padx=3)

        ttk.Separator(filter_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        # 类型过滤
        ttk.Label(filter_frame, text="类型:").pack(side=tk.LEFT, padx=5)
        self.type_var = tk.StringVar(value='全部')
        self.type_combo = ttk.Combobox(filter_frame, textvariable=self.type_var,
                                       state='readonly', width=20)
        self.type_combo['values'] = ['全部']
        self.type_combo.pack(side=tk.LEFT, padx=5)
        self.type_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_display())

        # 搜索框
        ttk.Label(filter_frame, text="搜索:").pack(side=tk.LEFT, padx=(15, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=25)
        search_entry.pack(side=tk.LEFT, padx=5)
        self.search_var.trace('w', lambda *a: self.refresh_display())

        # ============== 主内容区域 ==============
        main_frame = ttk.Frame(self.frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 使用 PanedWindow 分割统计和列表
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # 左侧：统计面板
        stats_frame = ttk.LabelFrame(paned, text="统计", width=200)
        paned.add(stats_frame, weight=1)

        self._create_stats_panel(stats_frame)

        # 右侧：结果列表
        list_frame = ttk.Frame(paned)
        paned.add(list_frame, weight=4)

        self._create_results_tree(list_frame)

        # ============== 底部状态栏 ==============
        self.status_label = ttk.Label(self.frame, text="状态: 等待操作...")
        self.status_label.pack(pady=5)

    def _create_stats_panel(self, parent):
        """创建统计面板"""
        # 快照统计
        self.stats_text = tk.Text(parent, wrap=tk.WORD, width=28, height=25,
                                  font=("Consolas", 9))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.stats_text.config(state=tk.DISABLED)

        # 初始化统计显示
        self._update_stats_display()

    def _create_results_tree(self, parent):
        """创建结果列表"""
        # 创建 Treeview
        columns = ('type', 'action', 'location', 'value', 'severity', 'description')
        self.tree = ttk.Treeview(parent, columns=columns, show='headings', height=20)

        self.tree.heading('type', text='类型')
        self.tree.heading('action', text='操作')
        self.tree.heading('location', text='位置')
        self.tree.heading('value', text='值')
        self.tree.heading('severity', text='严重程度')
        self.tree.heading('description', text='描述')

        self.tree.column('type', width=130)
        self.tree.column('action', width=70)
        self.tree.column('location', width=250)
        self.tree.column('value', width=200)
        self.tree.column('severity', width=80)
        self.tree.column('description', width=300)

        # 颜色标签
        self.tree.tag_configure('critical', background='#ffcccc', foreground='#8B0000')
        self.tree.tag_configure('warning', background='#fff3cd', foreground='#856404')
        self.tree.tag_configure('info', background='#e2e3e5', foreground='#383d41')
        self.tree.tag_configure('normal', background='white', foreground='black')

        # 滚动条
        scrollbar_y = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        # 布局
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定事件
        self.tree.bind('<Double-1>', lambda e: self._show_detail())
        self._setup_context_menu()

    def _setup_context_menu(self):
        """设置右键菜单"""
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="查看详情", command=self._show_detail)
        self.context_menu.add_command(label="复制位置", command=self._copy_location)
        self.context_menu.add_command(label="复制值", command=self._copy_value)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="复制全部", command=self._copy_all)

        self.tree.bind('<Button-3>', self._show_context_menu)

    def _show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    # ==================== 核心功能 ====================

    def take_snapshot(self):
        """获取当前快照"""
        self.status_label.configure(text="状态: 正在获取快照...")
        self.log("正在获取系统持久化项快照...", self.output_widget)

        def do_snapshot():
            try:
                snapshot = self.manager.take_snapshot()
                self.current_snapshot = snapshot
                self.display_mode = 'snapshot'

                # 更新UI
                self.safe_after(self._on_snapshot_complete, snapshot)
            except Exception as e:
                self.safe_after(lambda: self.log(f"获取快照失败: {e}", self.output_widget))
                self.safe_after(lambda: self.status_label.configure(text=f"状态: 获取快照失败"))

        threading.Thread(target=do_snapshot, daemon=True).start()

    def _on_snapshot_complete(self, snapshot):
        """快照完成回调"""
        self.log(f"快照获取完成 - {snapshot['timestamp']}", self.output_widget)
        self._update_stats_display(snapshot)
        self._display_snapshot(snapshot)
        self.status_label.configure(text=f"状态: 快照完成 - {snapshot['timestamp']}")

    def take_initial_snapshot(self):
        """获取初始快照（样本运行前）"""
        self.status_label.configure(text="状态: 正在获取初始快照...")
        self.log("正在获取初始快照（样本运行前）...", self.output_widget)

        def do_snapshot():
            try:
                snapshot = self.manager.take_initial_snapshot()
                self.safe_after(self._on_initial_complete, snapshot)
            except Exception as e:
                self.safe_after(lambda: self.log(f"获取初始快照失败: {e}", self.output_widget))

        threading.Thread(target=do_snapshot, daemon=True).start()

    def _on_initial_complete(self, snapshot):
        """初始快照完成"""
        self.initial_status.configure(text=f"初始: {snapshot['timestamp']}", foreground='green')
        self.log(f"初始快照已保存 - {snapshot['timestamp']}", self.output_widget)
        self.status_label.configure(text="状态: 初始快照完成，请运行样本后获取最终快照")
        self._update_stats_display(snapshot)

    def take_final_snapshot(self):
        """获取最终快照（样本运行后）"""
        if not self.manager.initial_snapshot:
            messagebox.showwarning("提示", "请先获取初始快照")
            return

        self.status_label.configure(text="状态: 正在获取最终快照...")
        self.log("正在获取最终快照（样本运行后）...", self.output_widget)

        def do_snapshot():
            try:
                snapshot = self.manager.take_final_snapshot()
                self.safe_after(self._on_final_complete, snapshot)
            except Exception as e:
                self.safe_after(lambda: self.log(f"获取最终快照失败: {e}", self.output_widget))

        threading.Thread(target=do_snapshot, daemon=True).start()

    def _on_final_complete(self, snapshot):
        """最终快照完成"""
        self.final_status.configure(text=f"最终: {snapshot['timestamp']}", foreground='blue')
        self.log(f"最终快照已保存 - {snapshot['timestamp']}", self.output_widget)
        self.status_label.configure(text="状态: 最终快照完成，可以进行对比检测")

    def detect_changes(self):
        """检测变化"""
        if not self.manager.initial_snapshot or not self.manager.final_snapshot:
            messagebox.showwarning("提示", "请先获取初始快照和最终快照")
            return

        self.status_label.configure(text="状态: 正在分析变化...")
        self.log("正在对比快照，检测持久化变化...", self.output_widget)

        def do_detect():
            try:
                changes = self.manager.detect_changes()
                self.display_mode = 'changes'
                self.safe_after(self._on_detect_complete, changes)
            except Exception as e:
                self.safe_after(lambda: self.log(f"检测失败: {e}", self.output_widget))

        threading.Thread(target=do_detect, daemon=True).start()

    def _on_detect_complete(self, changes):
        """检测完成回调"""
        summary = self.manager.get_summary()

        self.log(f"检测完成!", self.output_widget)

        if isinstance(summary, dict):
            self.log(f"  总变化: {summary['total']} 项", self.output_widget)
            self.log(f"  严重: {summary['critical']} 项", self.output_widget)
            self.log(f"  警告: {summary['warning']} 项", self.output_widget)

            # 更新变化状态
            self.change_status.configure(
                text=f"变化: {summary['total']} (严重:{summary['critical']}, 警告:{summary['warning']})",
                foreground='red' if summary['critical'] > 0 else ('orange' if summary['warning'] > 0 else 'green')
            )

            # 更新类型过滤选项
            types = ['全部'] + list(summary.get('by_type', {}).keys())
            self.type_combo['values'] = types
        else:
            self.log(f"  {summary}", self.output_widget)
            self.change_status.configure(text="变化: 0", foreground='green')

        # 显示变化
        self._display_changes(changes)

        # 弹出警告
        if isinstance(summary, dict) and summary['critical'] > 0:
            messagebox.showwarning("安全警告",
                f"检测到 {summary['critical']} 个严重持久化变化!\n\n"
                "建议立即检查详情。")

        self.status_label.configure(text=f"状态: 检测完成 - {len(changes)} 个变化")

    # ==================== 显示功能 ====================

    def _display_snapshot(self, snapshot):
        """显示快照内容"""
        # 清空列表
        for item in self.tree.get_children():
            self.tree.delete(item)

        # 显示各类持久化项
        categories = [
            ('registry_run_keys', 'Registry Run Key', 'info'),
            ('scheduled_tasks', 'Scheduled Task', 'info'),
            ('services', 'Windows Service', 'info'),
            ('startup_folders', 'Startup Folder', 'info'),
            ('startup_approved', 'Startup Approved', 'info'),
            ('wmi_subscriptions', 'WMI Subscription', 'warning'),
            ('wmi_consumers', 'WMI Consumer', 'warning'),
            ('wmi_bindings', 'WMI Binding', 'warning'),
            ('winlogon_keys', 'Winlogon Key', 'info'),
            ('image_hijacks', 'IFEO Hijack', 'critical'),
            ('browser_extensions', 'Browser Extension', 'info'),
            ('active_setup', 'Active Setup', 'info'),
            ('appinit_settings', 'AppInit DLLs', 'warning'),
        ]

        count = 0
        search = self.search_var.get().strip().lower()
        filter_type = self.type_var.get()

        for key, type_name, default_severity in categories:
            items = snapshot.get(key, [])

            # 类型过滤
            if filter_type != '全部' and filter_type != type_name:
                continue

            for item in items:
                # 提取显示信息
                location = self._get_item_location(item, key)
                value = self._get_item_value(item, key)
                description = self._get_item_description(item, key)

                # 搜索过滤
                if search:
                    searchable = f"{type_name} {location} {value} {description}".lower()
                    if search not in searchable:
                        continue

                # 插入数据
                values = (type_name, 'Exists', location, value, default_severity, description)
                tag = default_severity if default_severity in ['critical', 'warning'] else 'normal'
                self.tree.insert('', tk.END, values=values, tags=(tag,))
                count += 1

        self.status_label.configure(text=f"状态: 显示 {count} 个持久化项")

    def _display_changes(self, changes):
        """显示变化"""
        # 清空列表
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not changes:
            self.status_label.configure(text="状态: 未检测到变化")
            return

        search = self.search_var.get().strip().lower()
        severity_filter = self.display_var.get()
        type_filter = self.type_var.get()

        count = 0
        for change in changes:
            # 严重程度过滤
            if severity_filter != 'all' and change['severity'] != severity_filter:
                continue

            # 类型过滤
            if type_filter != '全部' and change['type'] != type_filter:
                continue

            # 搜索过滤
            if search:
                searchable = f"{change['type']} {change['location']} {change.get('value', '')} {change['description']}".lower()
                if search not in searchable:
                    continue

            # 获取值（可能是 new_value 或 value）
            value = change.get('new_value', change.get('value', ''))
            if isinstance(value, dict):
                value = str(value)[:100]

            values = (
                change['type'],
                change['action'],
                change['location'],
                value,
                change['severity'],
                change['description']
            )

            self.tree.insert('', tk.END, values=values, tags=(change['severity'],))
            count += 1

        self.status_label.configure(text=f"状态: 显示 {count} 个变化")

    def refresh_display(self):
        """刷新显示"""
        if self.display_mode == 'changes' and self.manager.changes:
            self._display_changes(self.manager.changes)
        elif self.current_snapshot:
            self._display_snapshot(self.current_snapshot)

    def _update_stats_display(self, snapshot=None):
        """更新统计面板"""
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)

        if not snapshot:
            self.stats_text.insert(tk.END, "暂无快照数据\n\n")
            self.stats_text.insert(tk.END, "点击'获取快照'开始\n")
            self.stats_text.insert(tk.END, "或使用'初始/最终快照'\n")
            self.stats_text.insert(tk.END, "进行对比检测\n")
        else:
            self.stats_text.insert(tk.END, f"快照时间:\n{snapshot['timestamp']}\n\n")
            self.stats_text.insert(tk.END, "=" * 25 + "\n")
            self.stats_text.insert(tk.END, "各类持久化项统计\n")
            self.stats_text.insert(tk.END, "=" * 25 + "\n\n")

            stats = [
                ('注册表Run键', len(snapshot.get('registry_run_keys', []))),
                ('计划任务', len(snapshot.get('scheduled_tasks', []))),
                ('Windows服务', len(snapshot.get('services', []))),
                ('启动文件夹', len(snapshot.get('startup_folders', []))),
                ('Startup审批', len(snapshot.get('startup_approved', []))),
                ('WMI订阅', len(snapshot.get('wmi_subscriptions', []))),
                ('WMI消费者', len(snapshot.get('wmi_consumers', []))),
                ('WMI绑定', len(snapshot.get('wmi_bindings', []))),
                ('Winlogon键', len(snapshot.get('winlogon_keys', []))),
                ('IFEO劫持', len(snapshot.get('image_hijacks', []))),
                ('浏览器扩展', len(snapshot.get('browser_extensions', []))),
                ('Active Setup', len(snapshot.get('active_setup', []))),
                ('AppInit DLLs', len(snapshot.get('appinit_settings', []))),
            ]

            total = 0
            for name, count in stats:
                self.stats_text.insert(tk.END, f"{name}: {count}\n")
                total += count

            self.stats_text.insert(tk.END, "\n" + "-" * 25 + "\n")
            self.stats_text.insert(tk.END, f"总计: {total} 项\n")

        self.stats_text.config(state=tk.DISABLED)

    # ==================== 辅助方法 ====================

    def _get_item_location(self, item, category):
        """获取项目位置"""
        if category == 'registry_run_keys':
            return item.get('full_path', '')
        elif category == 'scheduled_tasks':
            return item.get('name', '')
        elif category == 'services':
            return item.get('name', '')
        elif category == 'startup_folders':
            return item.get('path', '')
        elif category in ['wmi_subscriptions', 'wmi_consumers']:
            return item.get('name', '')
        elif category == 'wmi_bindings':
            return item.get('binding', '')
        elif category == 'winlogon_keys':
            return item.get('name', '')
        elif category == 'image_hijacks':
            return item.get('target', '')
        elif category == 'browser_extensions':
            return f"{item.get('browser', '')} - {item.get('id', '')}"
        elif category in ['active_setup', 'startup_approved', 'appinit_settings']:
            return item.get('full_path', item.get('name', ''))
        return str(item)[:50]

    def _get_item_value(self, item, category):
        """获取项目值"""
        if category == 'registry_run_keys':
            return item.get('value', '')[:100]
        elif category == 'scheduled_tasks':
            return item.get('command', '')[:100]
        elif category == 'services':
            return item.get('binary_path', '')[:100]
        elif category == 'startup_folders':
            return item.get('name', '')
        elif category == 'wmi_subscriptions':
            return item.get('query', '')[:100]
        elif category == 'wmi_consumers':
            return item.get('data', '')[:100]
        elif category == 'winlogon_keys':
            return item.get('value', '')[:100]
        elif category == 'image_hijacks':
            return item.get('debugger', '')[:100]
        elif category == 'browser_extensions':
            return item.get('name', item.get('id', ''))
        return ''

    def _get_item_description(self, item, category):
        """获取项目描述"""
        if category == 'registry_run_keys':
            return f"注册表启动项: {item.get('name', '')}"
        elif category == 'scheduled_tasks':
            return f"计划任务: {item.get('name', '')}"
        elif category == 'services':
            return f"服务: {item.get('display_name', item.get('name', ''))}"
        elif category == 'startup_folders':
            return f"启动文件夹项: {item.get('name', '')}"
        elif category == 'wmi_subscriptions':
            return f"WMI事件订阅"
        elif category == 'wmi_consumers':
            return f"WMI消费者: {item.get('type', '')}"
        elif category == 'winlogon_keys':
            return f"Winlogon: {item.get('name', '')}"
        elif category == 'image_hijacks':
            return f"映像劫持: {item.get('target', '')}"
        elif category == 'browser_extensions':
            return f"{item.get('browser', '')}扩展"
        return ''

    def _get_selected_item(self):
        """获取选中项数据"""
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0])['values']

    def _show_detail(self):
        """显示详情"""
        values = self._get_selected_item()
        if not values:
            return

        detail = {
            '类型': values[0],
            '操作': values[1],
            '位置': values[2],
            '值': values[3],
            '严重程度': values[4],
            '描述': values[5],
        }

        self.show_detail_dialog(f"详情 - {values[0]}", detail)

    def _copy_location(self):
        """复制位置"""
        values = self._get_selected_item()
        if values:
            self.tree.clipboard_clear()
            self.tree.clipboard_append(values[2])
            self.log(f"已复制: {values[2]}", self.output_widget)

    def _copy_value(self):
        """复制值"""
        values = self._get_selected_item()
        if values:
            self.tree.clipboard_clear()
            self.tree.clipboard_append(values[3])
            self.log(f"已复制: {values[3]}", self.output_widget)

    def _copy_all(self):
        """复制全部信息"""
        values = self._get_selected_item()
        if values:
            text = f"类型: {values[0]}\n操作: {values[1]}\n位置: {values[2]}\n值: {values[3]}\n严重程度: {values[4]}\n描述: {values[5]}"
            self.tree.clipboard_clear()
            self.tree.clipboard_append(text)
            self.log("已复制完整信息", self.output_widget)

    def export_report(self):
        """导出报告"""
        if not self.manager.changes and not self.current_snapshot:
            messagebox.showwarning("提示", "没有可导出的数据")
            return

        # 选择保存路径
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_name = f"persistence_report_{timestamp}.json"

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")],
            initialfile=default_name
        )

        if not filepath:
            return

        try:
            if self.manager.changes:
                # 导出变化检测结果
                success = self.manager.export_changes(filepath)
                if success:
                    self.log(f"报告已导出: {filepath}", self.output_widget)
                    messagebox.showinfo("成功", f"报告已导出到:\n{filepath}")
            elif self.current_snapshot:
                # 导出快照
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(self.current_snapshot, f, indent=2, ensure_ascii=False)
                self.log(f"快照已导出: {filepath}", self.output_widget)
                messagebox.showinfo("成功", f"快照已导出到:\n{filepath}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")

    def clear_results(self):
        """清空结果"""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.current_snapshot = None
        self.manager.initial_snapshot = None
        self.manager.final_snapshot = None
        self.manager.changes = []

        self.initial_status.configure(text="初始: 无", foreground='gray')
        self.final_status.configure(text="最终: 无", foreground='gray')
        self.change_status.configure(text="")

        self._update_stats_display()
        self.status_label.configure(text="状态: 已清空")
        self.log("已清空所有结果", self.output_widget)

    def _on_double_click(self, tree):
        """双击事件"""
        self._show_detail()
