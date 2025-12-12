#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows 事件日志分析选项卡
用于查询和分析 Security、System、Sysmon 等日志
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from typing import Any, Optional, List, Dict
import threading
from datetime import datetime
import csv
import os
from .base_tab import BaseTab
from console_logger import log_action, console_log


class EventLogTab(BaseTab):
    """事件日志分析选项卡"""

    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.events_data = []  # 当前查询的事件
        self.filtered_events = []  # 过滤后的事件

        # UI 控件
        self.event_tree = None
        self.detail_text = None
        self.status_label = None
        self.stats_label = None
        self.search_var = None

        # 事件类型选择
        self.logon_var = None
        self.process_var = None
        self.account_var = None
        self.service_var = None
        self.network_var = None

        # 其他选项
        self.hours_var = None
        self.suspicious_only_var = None

        super().__init__(parent, manager, "事件日志")

    def setup_ui(self):
        """设置UI"""
        # === 顶部工具栏 ===
        toolbar = ttk.Frame(self.frame)
        toolbar.pack(fill=tk.X, pady=5, padx=5)

        # 事件类型选择
        type_frame = ttk.LabelFrame(toolbar, text="事件类型")
        type_frame.pack(side=tk.LEFT, padx=5)

        self.logon_var = tk.BooleanVar(value=True)
        self.process_var = tk.BooleanVar(value=False)
        self.account_var = tk.BooleanVar(value=False)
        self.service_var = tk.BooleanVar(value=False)
        self.network_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(type_frame, text="登录", variable=self.logon_var).pack(side=tk.LEFT, padx=3)
        ttk.Checkbutton(type_frame, text="进程", variable=self.process_var).pack(side=tk.LEFT, padx=3)
        ttk.Checkbutton(type_frame, text="账户", variable=self.account_var).pack(side=tk.LEFT, padx=3)
        ttk.Checkbutton(type_frame, text="服务", variable=self.service_var).pack(side=tk.LEFT, padx=3)
        ttk.Checkbutton(type_frame, text="网络", variable=self.network_var).pack(side=tk.LEFT, padx=3)

        # 时间范围
        time_frame = ttk.Frame(toolbar)
        time_frame.pack(side=tk.LEFT, padx=15)

        ttk.Label(time_frame, text="时间范围:").pack(side=tk.LEFT)
        self.hours_var = tk.StringVar(value="24")
        hours_combo = ttk.Combobox(time_frame, textvariable=self.hours_var, width=6,
                                   values=["1", "6", "12", "24", "48", "72", "168"])
        hours_combo.pack(side=tk.LEFT, padx=3)
        ttk.Label(time_frame, text="小时").pack(side=tk.LEFT)

        # 查询按钮
        ttk.Button(toolbar, text="查询事件", command=self.query_events).pack(side=tk.LEFT, padx=10)

        # 可疑过滤
        self.suspicious_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(toolbar, text="仅显示可疑", variable=self.suspicious_only_var,
                       command=self._apply_filter).pack(side=tk.LEFT, padx=5)

        # 导出按钮
        ttk.Button(toolbar, text="导出CSV", command=self._export_csv).pack(side=tk.RIGHT, padx=5)

        # === 搜索栏 ===
        search_frame = ttk.Frame(self.frame)
        search_frame.pack(fill=tk.X, pady=3, padx=5)

        ttk.Label(search_frame, text="搜索:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *a: self._apply_filter())
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=5)

        # 数据源状态
        self.source_label = ttk.Label(search_frame, text="", foreground='gray')
        self.source_label.pack(side=tk.RIGHT, padx=5)

        # === 主内容区域 ===
        paned = ttk.PanedWindow(self.frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 上半部分 - 事件列表
        list_frame = ttk.Frame(paned)
        paned.add(list_frame, weight=3)

        # 创建事件列表
        columns = ('时间', '事件ID', '类型', '用户', '详情', '可疑')
        self.event_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)

        self.event_tree.heading('时间', text='时间')
        self.event_tree.heading('事件ID', text='事件ID')
        self.event_tree.heading('类型', text='类型')
        self.event_tree.heading('用户', text='用户')
        self.event_tree.heading('详情', text='详情')
        self.event_tree.heading('可疑', text='可疑')

        self.event_tree.column('时间', width=140)
        self.event_tree.column('事件ID', width=70)
        self.event_tree.column('类型', width=100)
        self.event_tree.column('用户', width=120)
        self.event_tree.column('详情', width=350)
        self.event_tree.column('可疑', width=60)

        # 标签样式
        self.event_tree.tag_configure('suspicious', background='#ffcccc', foreground='red')
        self.event_tree.tag_configure('warning', background='#ffffcc', foreground='#996600')
        self.event_tree.tag_configure('normal', background='white', foreground='black')
        self.event_tree.tag_configure('logon_fail', background='#ffeecc', foreground='#cc6600')

        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.event_tree.yview)
        self.event_tree.configure(yscrollcommand=scrollbar.set)

        self.event_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定事件
        self.event_tree.bind('<<TreeviewSelect>>', self._on_select)
        self.event_tree.bind('<Double-1>', lambda e: self._show_full_detail())

        # 右键菜单
        self._setup_context_menu()

        # 下半部分 - 详情面板
        detail_frame = ttk.LabelFrame(paned, text="事件详情")
        paned.add(detail_frame, weight=1)

        self.detail_text = scrolledtext.ScrolledText(detail_frame, height=8,
                                                     font=('Consolas', 9), wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # === 状态栏 ===
        status_frame = ttk.Frame(self.frame)
        status_frame.pack(fill=tk.X, pady=3, padx=5)

        self.status_label = ttk.Label(status_frame, text="就绪 - 选择事件类型后点击查询")
        self.status_label.pack(side=tk.LEFT)

        self.stats_label = ttk.Label(status_frame, text="", foreground='gray')
        self.stats_label.pack(side=tk.RIGHT)

        # 检查数据源
        self.frame.after(100, self._check_data_sources)

    def _setup_context_menu(self):
        """设置右键菜单"""
        menu_items = [
            {'label': '查看完整详情', 'command': self._show_full_detail},
            {'label': '复制事件信息', 'command': self._copy_event},
            {'separator': True, 'label': '---'},
            {'label': '复制用户名', 'command': self._copy_username},
            {'label': '复制IP地址', 'command': self._copy_ip},
            {'separator': True, 'label': '---'},
            {'label': '在进程溯源中查询', 'command': self._trace_process},
        ]
        self.setup_tree_context_menu(self.event_tree, menu_items)

    def _check_data_sources(self):
        """检查数据源可用性"""
        def check():
            logs = self.manager.get_available_logs()
            self.safe_after(lambda: self._update_source_label(logs))

        threading.Thread(target=check, daemon=True).start()

    def _update_source_label(self, logs: Dict[str, bool]):
        """更新数据源标签"""
        sources = []
        if logs.get('security'):
            sources.append('Security')
        if logs.get('sysmon'):
            sources.append('Sysmon')
        sources.append('System')

        if sources:
            self.source_label.config(text=f"可用日志: {', '.join(sources)}", foreground='green')
        else:
            self.source_label.config(text="无可用日志", foreground='red')

    def query_events(self):
        """查询事件"""
        # 检查是否选择了事件类型
        selected_types = []
        if self.logon_var.get():
            selected_types.append('logon')
        if self.process_var.get():
            selected_types.append('process')
        if self.account_var.get():
            selected_types.append('account')
        if self.service_var.get():
            selected_types.append('service')
        if self.network_var.get():
            selected_types.append('network')

        if not selected_types:
            messagebox.showwarning("提示", "请至少选择一种事件类型")
            return

        try:
            hours = int(self.hours_var.get())
        except:
            hours = 24

        self.status_label.config(text=f"正在查询事件（最近 {hours} 小时）...")
        self.log(f"开始查询事件日志: {', '.join(selected_types)}, 时间范围: {hours}小时", self.output_widget)
        log_action("事件日志查询", f"类型: {selected_types}")

        def query():
            all_events = []

            try:
                if 'logon' in selected_types:
                    events = self.manager.query_logon_events(hours=hours)
                    all_events.extend(events)

                if 'process' in selected_types:
                    events = self.manager.query_process_events(hours=hours)
                    all_events.extend(events)

                if 'account' in selected_types:
                    events = self.manager.query_account_events(hours=hours)
                    all_events.extend(events)

                if 'service' in selected_types:
                    events = self.manager.query_service_events(hours=hours)
                    all_events.extend(events)

                if 'network' in selected_types:
                    events = self.manager.query_sysmon_network(hours=hours)
                    all_events.extend(events)

                # 分析可疑事件
                all_events = self.manager.analyze_suspicious(all_events)

                # 按时间排序（最新的在前）
                all_events.sort(key=lambda x: x.get('TimeCreated', ''), reverse=True)

            except Exception as e:
                console_log(f"查询事件失败: {e}", "ERROR")

            self.safe_after(lambda: self._display_events(all_events))

        threading.Thread(target=query, daemon=True).start()

    def _display_events(self, events: List[Dict[str, Any]]):
        """显示事件"""
        self.events_data = events
        self._apply_filter()

        # 更新统计
        summary = self.manager.get_event_summary(events)
        suspicious_count = summary.get('suspicious', 0)

        self.status_label.config(
            text=f"查询完成 | 共 {summary['total']} 条事件 | 可疑: {suspicious_count}"
        )

        if suspicious_count > 0:
            self.log(f"发现 {suspicious_count} 条可疑事件!", self.output_widget)

        # 类型统计
        type_stats = []
        for t, count in summary.get('by_type', {}).items():
            type_stats.append(f"{t}: {count}")
        self.stats_label.config(text=' | '.join(type_stats))

    def _apply_filter(self):
        """应用过滤条件"""
        # 清空列表
        for item in self.event_tree.get_children():
            self.event_tree.delete(item)

        search_text = self.search_var.get().lower() if self.search_var else ''
        suspicious_only = self.suspicious_only_var.get() if self.suspicious_only_var else False

        self.filtered_events = []

        for event in self.events_data:
            # 可疑过滤
            if suspicious_only and not event.get('is_suspicious'):
                continue

            # 搜索过滤
            if search_text:
                searchable = ' '.join(str(v) for v in event.values()).lower()
                if search_text not in searchable:
                    continue

            self.filtered_events.append(event)

            # 构建显示内容
            time_str = event.get('TimeCreated', '')
            event_id = event.get('EventId', '')
            event_name = event.get('EventName', '')
            user = self._get_user(event)
            detail = self._get_detail_summary(event)
            suspicious = '!' if event.get('is_suspicious') else ''

            # 确定标签
            tag = self._get_event_tag(event)

            self.event_tree.insert('', tk.END,
                                  values=(time_str, event_id, event_name, user, detail, suspicious),
                                  tags=(tag,))

    def _get_user(self, event: Dict[str, Any]) -> str:
        """获取用户名"""
        user = event.get('TargetUserName') or event.get('User') or event.get('SubjectUserName') or ''
        domain = event.get('TargetDomainName') or event.get('SubjectDomainName') or ''
        if domain and user:
            return f"{domain}\\{user}"
        return user

    def _get_detail_summary(self, event: Dict[str, Any]) -> str:
        """获取详情摘要"""
        event_type = event.get('EventType', '')

        if event_type == 'logon':
            logon_type = event.get('LogonTypeDesc', event.get('LogonType', ''))
            ip = event.get('IpAddress', '')
            if ip and ip != '-':
                return f"类型{event.get('LogonType', '')}({logon_type}) 从 {ip}"
            return f"类型{event.get('LogonType', '')}({logon_type})"

        elif event_type == 'process':
            image = event.get('Image', '')
            if image:
                return os.path.basename(image)
            return ''

        elif event_type == 'service':
            service = event.get('ServiceName', '')
            return service

        elif event_type == 'account':
            target = event.get('TargetUserName', '')
            return f"目标: {target}"

        elif event_type == 'network':
            dest_ip = event.get('DestinationIp', '')
            dest_port = event.get('DestinationPort', '')
            return f"-> {dest_ip}:{dest_port}"

        return ''

    def _get_event_tag(self, event: Dict[str, Any]) -> str:
        """获取事件标签"""
        if event.get('is_suspicious'):
            return 'suspicious'
        if event.get('EventId') == 4625:
            return 'logon_fail'
        return 'normal'

    def _on_select(self, event):
        """选择事件处理"""
        selection = self.event_tree.selection()
        if not selection:
            return

        # 获取选中项的索引
        item = selection[0]
        index = self.event_tree.index(item)

        if 0 <= index < len(self.filtered_events):
            self._show_detail(self.filtered_events[index])

    def _show_detail(self, event: Dict[str, Any]):
        """显示事件详情"""
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)

        lines = [
            f"事件ID: {event.get('EventId', 'N/A')}",
            f"事件类型: {event.get('EventName', 'N/A')}",
            f"时间: {event.get('TimeCreated', 'N/A')}",
            f"数据源: {event.get('EventSource', 'Security')}",
            "",
        ]

        event_type = event.get('EventType', '')

        if event_type == 'logon':
            lines.extend([
                f"--- 登录信息 ---",
                f"用户: {self._get_user(event)}",
                f"登录类型: {event.get('LogonType', '')} ({event.get('LogonTypeDesc', '')})",
                f"源IP: {event.get('IpAddress', 'N/A')}",
                f"工作站: {event.get('WorkstationName', 'N/A')}",
                f"认证包: {event.get('AuthenticationPackageName', 'N/A')}",
            ])
            if event.get('EventId') == 4625:
                lines.append(f"失败原因: {event.get('FailureReason', event.get('Status', 'N/A'))}")

        elif event_type == 'process':
            lines.extend([
                f"--- 进程信息 ---",
                f"进程: {event.get('Image', 'N/A')}",
                f"PID: {event.get('ProcessId', 'N/A')}",
                f"命令行: {event.get('CommandLine', 'N/A')}",
                f"用户: {event.get('User', 'N/A')}",
                f"",
                f"父进程: {event.get('ParentImage', 'N/A')}",
                f"父进程PID: {event.get('ParentProcessId', 'N/A')}",
                f"父进程命令行: {event.get('ParentCommandLine', 'N/A')}",
            ])
            if event.get('IntegrityLevel'):
                lines.append(f"完整性级别: {event.get('IntegrityLevel')}")
            if event.get('Hashes'):
                lines.append(f"哈希: {event.get('Hashes')}")

        elif event_type == 'service':
            lines.extend([
                f"--- 服务信息 ---",
                f"服务名: {event.get('ServiceName', 'N/A')}",
                f"镜像路径: {event.get('ImagePath', 'N/A')}",
                f"服务类型: {event.get('ServiceType', 'N/A')}",
                f"启动类型: {event.get('StartType', 'N/A')}",
                f"账户: {event.get('AccountName', 'N/A')}",
            ])

        elif event_type == 'account':
            lines.extend([
                f"--- 账户信息 ---",
                f"目标账户: {event.get('TargetUserName', 'N/A')}",
                f"目标域: {event.get('TargetDomainName', 'N/A')}",
                f"操作者: {event.get('SubjectUserName', 'N/A')}",
                f"操作者域: {event.get('SubjectDomainName', 'N/A')}",
            ])
            if event.get('MemberName'):
                lines.append(f"成员: {event.get('MemberName')}")

        elif event_type == 'network':
            lines.extend([
                f"--- 网络连接 ---",
                f"进程: {event.get('Image', 'N/A')}",
                f"协议: {event.get('Protocol', 'N/A')}",
                f"源: {event.get('SourceIp', '')}:{event.get('SourcePort', '')}",
                f"目标: {event.get('DestinationIp', '')}:{event.get('DestinationPort', '')}",
                f"目标主机: {event.get('DestinationHostname', 'N/A')}",
            ])

        # 可疑原因
        if event.get('is_suspicious'):
            lines.extend([
                "",
                "--- 可疑原因 ---",
            ])
            for reason in event.get('suspicious_reasons', []):
                lines.append(f"  * {reason}")

        self.detail_text.insert(tk.END, '\n'.join(lines))
        self.detail_text.config(state=tk.DISABLED)

    def _show_full_detail(self):
        """显示完整详情对话框"""
        selection = self.event_tree.selection()
        if not selection:
            return

        index = self.event_tree.index(selection[0])
        if 0 <= index < len(self.filtered_events):
            event = self.filtered_events[index]

            # 构建详情数据
            detail_data = {}
            for key, value in event.items():
                if value and key not in ('is_suspicious', 'suspicious_reasons', 'EventType'):
                    detail_data[key] = value

            if event.get('is_suspicious'):
                detail_data['---可疑原因---'] = ''
                for i, reason in enumerate(event.get('suspicious_reasons', []), 1):
                    detail_data[f'原因{i}'] = reason

            self.show_detail_dialog(f"事件详情 - {event.get('EventName', '')}", detail_data)

    def _copy_event(self):
        """复制事件信息"""
        selection = self.event_tree.selection()
        if not selection:
            return

        index = self.event_tree.index(selection[0])
        if 0 <= index < len(self.filtered_events):
            event = self.filtered_events[index]
            info = '\n'.join(f"{k}: {v}" for k, v in event.items()
                           if v and k not in ('is_suspicious', 'suspicious_reasons'))
            self.event_tree.clipboard_clear()
            self.event_tree.clipboard_append(info)
            self.log("已复制事件信息到剪贴板", self.output_widget)

    def _copy_username(self):
        """复制用户名"""
        selection = self.event_tree.selection()
        if not selection:
            return

        index = self.event_tree.index(selection[0])
        if 0 <= index < len(self.filtered_events):
            user = self._get_user(self.filtered_events[index])
            if user:
                self.event_tree.clipboard_clear()
                self.event_tree.clipboard_append(user)
                self.log(f"已复制用户名: {user}", self.output_widget)

    def _copy_ip(self):
        """复制IP地址"""
        selection = self.event_tree.selection()
        if not selection:
            return

        index = self.event_tree.index(selection[0])
        if 0 <= index < len(self.filtered_events):
            event = self.filtered_events[index]
            ip = event.get('IpAddress') or event.get('DestinationIp') or event.get('SourceIp')
            if ip and ip != '-':
                self.event_tree.clipboard_clear()
                self.event_tree.clipboard_append(ip)
                self.log(f"已复制IP: {ip}", self.output_widget)

    def _trace_process(self):
        """在进程溯源中查询"""
        selection = self.event_tree.selection()
        if not selection:
            return

        index = self.event_tree.index(selection[0])
        if 0 <= index < len(self.filtered_events):
            event = self.filtered_events[index]
            pid = event.get('ProcessId')
            if pid:
                self.log(f"请在进程溯源选项卡中查询 PID: {pid}", self.output_widget)

    def _export_csv(self):
        """导出为CSV"""
        if not self.filtered_events:
            messagebox.showwarning("提示", "没有数据可导出")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
            initialfile=f"eventlog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                if self.filtered_events:
                    # 获取所有字段
                    fields = set()
                    for event in self.filtered_events:
                        fields.update(event.keys())
                    fields = sorted(fields)

                    writer = csv.DictWriter(f, fieldnames=fields)
                    writer.writeheader()

                    for event in self.filtered_events:
                        # 处理列表字段
                        row = {}
                        for k, v in event.items():
                            if isinstance(v, list):
                                row[k] = '; '.join(str(x) for x in v)
                            else:
                                row[k] = v
                        writer.writerow(row)

            self.log(f"已导出 {len(self.filtered_events)} 条事件到: {file_path}", self.output_widget)
            messagebox.showinfo("成功", f"已导出到:\n{file_path}")

        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")
