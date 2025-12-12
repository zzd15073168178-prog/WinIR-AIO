#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程溯源选项卡
用于追踪进程创建链，解决父进程已退出无法追溯的问题
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Any, Optional, List, Dict
import threading
from datetime import datetime
from .base_tab import BaseTab
from console_logger import log_action, console_log


class ProcessTraceTab(BaseTab):
    """进程溯源选项卡"""

    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.chain_data = []  # 当前显示的进程链
        self.pid_entry = None
        self.hours_var = None
        self.status_label = None
        self.chain_tree = None
        self.detail_text = None
        super().__init__(parent, manager, "进程溯源")

    def setup_ui(self):
        """设置UI"""
        # 工具栏
        toolbar = ttk.Frame(self.frame)
        toolbar.pack(fill=tk.X, pady=5, padx=5)

        # PID 输入
        ttk.Label(toolbar, text="进程PID:").pack(side=tk.LEFT, padx=(0, 5))
        self.pid_entry = ttk.Entry(toolbar, width=12)
        self.pid_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.pid_entry.bind('<Return>', lambda e: self.query_process_chain())

        # 查询按钮
        ttk.Button(toolbar, text="查询进程链", command=self.query_process_chain).pack(side=tk.LEFT, padx=5)

        # 时间范围
        ttk.Label(toolbar, text="查询范围:").pack(side=tk.LEFT, padx=(20, 5))
        self.hours_var = tk.StringVar(value="24")
        hours_combo = ttk.Combobox(toolbar, textvariable=self.hours_var, width=8,
                                   values=["1", "6", "12", "24", "48", "72", "168"])
        hours_combo.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(toolbar, text="小时").pack(side=tk.LEFT)

        # 刷新缓存按钮
        ttk.Button(toolbar, text="加载历史", command=self._load_history).pack(side=tk.LEFT, padx=20)

        # 数据源状态
        self.source_label = ttk.Label(toolbar, text="", foreground='gray')
        self.source_label.pack(side=tk.RIGHT, padx=5)

        # 主内容区域 - 使用 PanedWindow 分割
        paned = ttk.PanedWindow(self.frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 上半部分 - 进程链树形视图
        tree_frame = ttk.LabelFrame(paned, text="进程创建链")
        paned.add(tree_frame, weight=2)

        # 创建树形视图
        columns = ('PID', '进程名', '路径', '状态', '来源')
        self.chain_tree = ttk.Treeview(tree_frame, columns=columns,
                                       show='tree headings', height=10)

        self.chain_tree.heading('#0', text='层级')
        self.chain_tree.heading('PID', text='PID')
        self.chain_tree.heading('进程名', text='进程名')
        self.chain_tree.heading('路径', text='可执行路径')
        self.chain_tree.heading('状态', text='状态')
        self.chain_tree.heading('来源', text='数据来源')

        self.chain_tree.column('#0', width=150)
        self.chain_tree.column('PID', width=70)
        self.chain_tree.column('进程名', width=120)
        self.chain_tree.column('路径', width=300)
        self.chain_tree.column('状态', width=70)
        self.chain_tree.column('来源', width=80)

        # 标签样式
        self.chain_tree.tag_configure('alive', background='#ccffcc', foreground='darkgreen')
        self.chain_tree.tag_configure('exited', background='#ffeecc', foreground='#996600')
        self.chain_tree.tag_configure('unknown', background='#ffcccc', foreground='red')
        self.chain_tree.tag_configure('target', background='#cce5ff', foreground='darkblue')

        # 滚动条
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.chain_tree.yview)
        self.chain_tree.configure(yscrollcommand=scrollbar.set)

        self.chain_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定选择事件
        self.chain_tree.bind('<<TreeviewSelect>>', self._on_select)
        self.chain_tree.bind('<Double-1>', lambda e: self._show_full_detail())

        # 右键菜单
        self._setup_context_menu()

        # 下半部分 - 详情面板
        detail_frame = ttk.LabelFrame(paned, text="进程详情")
        paned.add(detail_frame, weight=1)

        self.detail_text = scrolledtext.ScrolledText(detail_frame, height=8,
                                                     font=('Consolas', 9), wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 状态栏
        status_frame = ttk.Frame(self.frame)
        status_frame.pack(fill=tk.X, pady=5, padx=5)

        self.status_label = ttk.Label(status_frame, text="就绪 - 输入 PID 开始查询")
        self.status_label.pack(side=tk.LEFT)

        # 缓存统计
        self.cache_label = ttk.Label(status_frame, text="", foreground='gray')
        self.cache_label.pack(side=tk.RIGHT)

        # 初始化检查数据源
        self.frame.after(100, self._check_data_source)

    def _setup_context_menu(self):
        """设置右键菜单"""
        menu_items = [
            {'label': '查看完整详情', 'command': self._show_full_detail},
            {'label': '复制信息', 'command': self._copy_info},
            {'separator': True, 'label': '---'},
            {'label': '以此进程为起点查询', 'command': self._query_from_selected},
            {'separator': True, 'label': '---'},
            {'label': '复制命令行', 'command': self._copy_cmdline},
            {'label': '复制路径', 'command': self._copy_path},
        ]
        self.setup_tree_context_menu(self.chain_tree, menu_items)

    def _check_data_source(self):
        """检查数据源可用性"""
        def check():
            info = self.manager.get_data_source_info()
            self.safe_after(lambda: self._update_source_label(info))

        threading.Thread(target=check, daemon=True).start()

    def _update_source_label(self, info: Dict[str, Any]):
        """更新数据源标签"""
        primary = info.get('primary_source', 'none')
        if primary == 'sysmon':
            self.source_label.config(text="数据源: Sysmon", foreground='green')
        elif primary == 'security':
            self.source_label.config(text="数据源: Security日志", foreground='orange')
        else:
            self.source_label.config(text="数据源: 无可用日志", foreground='red')

    def query_process_chain(self):
        """查询进程创建链"""
        pid_str = self.pid_entry.get().strip()
        if not pid_str:
            messagebox.showwarning("提示", "请输入进程 PID")
            return

        try:
            pid = int(pid_str)
        except ValueError:
            messagebox.showwarning("错误", "PID 必须是数字")
            return

        self.status_label.config(text=f"正在查询 PID {pid} 的进程链...")
        self.log(f"开始查询进程链: PID {pid}", self.output_widget)
        log_action("进程溯源", f"PID: {pid}")

        def query():
            try:
                hours = int(self.hours_var.get())
            except:
                hours = 24

            chain = self.manager.get_process_chain(pid, max_depth=15)
            self.safe_after(lambda: self._display_chain(chain, pid))

        threading.Thread(target=query, daemon=True).start()

    def _display_chain(self, chain: List[Dict[str, Any]], target_pid: int):
        """显示进程链"""
        # 清空树
        for item in self.chain_tree.get_children():
            self.chain_tree.delete(item)

        self.chain_data = chain

        if not chain:
            self.status_label.config(text=f"未找到 PID {target_pid} 的进程信息")
            self.log(f"未找到 PID {target_pid} 的进程信息", self.output_widget)
            return

        # 从目标进程开始，逐级显示（反向，让目标进程在最上面）
        parent_node = ''

        for i, proc in enumerate(chain):
            pid = proc.get('pid', 0)
            name = proc.get('name', 'Unknown')
            exe_path = proc.get('exe_path', '')
            is_alive = proc.get('is_alive', False)
            source = proc.get('source', 'unknown')

            # 确定状态和标签
            if i == 0:  # 目标进程
                status = '目标进程'
                tag = 'target'
                prefix = '目标'
            elif is_alive:
                status = '运行中'
                tag = 'alive'
                prefix = '父进程' if i == 1 else f'第{i}级父进程'
            elif source == 'unknown':
                status = '未知'
                tag = 'unknown'
                prefix = f'第{i}级父进程'
            else:
                status = '已退出'
                tag = 'exited'
                prefix = '父进程' if i == 1 else f'第{i}级父进程'

            # 数据来源显示
            source_display = {
                'psutil': '实时',
                'sysmon': 'Sysmon',
                'security': 'Security',
                'sysmon_parent': 'Sysmon',
                'event_log': '事件日志',
                'unknown': '未知'
            }.get(source, source)

            # 插入节点
            node = self.chain_tree.insert(
                parent_node, tk.END,
                text=prefix,
                values=(pid, name, exe_path, status, source_display),
                tags=(tag,)
            )

            # 展开节点
            self.chain_tree.item(node, open=True)
            parent_node = node

        # 更新状态
        alive_count = sum(1 for p in chain if p.get('is_alive'))
        exited_count = len(chain) - alive_count

        self.status_label.config(
            text=f"找到 {len(chain)} 级进程链 | 运行中: {alive_count} | 已退出: {exited_count}"
        )

        self.log(
            f"查询完成: PID {target_pid} 的进程链共 {len(chain)} 级",
            self.output_widget
        )

        # 选中目标进程
        first_item = self.chain_tree.get_children()
        if first_item:
            self.chain_tree.selection_set(first_item[0])
            self.chain_tree.focus(first_item[0])

        # 更新缓存统计
        self._update_cache_stats()

    def _on_select(self, event):
        """选择事件处理"""
        selection = self.chain_tree.selection()
        if not selection:
            return

        # 获取选中项的索引
        item = selection[0]
        values = self.chain_tree.item(item, 'values')
        if not values:
            return

        pid = int(values[0])

        # 查找对应的进程信息
        proc = None
        for p in self.chain_data:
            if p.get('pid') == pid:
                proc = p
                break

        if proc:
            self._show_detail(proc)

    def _show_detail(self, proc: Dict[str, Any]):
        """显示进程详情"""
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)

        # 基本信息
        lines = [
            f"进程名: {proc.get('name', 'N/A')}",
            f"PID: {proc.get('pid', 'N/A')}",
            f"状态: {'运行中' if proc.get('is_alive') else '已退出'}",
            f"数据来源: {proc.get('source', 'N/A')}",
            "",
            f"可执行路径: {proc.get('exe_path', 'N/A')}",
            f"命令行: {proc.get('cmdline', 'N/A')}",
            f"用户: {proc.get('user', 'N/A')}",
        ]

        # 创建时间
        create_time = proc.get('create_time')
        if create_time:
            if isinstance(create_time, datetime):
                lines.append(f"创建时间: {create_time.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                lines.append(f"创建时间: {create_time}")

        # 父进程信息
        parent_pid = proc.get('parent_pid')
        if parent_pid:
            lines.extend([
                "",
                "--- 父进程信息 ---",
                f"父进程PID: {parent_pid}",
                f"父进程名: {proc.get('parent_name', 'N/A')}",
                f"父进程路径: {proc.get('parent_exe_path', 'N/A')}",
                f"父进程命令行: {proc.get('parent_cmdline', 'N/A')}",
            ])

        # 额外信息
        if proc.get('integrity_level'):
            lines.append(f"\n完整性级别: {proc.get('integrity_level')}")
        if proc.get('hashes'):
            lines.append(f"哈希: {proc.get('hashes')}")

        self.detail_text.insert(tk.END, '\n'.join(lines))
        self.detail_text.config(state=tk.DISABLED)

    def _show_full_detail(self):
        """显示完整详情对话框"""
        selection = self.chain_tree.selection()
        if not selection:
            return

        values = self.chain_tree.item(selection[0], 'values')
        if not values:
            return

        pid = int(values[0])
        proc = None
        for p in self.chain_data:
            if p.get('pid') == pid:
                proc = p
                break

        if not proc:
            return

        # 构建详情数据
        detail_data = {
            'PID': proc.get('pid'),
            '进程名': proc.get('name'),
            '状态': '运行中' if proc.get('is_alive') else '已退出',
            '数据来源': proc.get('source'),
            '---1': '',
            '可执行路径': proc.get('exe_path') or 'N/A',
            '命令行': proc.get('cmdline') or 'N/A',
            '用户': proc.get('user') or 'N/A',
        }

        create_time = proc.get('create_time')
        if create_time:
            if isinstance(create_time, datetime):
                detail_data['创建时间'] = create_time.strftime('%Y-%m-%d %H:%M:%S')
            else:
                detail_data['创建时间'] = str(create_time)

        detail_data['---2'] = ''
        detail_data['父进程PID'] = proc.get('parent_pid') or 'N/A'
        detail_data['父进程名'] = proc.get('parent_name') or 'N/A'
        detail_data['父进程路径'] = proc.get('parent_exe_path') or 'N/A'
        detail_data['父进程命令行'] = proc.get('parent_cmdline') or 'N/A'

        if proc.get('integrity_level'):
            detail_data['---3'] = ''
            detail_data['完整性级别'] = proc.get('integrity_level')

        if proc.get('hashes'):
            detail_data['哈希'] = proc.get('hashes')

        self.show_detail_dialog(f"进程详情 - {proc.get('name')}", detail_data)

    def _copy_info(self):
        """复制进程信息"""
        selection = self.chain_tree.selection()
        if not selection:
            return

        values = self.chain_tree.item(selection[0], 'values')
        if not values:
            return

        pid = int(values[0])
        proc = None
        for p in self.chain_data:
            if p.get('pid') == pid:
                proc = p
                break

        if proc:
            info = f"PID: {proc.get('pid')}\n"
            info += f"进程名: {proc.get('name')}\n"
            info += f"路径: {proc.get('exe_path')}\n"
            info += f"命令行: {proc.get('cmdline')}\n"
            info += f"父进程PID: {proc.get('parent_pid')}\n"
            info += f"父进程名: {proc.get('parent_name')}"

            self.chain_tree.clipboard_clear()
            self.chain_tree.clipboard_append(info)
            self.log("已复制进程信息到剪贴板", self.output_widget)

    def _copy_cmdline(self):
        """复制命令行"""
        selection = self.chain_tree.selection()
        if not selection:
            return

        values = self.chain_tree.item(selection[0], 'values')
        if not values:
            return

        pid = int(values[0])
        for p in self.chain_data:
            if p.get('pid') == pid and p.get('cmdline'):
                self.chain_tree.clipboard_clear()
                self.chain_tree.clipboard_append(p.get('cmdline'))
                self.log("已复制命令行到剪贴板", self.output_widget)
                return

    def _copy_path(self):
        """复制路径"""
        selection = self.chain_tree.selection()
        if not selection:
            return

        values = self.chain_tree.item(selection[0], 'values')
        if not values:
            return

        pid = int(values[0])
        for p in self.chain_data:
            if p.get('pid') == pid and p.get('exe_path'):
                self.chain_tree.clipboard_clear()
                self.chain_tree.clipboard_append(p.get('exe_path'))
                self.log("已复制路径到剪贴板", self.output_widget)
                return

    def _query_from_selected(self):
        """以选中的进程为起点查询"""
        selection = self.chain_tree.selection()
        if not selection:
            return

        values = self.chain_tree.item(selection[0], 'values')
        if not values:
            return

        pid = values[0]
        self.pid_entry.delete(0, tk.END)
        self.pid_entry.insert(0, str(pid))
        self.query_process_chain()

    def _load_history(self):
        """加载历史进程"""
        try:
            hours = int(self.hours_var.get())
        except:
            hours = 24

        self.status_label.config(text=f"正在加载最近 {hours} 小时的历史进程...")
        self.log(f"开始加载历史进程记录（最近 {hours} 小时）...", self.output_widget)

        def load():
            self.manager.load_from_event_log(hours=hours)
            self.manager.refresh_cache()
            self.safe_after(self._on_load_complete)

        threading.Thread(target=load, daemon=True).start()

    def _on_load_complete(self):
        """加载完成回调"""
        stats = self.manager.get_cache_stats()
        self.status_label.config(
            text=f"加载完成 | 缓存: {stats['total']} 个进程 (运行中: {stats['alive']}, 已退出: {stats['exited']})"
        )
        self.log(f"历史进程加载完成，共 {stats['total']} 条记录", self.output_widget)
        self._update_cache_stats()

    def _update_cache_stats(self):
        """更新缓存统计"""
        stats = self.manager.get_cache_stats()
        self.cache_label.config(
            text=f"缓存: {stats['total']} 条"
        )

    def set_pid_and_query(self, pid: int):
        """设置 PID 并查询（供外部调用）"""
        self.pid_entry.delete(0, tk.END)
        self.pid_entry.insert(0, str(pid))
        self.query_process_chain()
