#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""行为监控沙箱选项卡"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Any, Dict, List
import threading
import os
from datetime import datetime
from .base_tab import BaseTab
from console_logger import log_action, console_log


class SandboxTab(BaseTab):
    """行为监控沙箱选项卡"""

    def __init__(self, parent, manager: Any, output_widget):
        self.output_widget = output_widget

        # UI 组件
        self.file_path_var = None
        self.args_var = None
        self.timeout_var = None
        self.start_btn = None
        self.stop_btn = None
        self.clear_btn = None
        self.report_btn = None
        self.status_label = None
        self.progress_bar = None
        self.progress_label = None

        # 结果展示组件
        self.result_notebook = None
        self.dropped_files_tree = None
        self.processes_tree = None
        self.network_tree = None
        self.registry_tree = None
        self.persistence_tree = None

        # 统计标签
        self.stats_labels = {}

        super().__init__(parent, manager, "行为沙箱")

    def setup_ui(self):
        """设置 UI"""
        # 主容器
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ==================== 控制面板 ====================
        control_frame = ttk.LabelFrame(main_container, text="控制面板", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 5))

        # 第一行：目标文件
        row1 = ttk.Frame(control_frame)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="目标文件:", width=10).pack(side=tk.LEFT)
        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(row1, textvariable=self.file_path_var, width=60)
        file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(row1, text="浏览", command=self._browse_file, width=8).pack(side=tk.LEFT, padx=2)

        # 第二行：参数和超时
        row2 = ttk.Frame(control_frame)
        row2.pack(fill=tk.X, pady=2)

        ttk.Label(row2, text="命令参数:", width=10).pack(side=tk.LEFT)
        self.args_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.args_var, width=40).pack(side=tk.LEFT, padx=5)

        ttk.Label(row2, text="超时(秒):").pack(side=tk.LEFT, padx=(20, 5))
        self.timeout_var = tk.StringVar(value="60")
        timeout_spin = ttk.Spinbox(row2, textvariable=self.timeout_var, from_=10, to=300, width=6)
        timeout_spin.pack(side=tk.LEFT)

        # 第三行：按钮
        row3 = ttk.Frame(control_frame)
        row3.pack(fill=tk.X, pady=(10, 0))

        self.start_btn = ttk.Button(row3, text="启动分析", command=self._start_analysis,
                                     width=12, bootstyle="success")
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(row3, text="停止分析", command=self._stop_analysis,
                                    width=12, state=tk.DISABLED, bootstyle="danger")
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = ttk.Button(row3, text="清空结果", command=self._clear_results, width=12)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        self.report_btn = ttk.Button(row3, text="生成报告", command=self._generate_report,
                                      width=12, state=tk.DISABLED, bootstyle="info")
        self.report_btn.pack(side=tk.LEFT, padx=5)

        # ==================== 状态栏 ====================
        status_frame = ttk.Frame(main_container)
        status_frame.pack(fill=tk.X, pady=5)

        self.status_label = ttk.Label(status_frame, text="状态: 就绪", font=("微软雅黑", 10))
        self.status_label.pack(side=tk.LEFT)

        self.progress_label = ttk.Label(status_frame, text="")
        self.progress_label.pack(side=tk.RIGHT, padx=10)

        self.progress_bar = ttk.Progressbar(status_frame, length=200, mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT)

        # ==================== 结果展示区 ====================
        result_frame = ttk.LabelFrame(main_container, text="分析结果", padding=5)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.result_notebook = ttk.Notebook(result_frame)
        self.result_notebook.pack(fill=tk.BOTH, expand=True)

        # 创建各个结果 Tab
        self._create_dropped_files_tab()
        self._create_processes_tab()
        self._create_network_tab()
        self._create_registry_tab()
        self._create_persistence_tab()

        # ==================== 说明 ====================
        info_text = ("行为监控沙箱：用于分析可疑程序的运行时行为。"
                     "监控内容包括：文件释放、进程创建、网络连接、注册表修改、持久化变化。"
                     "注意：这不是隔离沙箱，程序的操作会真实影响系统，建议在虚拟机中运行。")
        info_label = ttk.Label(main_container, text=info_text, wraplength=900, foreground='gray')
        info_label.pack(pady=5)

        # 设置回调
        self._setup_callbacks()

    def _create_dropped_files_tab(self):
        """创建释放文件 Tab"""
        tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(tab, text="释放文件")

        # 工具栏
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=tk.X, pady=2)

        self.stats_labels['dropped'] = ttk.Label(toolbar, text="共 0 个文件，可执行文件 0 个")
        self.stats_labels['dropped'].pack(side=tk.LEFT, padx=5)

        # Treeview
        columns = ('文件名', '类型', '大小', '操作', 'MD5', '路径')
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.dropped_files_tree = self.create_tree(tree_frame, columns)
        self.dropped_files_tree.column('文件名', width=150)
        self.dropped_files_tree.column('类型', width=120)
        self.dropped_files_tree.column('大小', width=80)
        self.dropped_files_tree.column('操作', width=80)
        self.dropped_files_tree.column('MD5', width=220)
        self.dropped_files_tree.column('路径', width=350)

        scrollbar = self.add_scrollbar(tree_frame, self.dropped_files_tree)
        self.dropped_files_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 右键菜单
        self._setup_file_context_menu(self.dropped_files_tree)

    def _create_processes_tab(self):
        """创建运行程序 Tab"""
        tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(tab, text="运行程序")

        # 工具栏
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=tk.X, pady=2)

        self.stats_labels['processes'] = ttk.Label(toolbar, text="共 0 个进程")
        self.stats_labels['processes'].pack(side=tk.LEFT, padx=5)

        # Treeview
        columns = ('PID', '进程名', '命令行', '父进程', '启动时间', '状态')
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.processes_tree = self.create_tree(tree_frame, columns)
        self.processes_tree.column('PID', width=60)
        self.processes_tree.column('进程名', width=120)
        self.processes_tree.column('命令行', width=400)
        self.processes_tree.column('父进程', width=60)
        self.processes_tree.column('启动时间', width=140)
        self.processes_tree.column('状态', width=80)

        scrollbar = self.add_scrollbar(tree_frame, self.processes_tree)
        self.processes_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 右键菜单
        self._setup_process_context_menu(self.processes_tree)

    def _create_network_tab(self):
        """创建网络连接 Tab"""
        tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(tab, text="网络连接")

        # 工具栏
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=tk.X, pady=2)

        self.stats_labels['network'] = ttk.Label(toolbar, text="共 0 个连接")
        self.stats_labels['network'].pack(side=tk.LEFT, padx=5)

        # Treeview
        columns = ('时间', '进程', '协议', '本地地址', '远程地址', '状态', '可疑')
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.network_tree = self.create_tree(tree_frame, columns)
        self.network_tree.column('时间', width=140)
        self.network_tree.column('进程', width=100)
        self.network_tree.column('协议', width=60)
        self.network_tree.column('本地地址', width=150)
        self.network_tree.column('远程地址', width=180)
        self.network_tree.column('状态', width=100)
        self.network_tree.column('可疑', width=60)

        # 配置可疑标记颜色
        self.network_tree.tag_configure('suspicious', foreground='red')

        scrollbar = self.add_scrollbar(tree_frame, self.network_tree)
        self.network_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _create_registry_tab(self):
        """创建注册表修改 Tab"""
        tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(tab, text="注册表修改")

        # 工具栏
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=tk.X, pady=2)

        self.stats_labels['registry'] = ttk.Label(toolbar, text="共 0 个修改")
        self.stats_labels['registry'].pack(side=tk.LEFT, padx=5)

        # Treeview
        columns = ('时间', '操作', '键路径', '详情')
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.registry_tree = self.create_tree(tree_frame, columns)
        self.registry_tree.column('时间', width=100)
        self.registry_tree.column('操作', width=120)
        self.registry_tree.column('键路径', width=500)
        self.registry_tree.column('详情', width=200)

        scrollbar = self.add_scrollbar(tree_frame, self.registry_tree)
        self.registry_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _create_persistence_tab(self):
        """创建持久化变化 Tab"""
        tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(tab, text="持久化变化")

        # 工具栏
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=tk.X, pady=2)

        self.stats_labels['persistence'] = ttk.Label(toolbar, text="共 0 个变化")
        self.stats_labels['persistence'].pack(side=tk.LEFT, padx=5)

        # Treeview
        columns = ('类型', '操作', '位置', '值', '严重性')
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.persistence_tree = self.create_tree(tree_frame, columns)
        self.persistence_tree.column('类型', width=150)
        self.persistence_tree.column('操作', width=80)
        self.persistence_tree.column('位置', width=400)
        self.persistence_tree.column('值', width=200)
        self.persistence_tree.column('严重性', width=80)

        # 配置严重性颜色
        self.persistence_tree.tag_configure('critical', foreground='red')
        self.persistence_tree.tag_configure('warning', foreground='orange')
        self.persistence_tree.tag_configure('info', foreground='gray')

        scrollbar = self.add_scrollbar(tree_frame, self.persistence_tree)
        self.persistence_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _setup_file_context_menu(self, tree):
        """设置文件列表右键菜单"""
        menu_items = [
            {'label': '查看详情', 'command': lambda: self._show_file_detail(tree)},
            {'label': '复制路径', 'command': lambda: self._copy_path(tree, 5)},
            {'label': '复制 MD5', 'command': lambda: self._copy_path(tree, 4)},
            {'separator': True},
            {'label': '打开文件位置', 'command': lambda: self._open_file_location(tree, 5)},
        ]
        self.setup_tree_context_menu(tree, menu_items)

    def _setup_process_context_menu(self, tree):
        """设置进程列表右键菜单"""
        menu_items = [
            {'label': '查看详情', 'command': lambda: self._show_process_detail(tree)},
            {'label': '复制命令行', 'command': lambda: self._copy_path(tree, 2)},
        ]
        self.setup_tree_context_menu(tree, menu_items)

    def _setup_callbacks(self):
        """设置回调函数"""
        self.manager.on_status_change = self._on_status_change
        self.manager.on_progress_update = self._on_progress_update
        self.manager.on_complete = self._on_complete

    # ==================== 控制方法 ====================

    def _browse_file(self):
        """浏览选择文件"""
        file_path = filedialog.askopenfilename(
            title="选择要分析的文件",
            filetypes=[
                ("可执行文件", "*.exe;*.bat;*.cmd;*.ps1;*.vbs;*.js"),
                ("所有文件", "*.*")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)

    def _start_analysis(self):
        """启动分析"""
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("警告", "请选择要分析的文件")
            return

        if not os.path.exists(file_path):
            messagebox.showerror("错误", f"文件不存在: {file_path}")
            return

        try:
            timeout = int(self.timeout_var.get())
        except ValueError:
            timeout = 60

        args = self.args_var.get().strip()

        # 确认对话框
        if not messagebox.askyesno("确认",
                f"即将分析文件:\n{file_path}\n\n"
                f"超时时间: {timeout} 秒\n\n"
                "警告: 程序的操作会真实影响系统！\n"
                "建议在虚拟机中运行。\n\n"
                "是否继续?"):
            return

        self.log(f"开始分析: {file_path}", self.output_widget)
        log_action("沙箱分析", file_path)

        # 清空旧结果
        self._clear_all_trees()

        # 更新 UI 状态
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.clear_btn.configure(state=tk.DISABLED)
        self.report_btn.configure(state=tk.DISABLED)

        # 在后台线程启动分析
        def start_thread():
            success, message, pid = self.manager.start_analysis(
                file_path, args, timeout
            )
            self.safe_after(self._on_start_result, success, message, pid)

        threading.Thread(target=start_thread, daemon=True).start()

    def _stop_analysis(self):
        """停止分析"""
        self.log("正在停止分析...", self.output_widget)

        def stop_thread():
            success, message = self.manager.stop_analysis()
            self.safe_after(self._on_stop_result, success, message)

        threading.Thread(target=stop_thread, daemon=True).start()

    def _clear_results(self):
        """清空结果"""
        self._clear_all_trees()
        self._reset_stats()
        self.progress_bar['value'] = 0
        self.progress_label.configure(text="")
        self.status_label.configure(text="状态: 就绪")
        self.log("结果已清空", self.output_widget)

    def _generate_report(self):
        """生成报告"""
        format_choice = messagebox.askquestion(
            "报告格式",
            "选择报告格式:\n\n是 = HTML 格式 (推荐)\n否 = JSON 格式"
        )
        report_format = 'html' if format_choice == 'yes' else 'json'

        self.log(f"正在生成 {report_format.upper()} 报告...", self.output_widget)

        def generate_thread():
            success, message, file_path = self.manager.generate_report(report_format)
            self.safe_after(self._on_report_result, success, message, file_path)

        threading.Thread(target=generate_thread, daemon=True).start()

    # ==================== 回调方法 ====================

    def _on_status_change(self, status: str, message: str):
        """状态变化回调"""
        self.safe_after(self._update_status_label, status, message)

    def _on_progress_update(self, progress: int, message: str):
        """进度更新回调"""
        self.safe_after(self._update_progress, progress, message)

    def _on_complete(self, results: Dict):
        """分析完成回调"""
        self.safe_after(self._display_results, results)

    def _on_start_result(self, success: bool, message: str, pid: int):
        """启动结果回调"""
        if success:
            self.log(f"分析已启动，PID: {pid}", self.output_widget)
        else:
            self.log(f"启动失败: {message}", self.output_widget)
            self._reset_buttons()

    def _on_stop_result(self, success: bool, message: str):
        """停止结果回调"""
        if success:
            self.log("分析已停止", self.output_widget)
        else:
            self.log(f"停止失败: {message}", self.output_widget)
        self._reset_buttons()

    def _on_report_result(self, success: bool, message: str, file_path: str):
        """报告生成结果回调"""
        if success:
            self.log(f"报告已生成: {file_path}", self.output_widget)
            if messagebox.askyesno("成功", f"报告已生成:\n{file_path}\n\n是否打开?"):
                os.startfile(file_path)
        else:
            self.log(f"报告生成失败: {message}", self.output_widget)
            messagebox.showerror("错误", f"报告生成失败: {message}")

    # ==================== UI 更新方法 ====================

    def _update_status_label(self, status: str, message: str):
        """更新状态标签"""
        status_colors = {
            'preparing': 'blue',
            'snapshot': 'blue',
            'procmon': 'blue',
            'running': 'green',
            'analyzing': 'orange',
            'completed': 'green',
            'error': 'red',
            'stopping': 'orange',
            'timeout': 'orange',
            'exited': 'gray',
        }
        color = status_colors.get(status, 'black')
        self.status_label.configure(text=f"状态: {message}", foreground=color)

    def _update_progress(self, progress: int, message: str):
        """更新进度条"""
        self.progress_bar['value'] = progress
        self.progress_label.configure(text=message)

    def _display_results(self, results: Dict):
        """显示分析结果"""
        self.log("正在显示分析结果...", self.output_widget)

        # 释放文件
        dropped = results.get('dropped_files', [])
        executable = results.get('executable_files', [])
        for item in self.dropped_files_tree.get_children():
            self.dropped_files_tree.delete(item)
        for f in dropped:
            tag = 'executable' if f.get('is_executable') else ''
            self.dropped_files_tree.insert('', tk.END, values=(
                f.get('filename', ''),
                f.get('file_type', ''),
                f.get('size_str', ''),
                f.get('operation', ''),
                f.get('md5', ''),
                f.get('path', ''),
            ), tags=(tag,))
        self.dropped_files_tree.tag_configure('executable', foreground='red')
        self.stats_labels['dropped'].configure(
            text=f"共 {len(dropped)} 个文件，可执行文件 {len(executable)} 个"
        )

        # 运行程序
        processes = results.get('spawned_processes', [])
        for item in self.processes_tree.get_children():
            self.processes_tree.delete(item)
        for p in processes:
            self.processes_tree.insert('', tk.END, values=(
                p.get('pid', ''),
                p.get('name', ''),
                p.get('cmdline', ''),
                p.get('parent_pid', ''),
                p.get('create_time', ''),
                p.get('status', ''),
            ))
        self.stats_labels['processes'].configure(text=f"共 {len(processes)} 个进程")

        # 网络连接
        connections = results.get('network_connections', [])
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
        for c in connections:
            is_suspicious = c.get('is_suspicious', False)
            tag = 'suspicious' if is_suspicious else ''
            self.network_tree.insert('', tk.END, values=(
                c.get('time', ''),
                c.get('process_name', ''),
                c.get('protocol', ''),
                c.get('local_addr', ''),
                c.get('remote_addr', ''),
                c.get('status', ''),
                '是' if is_suspicious else '否',
            ), tags=(tag,))
        self.stats_labels['network'].configure(text=f"共 {len(connections)} 个连接")

        # 注册表修改
        registry = results.get('registry_modifications', [])
        for item in self.registry_tree.get_children():
            self.registry_tree.delete(item)
        for r in registry:
            self.registry_tree.insert('', tk.END, values=(
                r.get('time', ''),
                r.get('operation', ''),
                r.get('path', ''),
                r.get('detail', ''),
            ))
        self.stats_labels['registry'].configure(text=f"共 {len(registry)} 个修改")

        # 持久化变化
        persistence = results.get('persistence_changes', [])
        for item in self.persistence_tree.get_children():
            self.persistence_tree.delete(item)
        for p in persistence:
            severity = p.get('severity', 'info')
            value_str = str(p.get('value', ''))[:100]  # 限制长度
            self.persistence_tree.insert('', tk.END, values=(
                p.get('type', ''),
                p.get('action', ''),
                p.get('location', ''),
                value_str,
                severity,
            ), tags=(severity,))
        self.stats_labels['persistence'].configure(text=f"共 {len(persistence)} 个变化")

        # 更新按钮状态
        self._reset_buttons()
        if dropped or processes or connections or registry or persistence:
            self.report_btn.configure(state=tk.NORMAL)

        # 汇总日志
        self.log(f"分析完成: 释放文件 {len(dropped)} 个 (可执行 {len(executable)})，"
                 f"进程 {len(processes)} 个，网络连接 {len(connections)} 个，"
                 f"注册表修改 {len(registry)} 个，持久化变化 {len(persistence)} 个",
                 self.output_widget)

    def _clear_all_trees(self):
        """清空所有 Treeview"""
        for tree in [self.dropped_files_tree, self.processes_tree,
                     self.network_tree, self.registry_tree, self.persistence_tree]:
            if tree:
                for item in tree.get_children():
                    tree.delete(item)

    def _reset_stats(self):
        """重置统计标签"""
        self.stats_labels['dropped'].configure(text="共 0 个文件，可执行文件 0 个")
        self.stats_labels['processes'].configure(text="共 0 个进程")
        self.stats_labels['network'].configure(text="共 0 个连接")
        self.stats_labels['registry'].configure(text="共 0 个修改")
        self.stats_labels['persistence'].configure(text="共 0 个变化")

    def _reset_buttons(self):
        """重置按钮状态"""
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.clear_btn.configure(state=tk.NORMAL)

    # ==================== 右键菜单操作 ====================

    def _show_file_detail(self, tree):
        """显示文件详情"""
        selection = tree.selection()
        if not selection:
            return
        values = tree.item(selection[0])['values']
        if values:
            data = {
                '文件名': values[0],
                '类型': values[1],
                '大小': values[2],
                '操作': values[3],
                'MD5': values[4],
                '完整路径': values[5],
            }
            self.show_detail_dialog("文件详情", data)

    def _show_process_detail(self, tree):
        """显示进程详情"""
        selection = tree.selection()
        if not selection:
            return
        values = tree.item(selection[0])['values']
        if values:
            data = {
                'PID': values[0],
                '进程名': values[1],
                '命令行': values[2],
                '父进程 PID': values[3],
                '启动时间': values[4],
                '状态': values[5],
            }
            self.show_detail_dialog("进程详情", data)

    def _copy_path(self, tree, col_index: int):
        """复制指定列的值"""
        selection = tree.selection()
        if not selection:
            return
        values = tree.item(selection[0])['values']
        if values and len(values) > col_index:
            text = str(values[col_index])
            tree.clipboard_clear()
            tree.clipboard_append(text)
            self.log(f"已复制: {text[:50]}...", self.output_widget)

    def _open_file_location(self, tree, col_index: int):
        """打开文件位置"""
        selection = tree.selection()
        if not selection:
            return
        values = tree.item(selection[0])['values']
        if values and len(values) > col_index:
            path = str(values[col_index])
            self.open_file_location(path)
