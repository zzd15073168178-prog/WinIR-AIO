#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yara 规则扫描选项卡"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import psutil

from .base_tab import BaseTab


class YaraTab(BaseTab):
    """Yara 规则扫描选项卡"""

    SEVERITY_NAMES = {
        'critical': '严重',
        'high': '高',
        'medium': '中',
        'low': '低',
    }

    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.is_scanning = False
        self.processes = []
        super().__init__(parent, manager, "🛡️ Yara 扫描")

    def setup_ui(self):
        """设置 UI"""
        # 检查 yara 是否可用
        if not self.manager.is_available():
            self._show_install_guide()
            return

        # 顶部工具栏 - 规则设置和操作按钮合并
        toolbar_frame = ttk.Frame(self.frame)
        toolbar_frame.pack(fill=tk.X, padx=5, pady=3)

        # 规则选择
        self.use_builtin_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar_frame, text="内置规则(14条)", variable=self.use_builtin_var).pack(side=tk.LEFT)
        ttk.Button(toolbar_frame, text="查看", command=self.show_builtin_rules, width=4).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=5, fill=tk.Y)

        self.use_custom_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(toolbar_frame, text="自定义:", variable=self.use_custom_var).pack(side=tk.LEFT)

        self.custom_path_var = tk.StringVar()
        ttk.Entry(toolbar_frame, textvariable=self.custom_path_var, width=30).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="文件", command=self.select_rule_file, width=4).pack(side=tk.LEFT, padx=1)
        ttk.Button(toolbar_frame, text="目录", command=self.select_rule_dir, width=4).pack(side=tk.LEFT, padx=1)

        ttk.Separator(toolbar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=5, fill=tk.Y)

        ttk.Button(toolbar_frame, text="加载规则", command=self.load_rules).pack(side=tk.LEFT, padx=2)
        self.rule_status_label = ttk.Label(toolbar_frame, text="未加载", foreground='#999', width=10)
        self.rule_status_label.pack(side=tk.LEFT, padx=5)

        # 主内容区 - 左右分栏
        content_frame = ttk.Frame(self.frame)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=3)

        # 左侧 - 扫描目标
        left_frame = ttk.LabelFrame(content_frame, text="扫描目标", padding=3)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 3))

        # 扫描模式选项卡
        self.scan_notebook = ttk.Notebook(left_frame)
        self.scan_notebook.pack(fill=tk.BOTH, expand=True)

        # 进程扫描页
        proc_frame = ttk.Frame(self.scan_notebook)
        self.scan_notebook.add(proc_frame, text="进程扫描")

        proc_toolbar = ttk.Frame(proc_frame)
        proc_toolbar.pack(fill=tk.X, pady=2)

        ttk.Button(proc_toolbar, text="🔄", command=self.refresh_processes, width=3).pack(side=tk.LEFT, padx=2)
        ttk.Label(proc_toolbar, text="搜索:").pack(side=tk.LEFT, padx=(5, 2))
        self.proc_search_var = tk.StringVar()
        ttk.Entry(proc_toolbar, textvariable=self.proc_search_var, width=15).pack(side=tk.LEFT, padx=2)
        self.proc_search_var.trace('w', lambda *a: self.filter_processes())

        proc_list_frame = ttk.Frame(proc_frame)
        proc_list_frame.pack(fill=tk.BOTH, expand=True)

        self.proc_listbox = tk.Listbox(proc_list_frame, selectmode=tk.EXTENDED, exportselection=False)
        proc_scrollbar = ttk.Scrollbar(proc_list_frame, orient=tk.VERTICAL, command=self.proc_listbox.yview)
        self.proc_listbox.configure(yscrollcommand=proc_scrollbar.set)
        self.proc_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        proc_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 文件/目录扫描页
        file_frame = ttk.Frame(self.scan_notebook)
        self.scan_notebook.add(file_frame, text="文件扫描")

        file_row1 = ttk.Frame(file_frame)
        file_row1.pack(fill=tk.X, pady=3)
        ttk.Label(file_row1, text="路径:").pack(side=tk.LEFT)
        self.scan_path_var = tk.StringVar()
        ttk.Entry(file_row1, textvariable=self.scan_path_var).pack(side=tk.LEFT, padx=3, fill=tk.X, expand=True)
        ttk.Button(file_row1, text="文件", command=self.select_scan_file, width=4).pack(side=tk.LEFT, padx=1)
        ttk.Button(file_row1, text="目录", command=self.select_scan_dir, width=4).pack(side=tk.LEFT, padx=1)

        file_row2 = ttk.Frame(file_frame)
        file_row2.pack(fill=tk.X, pady=3)
        ttk.Label(file_row2, text="类型:").pack(side=tk.LEFT)
        self.file_types_var = tk.StringVar(value=".exe,.dll,.sys,.bat,.ps1,.vbs,.js")
        ttk.Entry(file_row2, textvariable=self.file_types_var).pack(side=tk.LEFT, padx=3, fill=tk.X, expand=True)

        # 右侧 - 结果
        right_frame = ttk.LabelFrame(content_frame, text="扫描结果", padding=3)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(3, 0))

        columns = ('rule', 'severity', 'target', 'type', 'description')
        self.tree = ttk.Treeview(right_frame, columns=columns, show='headings')

        self.tree.heading('rule', text='规则名称')
        self.tree.heading('severity', text='严重程度')
        self.tree.heading('target', text='扫描目标')
        self.tree.heading('type', text='类型')
        self.tree.heading('description', text='描述')

        self.tree.column('rule', width=120)
        self.tree.column('severity', width=60)
        self.tree.column('target', width=150)
        self.tree.column('type', width=40)
        self.tree.column('description', width=150)

        # 风险等级颜色
        self.tree.tag_configure('critical', foreground='#721c24', background='#f8d7da')
        self.tree.tag_configure('high', foreground='#856404', background='#ffeeba')
        self.tree.tag_configure('medium', foreground='#856404', background='#fff3cd')
        self.tree.tag_configure('low', foreground='#28a745')

        scrollbar_y = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar_y.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        # 右键菜单
        self._setup_context_menu()

        # 底部操作栏
        bottom_frame = ttk.Frame(self.frame)
        bottom_frame.pack(fill=tk.X, padx=5, pady=3)

        # 操作按钮
        ttk.Button(bottom_frame, text="扫描选中进程", command=self.scan_selected_processes).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom_frame, text="扫描所有进程", command=self.scan_all_processes).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom_frame, text="扫描文件/目录", command=self.scan_path).pack(side=tk.LEFT, padx=2)

        ttk.Separator(bottom_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        self.cancel_btn = ttk.Button(bottom_frame, text="取消", command=self.cancel_scan, state='disabled', width=6)
        self.cancel_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom_frame, text="清空", command=self.clear_results, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom_frame, text="导出", command=self.export_results, width=6).pack(side=tk.LEFT, padx=2)

        # 进度和状态
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(bottom_frame, variable=self.progress_var, maximum=100, length=150)
        self.progress_bar.pack(side=tk.RIGHT, padx=5)

        self.status_label = ttk.Label(bottom_frame, text="请先加载规则", width=30)
        self.status_label.pack(side=tk.RIGHT, padx=5)

        self.progress_label = ttk.Label(bottom_frame, text="就绪", width=20)
        self.progress_label.pack(side=tk.RIGHT)

        # 初始化
        self.refresh_processes()

    def _show_install_guide(self):
        """显示安装指南"""
        guide_frame = ttk.Frame(self.frame)
        guide_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(guide_frame, text="⚠️ yara-python 未安装", font=('微软雅黑', 14, 'bold')).pack(pady=10)

        guide_text = """
Yara 是一款强大的恶意软件识别和分类工具。

要使用此功能，请安装 yara-python:

    pip install yara-python

如果安装失败，可能需要先安装 Visual C++ Build Tools:
    1. 下载 Visual Studio Build Tools
    2. 选择 "C++ 生成工具" 工作负载
    3. 重新运行 pip install yara-python

或者使用预编译版本:
    pip install yara-python-wheel

安装完成后，请重启程序。
        """
        text_widget = tk.Text(guide_frame, height=15, width=60, font=('Consolas', 10))
        text_widget.pack(pady=10)
        text_widget.insert(tk.END, guide_text)
        text_widget.configure(state='disabled')

        ttk.Button(guide_frame, text="复制安装命令",
                  command=lambda: self._copy_to_clipboard("pip install yara-python")).pack(pady=5)

    def _copy_to_clipboard(self, text):
        """复制到剪贴板"""
        self.frame.clipboard_clear()
        self.frame.clipboard_append(text)
        messagebox.showinfo("提示", "已复制到剪贴板")

    def _setup_context_menu(self):
        """设置右键菜单"""
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="📋 复制规则名称", command=self.copy_rule_name)
        self.context_menu.add_command(label="📋 复制目标路径", command=self.copy_target)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🔍 查看详情", command=self.show_match_detail)
        self.context_menu.add_command(label="🌐 搜索规则信息", command=self.search_rule_online)

        self.tree.bind('<Button-3>', self._show_context_menu)
        self.tree.bind('<Double-1>', lambda e: self.show_match_detail())

    def _show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def refresh_processes(self):
        """刷新进程列表"""
        self.processes = []
        self.proc_listbox.delete(0, tk.END)

        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    info = proc.info
                    self.processes.append({
                        'pid': info['pid'],
                        'name': info['name'] or 'Unknown'
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            self.processes.sort(key=lambda x: x['name'].lower())

            for proc in self.processes:
                self.proc_listbox.insert(tk.END, f"{proc['name']} (PID: {proc['pid']})")

            self.log(f"🔄 已刷新进程列表，共 {len(self.processes)} 个进程", self.output_widget)
        except Exception as e:
            self.log(f"❌ 刷新进程失败: {e}", self.output_widget)

    def filter_processes(self):
        """过滤进程列表"""
        search = self.proc_search_var.get().strip().lower()
        self.proc_listbox.delete(0, tk.END)

        for proc in self.processes:
            if search in proc['name'].lower() or search in str(proc['pid']):
                self.proc_listbox.insert(tk.END, f"{proc['name']} (PID: {proc['pid']})")

    def get_selected_processes(self):
        """获取选中的进程"""
        indices = self.proc_listbox.curselection()
        selected = []

        search = self.proc_search_var.get().strip().lower()
        filtered = [p for p in self.processes
                   if search in p['name'].lower() or search in str(p['pid'])]

        for i in indices:
            if i < len(filtered):
                selected.append(filtered[i])

        return selected

    def select_rule_file(self):
        """选择规则文件"""
        file_path = filedialog.askopenfilename(
            title="选择 Yara 规则文件",
            filetypes=[("Yara 规则", "*.yar *.yara"), ("所有文件", "*.*")]
        )
        if file_path:
            self.custom_path_var.set(file_path)
            self.use_custom_var.set(True)

    def select_rule_dir(self):
        """选择规则目录"""
        dir_path = filedialog.askdirectory(title="选择 Yara 规则目录")
        if dir_path:
            self.custom_path_var.set(dir_path)
            self.use_custom_var.set(True)

    def select_scan_file(self):
        """选择要扫描的文件"""
        file_path = filedialog.askopenfilename(title="选择要扫描的文件")
        if file_path:
            self.scan_path_var.set(file_path)

    def select_scan_dir(self):
        """选择要扫描的目录"""
        dir_path = filedialog.askdirectory(title="选择要扫描的目录")
        if dir_path:
            self.scan_path_var.set(dir_path)

    def load_rules(self):
        """加载规则"""
        use_builtin = self.use_builtin_var.get()
        use_custom = self.use_custom_var.get()
        custom_path = self.custom_path_var.get().strip()

        if not use_builtin and not use_custom:
            messagebox.showwarning("提示", "请至少选择一种规则来源")
            return

        if use_custom and not custom_path:
            messagebox.showwarning("提示", "请指定自定义规则路径")
            return

        self.log("🔄 正在加载规则...", self.output_widget)

        try:
            if use_builtin and use_custom:
                success = self.manager.load_combined_rules(custom_path)
            elif use_builtin:
                success = self.manager.load_builtin_rules()
            else:
                if os.path.isfile(custom_path):
                    success = self.manager.load_rules_from_file(custom_path)
                else:
                    success = self.manager.load_rules_from_directory(custom_path)

            if success:
                self.rule_status_label.configure(text="状态: ✅ 规则已加载", foreground='green')
                self.status_label.configure(text="状态: 规则已加载，可以开始扫描")
                self.log("✅ 规则加载成功", self.output_widget)
            else:
                self.rule_status_label.configure(text="状态: ❌ 加载失败", foreground='red')
                self.log("❌ 规则加载失败", self.output_widget)
                messagebox.showerror("错误", "规则加载失败，请检查规则文件")

        except Exception as e:
            self.rule_status_label.configure(text="状态: ❌ 加载失败", foreground='red')
            self.log(f"❌ 规则加载失败: {e}", self.output_widget)
            messagebox.showerror("错误", f"规则加载失败: {e}")

    def show_builtin_rules(self):
        """显示内置规则"""
        rules = self.manager.get_builtin_rule_info()

        # 创建对话框
        dialog = tk.Toplevel(self.frame)
        dialog.title("内置 Yara 规则")
        dialog.geometry("600x400")

        # 规则列表
        columns = ('name', 'severity', 'description')
        tree = ttk.Treeview(dialog, columns=columns, show='headings')

        tree.heading('name', text='规则名称')
        tree.heading('severity', text='严重程度')
        tree.heading('description', text='描述')

        tree.column('name', width=200)
        tree.column('severity', width=80)
        tree.column('description', width=300)

        for rule in rules:
            severity = self.SEVERITY_NAMES.get(rule['severity'], rule['severity'])
            tree.insert('', tk.END, values=(rule['name'], severity, rule['description']),
                       tags=(rule['severity'],))

        tree.tag_configure('critical', foreground='#721c24', background='#f8d7da')
        tree.tag_configure('high', foreground='#856404', background='#ffeeba')
        tree.tag_configure('medium', foreground='#856404', background='#fff3cd')
        tree.tag_configure('low', foreground='#28a745')

        scrollbar = ttk.Scrollbar(dialog, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

        ttk.Button(dialog, text="关闭", command=dialog.destroy).pack(pady=5)

    def scan_selected_processes(self):
        """扫描选中的进程"""
        if not self.manager.rules_loaded:
            messagebox.showwarning("提示", "请先加载规则")
            return

        processes = self.get_selected_processes()
        if not processes:
            messagebox.showwarning("提示", "请先选择要扫描的进程")
            return

        self._start_process_scan(processes)

    def scan_all_processes(self):
        """扫描所有进程"""
        if not self.manager.rules_loaded:
            messagebox.showwarning("提示", "请先加载规则")
            return

        if not messagebox.askyesno("确认", f"确定要扫描所有 {len(self.processes)} 个进程吗？\n这可能需要较长时间。"):
            return

        self._start_process_scan(self.processes)

    def _start_process_scan(self, processes):
        """开始进程扫描"""
        if self.is_scanning:
            messagebox.showwarning("提示", "正在扫描中")
            return

        self.is_scanning = True
        self.manager.is_cancelled = False
        self.cancel_btn.configure(state='normal')
        self.progress_var.set(0)

        # 清空结果
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.manager.reset()

        self.log(f"🛡️ 开始 Yara 扫描 {len(processes)} 个进程...", self.output_widget)

        def scan():
            total = len(processes)
            for i, proc in enumerate(processes):
                if self.manager.is_cancelled:
                    break

                self.frame.after(0, lambda p=(i+1)/total*100: self.progress_var.set(p))
                self.frame.after(0, lambda n=proc['name'], pid=proc['pid']:
                    self.progress_label.configure(text=f"扫描: {n} (PID: {pid})"))

                try:
                    results = self.manager.scan_process(proc['pid'], proc['name'])

                    for r in results:
                        result_data = {
                            'rule_name': r.rule_name,
                            'severity': r.rule_meta.get('severity', 'medium'),
                            'target': r.target,
                            'target_type': r.target_type,
                            'description': r.rule_meta.get('description', ''),
                            'tags': r.rule_tags,
                            'strings': r.strings
                        }
                        self.frame.after(0, lambda rd=result_data: self._add_result(rd))

                except Exception as e:
                    self.frame.after(0, lambda n=proc['name'], err=str(e):
                        self.log(f"  ⚠️ {n}: {err}", self.output_widget))

            self.frame.after(0, self._scan_complete)

        threading.Thread(target=scan, daemon=True).start()

    def scan_path(self):
        """扫描文件/目录"""
        if not self.manager.rules_loaded:
            messagebox.showwarning("提示", "请先加载规则")
            return

        scan_path = self.scan_path_var.get().strip()
        if not scan_path:
            messagebox.showwarning("提示", "请指定扫描路径")
            return

        if not os.path.exists(scan_path):
            messagebox.showerror("错误", "路径不存在")
            return

        self._start_path_scan(scan_path)

    def _start_path_scan(self, scan_path):
        """开始路径扫描"""
        if self.is_scanning:
            messagebox.showwarning("提示", "正在扫描中")
            return

        self.is_scanning = True
        self.manager.is_cancelled = False
        self.cancel_btn.configure(state='normal')
        self.progress_var.set(0)

        # 清空结果
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.manager.reset()

        # 获取文件类型
        extensions = [ext.strip() for ext in self.file_types_var.get().split(',') if ext.strip()]

        self.log(f"🛡️ 开始 Yara 扫描: {scan_path}", self.output_widget)

        def scan():
            if os.path.isfile(scan_path):
                self.frame.after(0, lambda: self.progress_label.configure(
                    text=f"扫描: {os.path.basename(scan_path)}"))

                try:
                    results = self.manager.scan_file(scan_path)
                    for r in results:
                        result_data = {
                            'rule_name': r.rule_name,
                            'severity': r.rule_meta.get('severity', 'medium'),
                            'target': r.target,
                            'target_type': r.target_type,
                            'description': r.rule_meta.get('description', ''),
                            'tags': r.rule_tags,
                            'strings': r.strings
                        }
                        self.frame.after(0, lambda rd=result_data: self._add_result(rd))
                except Exception as e:
                    self.frame.after(0, lambda err=str(e):
                        self.log(f"  ❌ 扫描失败: {err}", self.output_widget))

            else:
                # 目录扫描
                def progress_callback(msg):
                    self.frame.after(0, lambda m=msg: self.progress_label.configure(text=m[:50]))

                try:
                    results = self.manager.scan_directory(scan_path, extensions, progress_callback)
                    for r in results:
                        result_data = {
                            'rule_name': r.rule_name,
                            'severity': r.rule_meta.get('severity', 'medium'),
                            'target': r.target,
                            'target_type': r.target_type,
                            'description': r.rule_meta.get('description', ''),
                            'tags': r.rule_tags,
                            'strings': r.strings
                        }
                        self.frame.after(0, lambda rd=result_data: self._add_result(rd))
                except Exception as e:
                    self.frame.after(0, lambda err=str(e):
                        self.log(f"  ❌ 扫描失败: {err}", self.output_widget))

            self.frame.after(0, self._scan_complete)

        threading.Thread(target=scan, daemon=True).start()

    def _add_result(self, result_data):
        """添加结果到列表"""
        severity = self.SEVERITY_NAMES.get(result_data['severity'], result_data['severity'])
        target_type = '进程' if result_data['target_type'] == 'process' else '文件'

        values = (
            result_data['rule_name'],
            severity,
            result_data['target'],
            target_type,
            result_data['description']
        )

        self.tree.insert('', tk.END, values=values, tags=(result_data['severity'],))

    def _scan_complete(self):
        """扫描完成"""
        self.is_scanning = False
        self.cancel_btn.configure(state='disabled')
        self.progress_var.set(100)
        self.progress_label.configure(text="扫描完成")

        summary = self.manager.get_summary()
        self.status_label.configure(
            text=f"状态: 完成 | 共 {summary['total_matches']} 个匹配 | "
                 f"严重: {summary['by_severity']['critical']} | "
                 f"高: {summary['by_severity']['high']} | "
                 f"中: {summary['by_severity']['medium']} | "
                 f"低: {summary['by_severity']['low']}"
        )

        self.log(f"✅ 扫描完成! 共发现 {summary['total_matches']} 个匹配", self.output_widget)

        if summary['by_severity']['critical'] > 0 or summary['by_severity']['high'] > 0:
            messagebox.showwarning("安全警告",
                f"发现高风险威胁!\n\n"
                f"严重: {summary['by_severity']['critical']} 个\n"
                f"高危: {summary['by_severity']['high']} 个\n\n"
                f"请仔细检查扫描结果。")

    def cancel_scan(self):
        """取消扫描"""
        if self.is_scanning:
            self.manager.cancel()
            self.log("⏹ 已取消扫描", self.output_widget)

    def clear_results(self):
        """清空结果"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.manager.reset()
        self.progress_var.set(0)
        self.progress_label.configure(text="就绪")
        self.status_label.configure(text="状态: 已清空结果")

    def copy_rule_name(self):
        """复制规则名称"""
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])['values']
            if values:
                self.tree.clipboard_clear()
                self.tree.clipboard_append(values[0])

    def copy_target(self):
        """复制目标路径"""
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])['values']
            if values and len(values) > 2:
                self.tree.clipboard_clear()
                self.tree.clipboard_append(values[2])

    def show_match_detail(self):
        """显示匹配详情"""
        selection = self.tree.selection()
        if not selection:
            return

        values = self.tree.item(selection[0])['values']
        if not values:
            return

        # 查找对应的结果
        rule_name = values[0]
        target = values[2]

        for result in self.manager.results:
            if result.rule_name == rule_name and result.target == target:
                detail = {
                    '规则名称': result.rule_name,
                    '标签': ', '.join(result.rule_tags) if result.rule_tags else '无',
                    '严重程度': result.rule_meta.get('severity', 'unknown'),
                    '描述': result.rule_meta.get('description', '无'),
                    '参考': result.rule_meta.get('reference', '无'),
                    '---1': '',
                    '目标': result.target,
                    '目标类型': '进程' if result.target_type == 'process' else '文件',
                    'PID': result.pid if result.pid else 'N/A',
                    '---2': '',
                    '匹配字符串': '\n'.join([f"  {s['identifier']}: {s['data']}" for s in result.strings[:10]]) if result.strings else '无'
                }
                self.show_detail_dialog(f"匹配详情 - {rule_name}", detail)
                break

    def search_rule_online(self):
        """在线搜索规则"""
        import webbrowser
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])['values']
            if values:
                rule_name = values[0]
                webbrowser.open(f"https://www.google.com/search?q=yara+rule+{rule_name}")

    def export_results(self):
        """导出结果"""
        if not self.manager.results:
            messagebox.showinfo("提示", "没有结果可导出")
            return

        file_path = filedialog.asksaveasfilename(
            title="导出结果",
            defaultextension=".json",
            filetypes=[
                ("JSON 文件", "*.json"),
                ("CSV 文件", "*.csv")
            ]
        )

        if file_path:
            ext = file_path.split('.')[-1].lower()
            if self.manager.export_results(file_path, ext):
                self.log(f"💾 结果已导出到: {file_path}", self.output_widget)
                messagebox.showinfo("成功", f"结果已导出到:\n{file_path}")
            else:
                messagebox.showerror("错误", "导出失败")
