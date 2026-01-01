#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进程内存扫描选项卡"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import psutil
import sys
import os

# 添加父目录到路径以导入 memory_scanner_v2
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from memory_scanner_v2 import MemoryScannerV2, ScanResultV2

from .base_tab import BaseTab


class MemoryScannerTab(BaseTab):
    """进程内存扫描选项卡"""

    # 类别中文映射
    CATEGORY_NAMES = {
        'ipv4': 'IPv4 地址',
        'ipv6': 'IPv6 地址',
        'url': 'URL',
        'domain': '可疑域名',
        'email': '邮箱地址',
        'base64_long': 'Base64 数据',
        'powershell': 'PowerShell 命令',
        'cmd_exec': 'CMD 命令',
        'credential_keyword': '凭据关键字',
        'private_key': '私钥',
        'bitcoin_addr': '比特币地址',
        'registry_path': '注册表路径',
        'windows_path': '可执行文件路径',
        'unc_path': 'UNC 路径',
        'shell_code': 'Shellcode',
        'mimikatz': 'Mimikatz',
        'cobalt_strike': 'Cobalt Strike',
        'metasploit': 'Metasploit',
        'custom': '自定义规则',
    }

    RISK_NAMES = {
        'low': '低',
        'medium': '中',
        'high': '高',
        'critical': '严重',
    }

    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.is_scanning = False
        self.processes = []
        self._current_scanner_v2 = None  # V2 扫描器实例
        super().__init__(parent, manager, "🔬 内存扫描")

    def setup_ui(self):
        """设置 UI"""
        # 顶部说明
        info_frame = ttk.LabelFrame(self.frame, text="功能说明", padding=5)
        info_frame.pack(fill=tk.X, padx=5, pady=5)

        info_text = ("扫描进程内存中的可疑字符串：IP地址、URL、C2特征、凭据、Shellcode等。\n"
                    "适用于：恶意软件分析、内存取证、威胁狩猎、应急响应等场景。")
        ttk.Label(info_frame, text=info_text, foreground='#666').pack(anchor=tk.W)

        # 进程选择区域
        select_frame = ttk.LabelFrame(self.frame, text="进程选择", padding=5)
        select_frame.pack(fill=tk.X, padx=5, pady=5)

        # 进程列表 (左侧)
        left_frame = ttk.Frame(select_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        proc_toolbar = ttk.Frame(left_frame)
        proc_toolbar.pack(fill=tk.X)

        ttk.Button(proc_toolbar, text="🔄 刷新进程", command=self.refresh_processes).pack(side=tk.LEFT, padx=2)

        ttk.Label(proc_toolbar, text="搜索:").pack(side=tk.LEFT, padx=(10, 2))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(proc_toolbar, textvariable=self.search_var, width=20)
        search_entry.pack(side=tk.LEFT, padx=2)
        self.search_var.trace('w', lambda *a: self.filter_processes())

        # 进程列表
        proc_list_frame = ttk.Frame(left_frame)
        proc_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.proc_listbox = tk.Listbox(proc_list_frame, selectmode=tk.EXTENDED, height=6,
                                        exportselection=False)
        proc_scrollbar = ttk.Scrollbar(proc_list_frame, orient=tk.VERTICAL,
                                        command=self.proc_listbox.yview)
        self.proc_listbox.configure(yscrollcommand=proc_scrollbar.set)

        self.proc_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        proc_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 扫描选项 (右侧)
        right_frame = ttk.LabelFrame(select_frame, text="扫描选项", padding=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))

        # 类别选择
        ttk.Label(right_frame, text="扫描类别:").pack(anchor=tk.W)

        self.category_vars = {}
        categories_frame = ttk.Frame(right_frame)
        categories_frame.pack(fill=tk.X, pady=2)

        # 分两列显示
        col1 = ttk.Frame(categories_frame)
        col1.pack(side=tk.LEFT, padx=5)
        col2 = ttk.Frame(categories_frame)
        col2.pack(side=tk.LEFT, padx=5)

        important_cats = ['ipv4', 'url', 'domain', 'powershell', 'cmd_exec',
                          'credential_keyword', 'shell_code', 'mimikatz', 'cobalt_strike']

        for i, (cat, name) in enumerate(self.CATEGORY_NAMES.items()):
            if cat == 'custom':
                continue
            var = tk.BooleanVar(value=(cat in important_cats))
            self.category_vars[cat] = var
            parent_col = col1 if i < 9 else col2
            ttk.Checkbutton(parent_col, text=name, variable=var).pack(anchor=tk.W)

        # 快捷按钮
        btn_frame = ttk.Frame(right_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="全选", command=self.select_all_categories, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="取消", command=self.deselect_all_categories, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="推荐", command=self.select_recommended, width=6).pack(side=tk.LEFT, padx=2)

        # 自定义搜索区域 (使用 memory_scanner_v2)
        custom_frame = ttk.LabelFrame(self.frame, text="自定义字符串搜索 (V2 增强版)", padding=5)
        custom_frame.pack(fill=tk.X, padx=5, pady=5)

        custom_row1 = ttk.Frame(custom_frame)
        custom_row1.pack(fill=tk.X, pady=2)

        ttk.Label(custom_row1, text="搜索字符串:").pack(side=tk.LEFT, padx=(0, 5))
        self.custom_string_var = tk.StringVar()
        custom_entry = ttk.Entry(custom_row1, textvariable=self.custom_string_var, width=40)
        custom_entry.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)

        # 搜索模式选择
        ttk.Label(custom_row1, text="模式:").pack(side=tk.LEFT, padx=(10, 5))
        self.search_mode_var = tk.StringVar(value="full")
        mode_combo = ttk.Combobox(custom_row1, textvariable=self.search_mode_var,
                                   values=["full", "simple"], width=8, state="readonly")
        mode_combo.pack(side=tk.LEFT, padx=2)

        ttk.Button(custom_row1, text="🔍 搜索选中进程", command=self.search_custom_string).pack(side=tk.LEFT, padx=5)
        ttk.Button(custom_row1, text="🔍 搜索全部进程", command=self.search_custom_all).pack(side=tk.LEFT, padx=2)

        custom_row2 = ttk.Frame(custom_frame)
        custom_row2.pack(fill=tk.X, pady=2)

        ttk.Label(custom_row2, text="模式说明: full=全面(UTF-8+UTF-16+大小写), simple=简单(仅UTF-8,区分大小写,与Go版一致)",
                  foreground='#666').pack(anchor=tk.W)

        # 操作按钮
        action_frame = ttk.Frame(self.frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(action_frame, text="🔍 扫描选中进程", command=self.scan_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(action_frame, text="🔍 扫描所有进程", command=self.scan_all).pack(side=tk.LEFT, padx=3)

        ttk.Separator(action_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        self.cancel_btn = ttk.Button(action_frame, text="⏹ 取消", command=self.cancel_scan, state='disabled')
        self.cancel_btn.pack(side=tk.LEFT, padx=3)

        ttk.Button(action_frame, text="🧹 清空结果", command=self.clear_results).pack(side=tk.LEFT, padx=3)
        ttk.Button(action_frame, text="💾 导出结果", command=self.export_results).pack(side=tk.LEFT, padx=3)

        # 进度条区域 - 更加醒目
        progress_frame = ttk.LabelFrame(self.frame, text="扫描进度", padding=5)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)

        # 第一行：进度条和百分比
        progress_row1 = ttk.Frame(progress_frame)
        progress_row1.pack(fill=tk.X, pady=(0, 3))

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_row1, variable=self.progress_var,
                                            maximum=100, mode='determinate', length=400)
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 10))

        # 百分比标签
        self.percent_label = ttk.Label(progress_row1, text="0%", font=('Consolas', 10, 'bold'), width=6)
        self.percent_label.pack(side=tk.RIGHT)

        # 第二行：当前扫描状态
        progress_row2 = ttk.Frame(progress_frame)
        progress_row2.pack(fill=tk.X)

        ttk.Label(progress_row2, text="状态:", foreground='#666').pack(side=tk.LEFT)
        self.progress_label = ttk.Label(progress_row2, text="就绪", foreground='#333')
        self.progress_label.pack(side=tk.LEFT, padx=5)

        # 已扫描/总数
        self.scan_count_label = ttk.Label(progress_row2, text="", foreground='#666')
        self.scan_count_label.pack(side=tk.RIGHT)

        # 结果列表
        result_frame = ttk.LabelFrame(self.frame, text="扫描结果", padding=5)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ('process', 'category', 'risk', 'value', 'address')
        self.tree = ttk.Treeview(result_frame, columns=columns, show='headings', height=10)

        self.tree.heading('process', text='进程')
        self.tree.heading('category', text='类别')
        self.tree.heading('risk', text='风险')
        self.tree.heading('value', text='发现内容')
        self.tree.heading('address', text='内存地址')

        self.tree.column('process', width=150)
        self.tree.column('category', width=120)
        self.tree.column('risk', width=60)
        self.tree.column('value', width=400)
        self.tree.column('address', width=120)

        # 风险等级颜色
        self.tree.tag_configure('low', foreground='#28a745')
        self.tree.tag_configure('medium', foreground='#856404', background='#fff3cd')
        self.tree.tag_configure('high', foreground='#856404', background='#ffeeba')
        self.tree.tag_configure('critical', foreground='#721c24', background='#f8d7da')

        scrollbar_y = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(result_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        # 右键菜单
        self._setup_context_menu()

        # 状态栏
        self.status_label = ttk.Label(self.frame, text="状态: 就绪 | 选择进程后开始扫描")
        self.status_label.pack(pady=5)

        # 加载进程列表
        self.refresh_processes()

    def _setup_context_menu(self):
        """设置右键菜单"""
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="📋 复制内容", command=self.copy_value)
        self.context_menu.add_command(label="📋 复制整行", command=self.copy_row)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🔍 VirusTotal 查询", command=self.search_virustotal)
        self.context_menu.add_command(label="🌐 在线搜索", command=self.search_online)

        self.tree.bind('<Button-3>', self._show_context_menu)
        self.tree.bind('<Double-1>', lambda e: self.show_detail())

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

            # 按名称排序
            self.processes.sort(key=lambda x: x['name'].lower())

            for proc in self.processes:
                self.proc_listbox.insert(tk.END, f"{proc['name']} (PID: {proc['pid']})")

            self.log(f"🔄 已刷新进程列表，共 {len(self.processes)} 个进程", self.output_widget)
        except Exception as e:
            self.log(f"❌ 刷新进程失败: {e}", self.output_widget)

    def filter_processes(self):
        """过滤进程列表"""
        search = self.search_var.get().strip().lower()
        self.proc_listbox.delete(0, tk.END)

        for proc in self.processes:
            if search in proc['name'].lower() or search in str(proc['pid']):
                self.proc_listbox.insert(tk.END, f"{proc['name']} (PID: {proc['pid']})")

    def select_all_categories(self):
        """全选类别"""
        for var in self.category_vars.values():
            var.set(True)

    def deselect_all_categories(self):
        """取消全选"""
        for var in self.category_vars.values():
            var.set(False)

    def select_recommended(self):
        """选择推荐类别"""
        recommended = ['ipv4', 'url', 'domain', 'powershell', 'cmd_exec',
                       'credential_keyword', 'shell_code', 'mimikatz', 'cobalt_strike', 'metasploit']
        for cat, var in self.category_vars.items():
            var.set(cat in recommended)

    def get_selected_categories(self):
        """获取选中的类别"""
        return [cat for cat, var in self.category_vars.items() if var.get()]

    def get_selected_processes(self):
        """获取选中的进程"""
        indices = self.proc_listbox.curselection()
        selected = []

        # 需要从过滤后的列表中获取
        search = self.search_var.get().strip().lower()
        filtered = [p for p in self.processes
                   if search in p['name'].lower() or search in str(p['pid'])]

        for i in indices:
            if i < len(filtered):
                selected.append(filtered[i])

        return selected

    def scan_selected(self):
        """扫描选中的进程"""
        processes = self.get_selected_processes()
        if not processes:
            messagebox.showwarning("提示", "请先选择要扫描的进程")
            return

        self._start_scan(processes)

    def scan_all(self):
        """扫描所有进程"""
        if not messagebox.askyesno("确认", f"确定要扫描所有 {len(self.processes)} 个进程吗？\n这可能需要较长时间。"):
            return

        self._start_scan(self.processes)

    def _start_scan(self, processes):
        """开始扫描"""
        if self.is_scanning:
            messagebox.showwarning("提示", "正在扫描中")
            return

        categories = self.get_selected_categories()

        # 自定义规则（使用自定义搜索框的内容）
        custom_patterns = None
        custom = self.custom_string_var.get().strip()
        if custom:
            import re
            # 支持逗号分隔多个搜索词
            terms = [s.strip() for s in custom.split(',') if s.strip()]
            if terms:
                custom_patterns = {term: re.escape(term).encode('utf-8') for term in terms}

        # 如果没有选择类别，也没有自定义搜索词，则提示
        if not categories and not custom_patterns:
            messagebox.showwarning("提示", "请选择扫描类别，或在自定义正则框中输入搜索内容")
            return

        self.is_scanning = True
        self.cancel_btn.configure(state='normal')
        self.progress_var.set(0)

        # 清空结果
        for item in self.tree.get_children():
            self.tree.delete(item)

        # 日志输出
        log_msg = f"🔬 开始扫描 {len(processes)} 个进程..."
        self.log(log_msg, self.output_widget)
        if categories:
            self.log(f"  扫描类别: {', '.join(categories)}", self.output_widget)
        if custom:
            self.log(f"  自定义搜索: {custom}", self.output_widget)

        def scan():
            total = len(processes)
            for i, proc in enumerate(processes):
                if self.manager.is_cancelled:
                    break

                # 计算进度百分比
                progress = (i + 1) / total * 100

                # 更新进度条和百分比
                self.safe_after(lambda p=progress: self.progress_var.set(p))
                self.safe_after(lambda p=progress: self.percent_label.configure(text=f"{p:.0f}%"))
                self.safe_after(lambda n=proc['name'], pid=proc['pid']:
                    self.progress_label.configure(text=f"扫描: {n} (PID: {pid})"))
                self.safe_after(lambda cur=i+1, tot=total:
                    self.scan_count_label.configure(text=f"进度: {cur}/{tot}"))

                try:
                    results = self.manager.scan_process(
                        proc['pid'], proc['name'],
                        categories=categories,
                        custom_patterns=custom_patterns
                    )

                    # 添加到结果列表
                    for r in results:
                        self.safe_after(self._add_result, r)

                except Exception as e:
                    self.safe_after(lambda n=proc['name'], err=str(e):
                        self.log(f"  ⚠️ {n}: {err}", self.output_widget))

            self.safe_after(self._scan_complete)

        threading.Thread(target=scan, daemon=True).start()

    def _add_result(self, result):
        """添加结果到列表"""
        cat_name = self.CATEGORY_NAMES.get(result.category, result.category)
        risk_name = self.RISK_NAMES.get(result.risk_level, result.risk_level)

        values = (
            f"{result.process_name} ({result.pid})",
            cat_name,
            risk_name,
            result.value[:100],  # 限制长度
            hex(result.address)
        )

        self.tree.insert('', tk.END, values=values, tags=(result.risk_level,))

    def _scan_complete(self):
        """扫描完成"""
        self.is_scanning = False
        self.cancel_btn.configure(state='disabled')
        self.progress_var.set(100)
        self.percent_label.configure(text="100%")
        self.progress_label.configure(text="扫描完成")
        self.scan_count_label.configure(text="")

        summary = self.manager.get_summary()
        self.status_label.configure(
            text=f"状态: 完成 | 共 {summary['total']} 个发现 | "
                 f"严重: {summary['by_risk']['critical']} | "
                 f"高: {summary['by_risk']['high']} | "
                 f"中: {summary['by_risk']['medium']} | "
                 f"低: {summary['by_risk']['low']}"
        )

        self.log(f"✅ 扫描完成! 共发现 {summary['total']} 个可疑内容", self.output_widget)

        if summary['by_risk']['critical'] > 0 or summary['by_risk']['high'] > 0:
            messagebox.showwarning("安全警告",
                f"发现高风险内容!\n\n"
                f"严重: {summary['by_risk']['critical']} 个\n"
                f"高危: {summary['by_risk']['high']} 个\n\n"
                f"请仔细检查扫描结果。")

    def cancel_scan(self):
        """取消扫描"""
        if self.is_scanning:
            self.manager.cancel()
            # 同时取消 V2 扫描器（如果存在）
            if hasattr(self, '_current_scanner_v2') and self._current_scanner_v2:
                self._current_scanner_v2.cancel()
            self.log("⏹ 已取消扫描", self.output_widget)

    def clear_results(self):
        """清空结果"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.manager.results = []
        self.progress_var.set(0)
        self.percent_label.configure(text="0%")
        self.progress_label.configure(text="就绪")
        self.scan_count_label.configure(text="")
        self.status_label.configure(text="状态: 就绪 | 选择进程后开始扫描")

    def show_detail(self):
        """显示详情"""
        selection = self.tree.selection()
        if not selection:
            return

        values = self.tree.item(selection[0])['values']
        if not values:
            return

        # 查找对应的结果
        for result in self.manager.results:
            if hex(result.address) == values[4]:
                detail = {
                    '进程': f"{result.process_name} (PID: {result.pid})",
                    '类别': self.CATEGORY_NAMES.get(result.category, result.category),
                    '风险等级': self.RISK_NAMES.get(result.risk_level, result.risk_level),
                    '---1': '',
                    '发现内容': result.value,
                    '内存地址': hex(result.address),
                    '---2': '',
                    '上下文': result.context,
                }
                self.show_detail_dialog(f"详情 - {result.category}", detail)
                break

    def copy_value(self):
        """复制内容"""
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])['values']
            if values and len(values) > 3:
                self.tree.clipboard_clear()
                self.tree.clipboard_append(values[3])

    def copy_row(self):
        """复制整行"""
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])['values']
            if values:
                text = ' | '.join(str(v) for v in values)
                self.tree.clipboard_clear()
                self.tree.clipboard_append(text)

    def search_virustotal(self):
        """VirusTotal 查询"""
        import webbrowser
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])['values']
            if values and len(values) > 3:
                value = values[3]
                # 如果是 IP 或域名，直接搜索
                webbrowser.open(f"https://www.virustotal.com/gui/search/{value}")

    def search_online(self):
        """在线搜索"""
        import webbrowser
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])['values']
            if values and len(values) > 3:
                value = values[3]
                webbrowser.open(f"https://www.google.com/search?q={value}")

    def export_results(self):
        """导出结果"""
        if not self.manager.results:
            messagebox.showinfo("提示", "没有结果可导出")
            return

        file_path = filedialog.asksaveasfilename(
            title="导出结果",
            defaultextension=".csv",
            filetypes=[
                ("CSV 文件", "*.csv"),
                ("JSON 文件", "*.json")
            ]
        )

        if file_path:
            ext = file_path.split('.')[-1].lower()
            if self.manager.export_results(file_path, ext):
                self.log(f"💾 结果已导出到: {file_path}", self.output_widget)
                messagebox.showinfo("成功", f"结果已导出到:\n{file_path}")
            else:
                messagebox.showerror("错误", "导出失败")

    def search_custom_string(self):
        """搜索自定义字符串 - 选中进程"""
        processes = self.get_selected_processes()
        if not processes:
            messagebox.showwarning("提示", "请先选择要搜索的进程")
            return
        self._start_custom_search(processes)

    def search_custom_all(self):
        """搜索自定义字符串 - 所有进程"""
        if not messagebox.askyesno("确认", f"确定要在所有 {len(self.processes)} 个进程中搜索吗？\n这可能需要较长时间。"):
            return
        self._start_custom_search(self.processes)

    def _start_custom_search(self, processes):
        """开始自定义字符串搜索 (使用 MemoryScannerV2)"""
        search_str = self.custom_string_var.get().strip()
        if not search_str:
            messagebox.showwarning("提示", "请输入要搜索的字符串")
            return

        if self.is_scanning:
            messagebox.showwarning("提示", "正在扫描中")
            return

        # 解析搜索字符串（支持逗号分隔多个）
        search_terms = [s.strip() for s in search_str.split(',') if s.strip()]
        if not search_terms:
            messagebox.showwarning("提示", "请输入有效的搜索字符串")
            return

        # 获取搜索模式
        search_mode = self.search_mode_var.get()
        mode_desc = "简单模式 (UTF-8, 区分大小写)" if search_mode == "simple" else "全面模式 (UTF-8 + UTF-16LE + 大小写)"

        self.is_scanning = True
        self.cancel_btn.configure(state='normal')
        self.progress_var.set(0)

        # 清空结果
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.manager.results = []

        self.log(f"🔍 开始自定义搜索 (V2 增强版)", self.output_widget)
        self.log(f"  搜索字符串: {', '.join(search_terms)}", self.output_widget)
        self.log(f"  搜索模式: {mode_desc}", self.output_widget)
        self.log(f"  搜索 {len(processes)} 个进程...", self.output_widget)

        # 创建 V2 扫描器实例
        scanner_v2 = MemoryScannerV2()
        self._current_scanner_v2 = scanner_v2  # 保存引用以便取消

        # 检查 SeDebugPrivilege
        if scanner_v2.is_debug_privilege_enabled():
            self.log(f"  ✓ SeDebugPrivilege 已启用", self.output_widget)
        else:
            self.log(f"  ⚠ SeDebugPrivilege 未启用（可能需要管理员权限）", self.output_widget)

        # 用于收集所有结果的列表
        all_results = []

        # 构建 PID 列表
        target_pids = {proc['pid'] for proc in processes}

        def search():
            total = len(processes)
            total_ops = total * len(search_terms)
            processed = 0

            def progress_callback(msg):
                # 更新进度标签
                self.safe_after(lambda m=msg: self.progress_label.configure(text=m[:50]))

            # 对每个搜索词进行搜索
            for term_idx, term in enumerate(search_terms):
                if scanner_v2.is_cancelled:
                    break

                self.safe_after(lambda t=term: self.log(f"  → 搜索: {t}", self.output_widget))

                # 遍历每个进程
                for i, proc in enumerate(processes):
                    if scanner_v2.is_cancelled:
                        break

                    pid = proc['pid']
                    name = proc['name']

                    # 计算总进度
                    current_op = term_idx * total + i + 1
                    progress = current_op / total_ops * 100

                    # 更新进度条和百分比
                    self.safe_after(lambda p=progress: self.progress_var.set(p))
                    self.safe_after(lambda p=progress: self.percent_label.configure(text=f"{p:.0f}%"))
                    self.safe_after(lambda n=name, p=pid:
                        self.progress_label.configure(text=f"搜索: {n} (PID: {p})"))
                    self.safe_after(lambda cur=current_op, tot=total_ops:
                        self.scan_count_label.configure(text=f"进度: {cur}/{tot}"))

                    try:
                        # 使用 V2 扫描器搜索单个进程
                        results = scanner_v2.search_string(
                            term,
                            target_pid=pid,
                            progress_callback=None,  # 不使用回调避免过多输出
                            search_mode=search_mode
                        )

                        # 添加结果到 UI
                        for r in results:
                            result_data = {
                                'process_name': r.process_name,
                                'pid': r.pid,
                                'value': r.match_content,
                                'address': r.match_address,
                                'path': r.process_path,
                                'network': r.network_connections,
                                'search_term': term
                            }
                            all_results.append(result_data)
                            self.safe_after(self._add_v2_result, result_data)

                    except Exception as e:
                        self.safe_after(lambda n=name, err=str(e):
                            self.log(f"  ⚠️ {n}: {err}", self.output_widget))

            self.safe_after(lambda: self._custom_search_complete(len(all_results)))

        threading.Thread(target=search, daemon=True).start()

    def _add_custom_result(self, result):
        """添加自定义搜索结果（对象版本）"""
        values = (
            f"{result.process_name} ({result.pid})",
            "自定义搜索",
            "命中",
            result.value[:100],
            hex(result.address)
        )
        self.tree.insert('', tk.END, values=values, tags=('high',))
        self.manager.results.append(result)

    def _add_v2_result(self, result_data):
        """添加 V2 扫描器结果"""
        values = (
            f"{result_data['process_name']} ({result_data['pid']})",
            f"搜索: {result_data.get('search_term', '自定义')}",
            "命中",
            result_data['value'][:100] if result_data['value'] else '',
            hex(result_data['address']) if result_data['address'] else '0x0'
        )
        self.tree.insert('', tk.END, values=values, tags=('high',))

        # 创建兼容的 ScanResult 对象以便导出
        from memory_scanner import ScanResult
        scan_result = ScanResult(
            pid=result_data['pid'],
            process_name=result_data['process_name'],
            category='custom_search',
            value=result_data['value'],
            context=f"路径: {result_data.get('path', '')}\n网络: {result_data.get('network', '')}",
            address=result_data['address'],
            risk_level='high'
        )
        self.manager.results.append(scan_result)

    def _add_custom_result_dict(self, result_data):
        """添加自定义搜索结果（字典版本，用于线程安全）"""
        from memory_scanner import ScanResult

        values = (
            f"{result_data['process_name']} ({result_data['pid']})",
            "自定义搜索",
            "命中",
            result_data['value'][:100] if result_data['value'] else '',
            hex(result_data['address'])
        )
        self.tree.insert('', tk.END, values=values, tags=('high',))

        # 重建 ScanResult 对象并添加到 manager.results
        scan_result = ScanResult(
            pid=result_data['pid'],
            process_name=result_data['process_name'],
            category=result_data['category'],
            value=result_data['value'],
            context=result_data['context'],
            address=result_data['address'],
            risk_level=result_data['risk_level']
        )
        self.manager.results.append(scan_result)

    def _custom_search_complete(self, count):
        """自定义搜索完成"""
        self.is_scanning = False
        self.cancel_btn.configure(state='disabled')
        self.progress_var.set(100)
        self.percent_label.configure(text="100%")
        self.progress_label.configure(text="搜索完成")
        self.scan_count_label.configure(text="")

        self.status_label.configure(text=f"状态: 搜索完成 | 共找到 {count} 个匹配项")
        self.log(f"✅ 搜索完成! 共找到 {count} 个匹配项", self.output_widget)

        if count > 0:
            messagebox.showinfo("搜索完成", f"在进程内存中找到 {count} 个匹配项！\n\n请检查结果列表。")
