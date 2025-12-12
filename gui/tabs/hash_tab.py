#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文件 Hash 计算选项卡"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os

from .base_tab import BaseTab


class HashTab(BaseTab):
    """文件 Hash 计算选项卡"""

    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.is_calculating = False
        super().__init__(parent, manager, "🔢 Hash 计算")

    def setup_ui(self):
        """设置 UI"""
        # 顶部工具栏
        toolbar = ttk.Frame(self.frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="📄 选择文件", command=self.select_file).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="📁 选择文件夹", command=self.select_folder).pack(side=tk.LEFT, padx=3)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        ttk.Button(toolbar, text="🧹 清空结果", command=self.clear_results).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="💾 导出结果", command=self.export_results).pack(side=tk.LEFT, padx=3)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        self.cancel_btn = ttk.Button(toolbar, text="⏹ 取消", command=self.cancel_calculation, state='disabled')
        self.cancel_btn.pack(side=tk.LEFT, padx=3)

        # 选项区域
        options_frame = ttk.LabelFrame(self.frame, text="选项", padding=5)
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        # 算法选择
        algo_frame = ttk.Frame(options_frame)
        algo_frame.pack(fill=tk.X, pady=2)

        ttk.Label(algo_frame, text="Hash 算法:").pack(side=tk.LEFT, padx=5)

        self.algo_vars = {}
        for algo in ['MD5', 'SHA1', 'SHA256', 'SHA512']:
            var = tk.BooleanVar(value=(algo in ['MD5', 'SHA256']))  # 默认选中 MD5 和 SHA256
            self.algo_vars[algo] = var
            ttk.Checkbutton(algo_frame, text=algo, variable=var).pack(side=tk.LEFT, padx=5)

        # 文件夹选项
        folder_options = ttk.Frame(options_frame)
        folder_options.pack(fill=tk.X, pady=2)

        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(folder_options, text="递归子目录", variable=self.recursive_var).pack(side=tk.LEFT, padx=5)

        ttk.Label(folder_options, text="线程数:").pack(side=tk.LEFT, padx=(20, 5))
        self.thread_var = tk.StringVar(value='4')
        thread_combo = ttk.Combobox(folder_options, textvariable=self.thread_var,
                                     values=['1', '2', '4', '8', '16'], width=5, state='readonly')
        thread_combo.pack(side=tk.LEFT, padx=2)

        ttk.Label(folder_options, text="扩展名过滤:").pack(side=tk.LEFT, padx=(20, 5))
        self.ext_var = tk.StringVar(value='')
        ext_entry = ttk.Entry(folder_options, textvariable=self.ext_var, width=25)
        ext_entry.pack(side=tk.LEFT, padx=2)
        ttk.Label(folder_options, text="(如: .exe,.dll 留空=全部)").pack(side=tk.LEFT, padx=2)

        # 进度条
        progress_frame = ttk.Frame(self.frame)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                            maximum=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 10))

        self.progress_label = ttk.Label(progress_frame, text="就绪", width=30)
        self.progress_label.pack(side=tk.RIGHT)

        # 结果列表
        list_frame = ttk.Frame(self.frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ('name', 'size', 'md5', 'sha256', 'status')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)

        self.tree.heading('name', text='文件名')
        self.tree.heading('size', text='大小')
        self.tree.heading('md5', text='MD5')
        self.tree.heading('sha256', text='SHA256')
        self.tree.heading('status', text='状态')

        self.tree.column('name', width=200)
        self.tree.column('size', width=80)
        self.tree.column('md5', width=250)
        self.tree.column('sha256', width=450)
        self.tree.column('status', width=80)

        # 颜色标签
        self.tree.tag_configure('success', foreground='#155724')
        self.tree.tag_configure('error', foreground='#721c24', background='#f8d7da')

        scrollbar_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定事件
        self.tree.bind('<Double-1>', lambda e: self.show_detail())
        self._setup_context_menu()

        # 状态栏
        self.status_label = ttk.Label(self.frame, text="状态: 就绪 | 选择文件或文件夹开始计算")
        self.status_label.pack(pady=5)

    def _setup_context_menu(self):
        """设置右键菜单"""
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="📋 查看详情", command=self.show_detail)
        self.context_menu.add_command(label="📄 复制 MD5", command=lambda: self.copy_hash('MD5'))
        self.context_menu.add_command(label="📄 复制 SHA1", command=lambda: self.copy_hash('SHA1'))
        self.context_menu.add_command(label="📄 复制 SHA256", command=lambda: self.copy_hash('SHA256'))
        self.context_menu.add_command(label="📄 复制 SHA512", command=lambda: self.copy_hash('SHA512'))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📁 打开文件位置", command=self.open_location)
        self.context_menu.add_command(label="🔍 VirusTotal 查询", command=self.check_virustotal)

        self.tree.bind('<Button-3>', self._show_context_menu)

    def _show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def get_selected_algorithms(self):
        """获取选中的算法"""
        return [algo for algo, var in self.algo_vars.items() if var.get()]

    def get_file_extensions(self):
        """获取文件扩展名过滤"""
        ext_str = self.ext_var.get().strip()
        if not ext_str:
            return None
        exts = [e.strip() for e in ext_str.split(',')]
        return [e if e.startswith('.') else f'.{e}' for e in exts if e]

    def select_file(self):
        """选择单个文件"""
        file_path = filedialog.askopenfilename(title="选择文件")
        if file_path:
            self.calculate_single_file(file_path)

    def select_folder(self):
        """选择文件夹"""
        folder_path = filedialog.askdirectory(title="选择文件夹")
        if folder_path:
            self.calculate_folder(folder_path)

    def calculate_single_file(self, file_path):
        """计算单个文件"""
        if self.is_calculating:
            messagebox.showwarning("提示", "正在计算中，请等待完成")
            return

        algorithms = self.get_selected_algorithms()
        if not algorithms:
            messagebox.showwarning("提示", "请至少选择一个 Hash 算法")
            return

        self.is_calculating = True
        self.progress_label.configure(text="计算中...")
        self.log(f"🔢 开始计算文件 Hash: {file_path}", self.output_widget)

        def calculate():
            result = self.manager.calculate_file_hash(file_path, algorithms)
            self.manager.results = [result]
            self.safe_after(lambda: self._calculation_complete([result]))

        threading.Thread(target=calculate, daemon=True).start()

    def calculate_folder(self, folder_path):
        """计算文件夹"""
        if self.is_calculating:
            messagebox.showwarning("提示", "正在计算中，请等待完成")
            return

        algorithms = self.get_selected_algorithms()
        if not algorithms:
            messagebox.showwarning("提示", "请至少选择一个 Hash 算法")
            return

        self.is_calculating = True
        self.cancel_btn.configure(state='normal')
        self.progress_var.set(0)
        self.progress_label.configure(text="扫描文件中...")
        self.log(f"🔢 开始计算文件夹 Hash: {folder_path}", self.output_widget)

        def progress_callback(current, total, file_path):
            percent = (current / total * 100) if total > 0 else 0
            self.safe_after(lambda: self.progress_var.set(percent))
            self.safe_after(lambda p=file_path, c=current, t=total:
                self.progress_label.configure(text=f"{c}/{t} - {os.path.basename(p)[:30]}"))

        def calculate():
            results = self.manager.calculate_folder_hash(
                folder_path,
                algorithms=algorithms,
                recursive=self.recursive_var.get(),
                max_workers=int(self.thread_var.get()),
                progress_callback=progress_callback,
                file_extensions=self.get_file_extensions()
            )
            self.safe_after(lambda: self._calculation_complete(results))

        threading.Thread(target=calculate, daemon=True).start()

    def _calculation_complete(self, results):
        """计算完成"""
        self.is_calculating = False
        self.cancel_btn.configure(state='disabled')
        self.progress_var.set(100)

        # 清空并填充结果
        for item in self.tree.get_children():
            self.tree.delete(item)

        for result in results:
            tag = 'error' if result['error'] else 'success'
            status = result['error'] if result['error'] else '✓ 完成'

            values = (
                result['name'],
                result['size_str'],
                result['MD5'][:32] if result['MD5'] else '-',
                result['SHA256'][:64] if result['SHA256'] else '-',
                status
            )
            self.tree.insert('', tk.END, values=values, tags=(tag,))

        # 更新状态
        summary = self.manager.get_summary()
        self.status_label.configure(
            text=f"状态: 完成 | 共 {summary['total']} 个文件 | "
                 f"成功 {summary['success']} | 失败 {summary['failed']} | "
                 f"总大小 {summary['total_size_str']}"
        )
        self.progress_label.configure(text="计算完成")

        self.log(f"✅ Hash 计算完成! 共 {summary['total']} 个文件", self.output_widget)
        if summary['failed'] > 0:
            self.log(f"⚠️ {summary['failed']} 个文件计算失败", self.output_widget)

    def cancel_calculation(self):
        """取消计算"""
        if self.is_calculating:
            self.manager.cancel()
            self.log("⏹ 已取消计算", self.output_widget)

    def clear_results(self):
        """清空结果"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.manager.results = []
        self.progress_var.set(0)
        self.progress_label.configure(text="就绪")
        self.status_label.configure(text="状态: 就绪 | 选择文件或文件夹开始计算")

    def _get_selected_result(self):
        """获取选中的结果"""
        selection = self.tree.selection()
        if not selection:
            return None

        values = self.tree.item(selection[0])['values']
        if not values:
            return None

        # 根据文件名查找完整结果
        name = values[0]
        for result in self.manager.results:
            if result['name'] == name:
                return result
        return None

    def show_detail(self):
        """显示详情"""
        result = self._get_selected_result()
        if not result:
            return

        detail = {
            '文件名': result['name'],
            '完整路径': result['path'],
            '文件大小': f"{result['size_str']} ({result['size']} 字节)",
            '---1': '',
            'MD5': result['MD5'] or '-',
            'SHA1': result['SHA1'] or '-',
            'SHA256': result['SHA256'] or '-',
            'SHA512': result['SHA512'] or '-',
        }

        if result['error']:
            detail['---2'] = ''
            detail['错误'] = result['error']

        self.show_detail_dialog(f"Hash 详情 - {result['name']}", detail)

    def copy_hash(self, algorithm):
        """复制指定的 Hash 值"""
        result = self._get_selected_result()
        if not result:
            return

        hash_value = result.get(algorithm, '')
        if hash_value:
            self.tree.clipboard_clear()
            self.tree.clipboard_append(hash_value)
            self.log(f"📋 已复制 {algorithm}: {hash_value}", self.output_widget)
        else:
            messagebox.showinfo("提示", f"没有 {algorithm} 值")

    def open_location(self):
        """打开文件位置"""
        result = self._get_selected_result()
        if result and result['path'] and os.path.exists(result['path']):
            folder = os.path.dirname(result['path'])
            os.startfile(folder)

    def check_virustotal(self):
        """VirusTotal 查询"""
        import webbrowser
        result = self._get_selected_result()
        if result:
            if result['SHA256']:
                webbrowser.open(f"https://www.virustotal.com/gui/file/{result['SHA256']}")
            elif result['MD5']:
                webbrowser.open(f"https://www.virustotal.com/gui/file/{result['MD5']}")
            else:
                messagebox.showinfo("提示", "没有 Hash 值，无法查询 VirusTotal")

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
                ("文本文件", "*.txt"),
                ("JSON 文件", "*.json")
            ]
        )

        if file_path:
            ext = os.path.splitext(file_path)[1].lower()
            format_map = {'.csv': 'csv', '.txt': 'txt', '.json': 'json'}
            format_type = format_map.get(ext, 'csv')

            if self.manager.export_results(file_path, format_type):
                self.log(f"💾 结果已导出到: {file_path}", self.output_widget)
                messagebox.showinfo("成功", f"结果已导出到:\n{file_path}")
            else:
                messagebox.showerror("错误", "导出失败")
