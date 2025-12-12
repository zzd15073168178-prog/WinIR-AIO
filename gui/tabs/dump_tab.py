#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进程转储选项卡"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any
import threading
import os
from datetime import datetime
from .base_tab import BaseTab
from console_logger import log_action, console_log


class DumpTab(BaseTab):
    """进程转储选项卡"""
    
    def __init__(self, parent, manager: Any, output_widget):
        self.output_widget = output_widget
        self.dump_files = []
        super().__init__(parent, manager, "💾 进程转储")
        # parent.add(self.frame, text=self.title)
    
    def setup_ui(self):
        """设置UI"""
        # 输入区域
        input_frame = ttk.Frame(self.frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="进程PID:").pack(side=tk.LEFT, padx=5)
        self.dump_pid_entry = ttk.Entry(input_frame, width=15)
        self.dump_pid_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(input_frame, text="转储类型:").pack(side=tk.LEFT, padx=5)
        self.dump_type = ttk.Combobox(input_frame, width=10, values=['mini', 'full'])
        self.dump_type.set('mini')
        self.dump_type.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="创建转储", command=self.create_dump).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="打开转储目录", command=self.open_dumps_dir).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="刷新列表", command=self.refresh_list).pack(side=tk.LEFT, padx=5)
        
        # 转储文件列表
        list_frame_container = ttk.LabelFrame(self.frame, text="已保存的转储文件", padding=5)
        list_frame_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
        list_frame = ttk.Frame(list_frame_container)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('文件名', '大小', '创建时间', '路径')
        self.dump_tree = self.create_tree(list_frame, columns, height=12)
        
        self.dump_tree.column('文件名', width=200)
        self.dump_tree.column('大小', width=100)
        self.dump_tree.column('创建时间', width=150)
        self.dump_tree.column('路径', width=400)
        
        scrollbar = self.add_scrollbar(list_frame, self.dump_tree)
        self.dump_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 右键菜单
        self._setup_context_menu()
        
        # 说明
        info_text = """转储说明：Mini转储包含基本信息，文件较小；Full转储包含完整内存，文件较大。转储文件保存在 dumps/ 目录。"""
        info_label = ttk.Label(self.frame, text=info_text, wraplength=800)
        info_label.pack(pady=5)
        
        self.refresh_list()
    
    def _setup_context_menu(self):
        """设置右键菜单"""
        menu_items = [
            {'label': '📋 查看详情', 'command': self._show_detail},
            {'label': '📄 复制路径', 'command': self._copy_path},
            {'separator': True, 'label': '---'},
            {'label': '📁 打开文件位置', 'command': self._open_location},
            {'separator': True, 'label': '---'},
            {'label': '🗑️ 删除文件', 'command': self._delete_file},
        ]
        self.setup_tree_context_menu(self.dump_tree, menu_items)
    
    def _on_double_click(self, tree):
        """双击查看详情"""
        self._show_detail()
    
    def refresh_list(self):
        """刷新转储文件列表"""
        for item in self.dump_tree.get_children():
            self.dump_tree.delete(item)
        
        from constants import DUMPS_DIR
        from utils.filesystem import ensure_directory
        
        ensure_directory(DUMPS_DIR)
        self.dump_files = []
        
        if os.path.exists(DUMPS_DIR):
            for f in os.listdir(DUMPS_DIR):
                if f.endswith('.dmp'):
                    path = os.path.join(DUMPS_DIR, f)
                    st = os.stat(path)
                    size = f"{st.st_size / 1024 / 1024:.1f} MB"
                    ctime = datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    
                    self.dump_files.append({
                        'name': f, 'size': size, 'ctime': ctime, 'path': path
                    })
                    
                    self.dump_tree.insert('', tk.END, values=(f, size, ctime, path))
        
        self.log(f"💾 找到 {len(self.dump_files)} 个转储文件", self.output_widget)
    
    def create_dump(self):
        """创建进程转储"""
        pid_str = self.dump_pid_entry.get().strip()
        
        if not pid_str:
            messagebox.showwarning("提示", "请输入进程PID")
            return
        
        try:
            pid = int(pid_str)
        except ValueError:
            messagebox.showwarning("错误", "PID必须是数字")
            return
        
        dump_type = self.dump_type.get()
        
        self.log(f"💾 创建进程 {pid} 的转储（类型: {dump_type}）...", self.output_widget)
        log_action("创建转储", f"PID: {pid}, 类型: {dump_type}")
        
        def dump_thread():
            success, message, dump_file = self.manager.create_dump(pid, dump_type=dump_type)
            try:
                if self.frame.winfo_exists():
                    self.frame.after(0, lambda: self.display_dump_result(success, message, dump_file))
            except tk.TclError:
                pass

        threading.Thread(target=dump_thread, daemon=True).start()
    
    def display_dump_result(self, success, message, dump_file):
        """显示转储结果"""
        if success:
            self.log(f"✅ {message}", self.output_widget)
            self.log(f"📁 文件: {dump_file}", self.output_widget)
            self.refresh_list()
        else:
            self.log(f"❌ {message}", self.output_widget)
    
    def _get_selected_file(self):
        """获取选中的文件"""
        selection = self.dump_tree.selection()
        if not selection:
            return None
        item = self.dump_tree.item(selection[0])
        if item['values']:
            return {'name': item['values'][0], 'size': item['values'][1],
                    'ctime': item['values'][2], 'path': item['values'][3]}
        return None
    
    def _show_detail(self):
        """显示详情"""
        file = self._get_selected_file()
        if not file:
            return
        
        path = file['path']
        detail_data = {
            '文件名': file['name'],
            '文件大小': file['size'],
            '创建时间': file['ctime'],
            '完整路径': path,
        }
        
        if os.path.exists(path):
            st = os.stat(path)
            detail_data['---1'] = ''
            detail_data['实际大小'] = f"{st.st_size:,} 字节"
            detail_data['修改时间'] = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        self.show_detail_dialog(f"转储文件详情 - {file['name']}", detail_data)
    
    def _copy_path(self):
        """复制路径"""
        file = self._get_selected_file()
        if file:
            self.dump_tree.clipboard_clear()
            self.dump_tree.clipboard_append(file['path'])
            self.log(f"📋 已复制路径: {file['path']}", self.output_widget)
    
    def _open_location(self):
        """打开位置"""
        file = self._get_selected_file()
        if file:
            self.open_file_location(file['path'])
    
    def _delete_file(self):
        """删除文件"""
        file = self._get_selected_file()
        if not file:
            return
        
        if messagebox.askyesno("确认删除", f"确定要删除转储文件 {file['name']} 吗?"):
            try:
                os.remove(file['path'])
                self.log(f"🗑️ 已删除: {file['name']}", self.output_widget)
                self.refresh_list()
            except Exception as e:
                messagebox.showerror("错误", f"删除失败: {e}")
    
    def open_dumps_dir(self):
        """打开转储目录"""
        from utils.filesystem import ensure_directory
        from constants import DUMPS_DIR
        
        ensure_directory(DUMPS_DIR)
        os.startfile(DUMPS_DIR)
