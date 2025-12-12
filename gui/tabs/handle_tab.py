#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""句柄查询选项卡"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any
import threading
import os
from .base_tab import BaseTab
from console_logger import log_action, console_log


class HandleTab(BaseTab):
    """句柄查询选项卡"""
    
    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.handle_data = []
        self.handle_search_var = None
        self.handle_stats_label = None
        self.current_pid = None
        super().__init__(parent, manager, "🔧 句柄查询")
        # parent.add(self.frame, text=self.title)
    
    def setup_ui(self):
        """设置UI"""
        # 输入区
        input_frame = ttk.Frame(self.frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="进程PID:").pack(side=tk.LEFT, padx=5)
        self.handle_pid_entry = ttk.Entry(input_frame, width=15)
        self.handle_pid_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(input_frame, text="类型过滤:").pack(side=tk.LEFT, padx=5)
        self.handle_filter = ttk.Combobox(input_frame, width=12,
            values=['全部', 'File', 'Key', 'Event', 'Section', 'Mutant', 'Directory', 'Process', 'Thread'])
        self.handle_filter.set('全部')
        self.handle_filter.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="查询句柄", command=self.query_handles).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="清空结果", command=self.clear_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="显示统计", command=self._show_stats).pack(side=tk.LEFT, padx=5)
        
        # 搜索框
        search_frame, self.handle_search_var = self.create_search_frame(
            self.frame, "过滤:", "输入关键词", width=30)
        self.handle_search_var.trace('w', lambda *a: self.filter_handles())
        
        # 句柄列表
        list_frame = ttk.Frame(self.frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        columns = ('类型', '句柄值', '名称/路径')
        self.handle_tree = self.create_tree(list_frame, columns, height=18)
        
        self.handle_tree.column('类型', width=100)
        self.handle_tree.column('句柄值', width=100)
        self.handle_tree.column('名称/路径', width=600)
        
        self.handle_tree.tag_configure('file', background='#cce5ff', foreground='darkblue')
        self.handle_tree.tag_configure('key', background='#ffe0cc', foreground='darkorange')
        self.handle_tree.tag_configure('event', background='#ccffcc', foreground='darkgreen')
        self.handle_tree.tag_configure('mutex', background='#e5ccff', foreground='purple')
        self.handle_tree.tag_configure('other', background='white', foreground='black')
        
        scrollbar = self.add_scrollbar(list_frame, self.handle_tree)
        self.handle_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 右键菜单
        self._setup_context_menu()
        
        # 状态栏
        self.handle_stats_label = ttk.Label(self.frame, text="状态: 等待查询...")
        self.handle_stats_label.pack(pady=5)
    
    def _setup_context_menu(self):
        """设置右键菜单"""
        menu_items = [
            {'label': '📋 查看详情', 'command': self._show_detail},
            {'label': '📄 复制信息', 'command': self._copy_info},
            {'separator': True, 'label': '---'},
            {'label': '📁 打开路径位置', 'command': self._open_location},
            {'separator': True, 'label': '---'},
            {'label': '📋 复制句柄值', 'command': lambda: self._copy_column(1)},
            {'label': '📋 复制名称/路径', 'command': lambda: self._copy_column(2)},
        ]
        self.setup_tree_context_menu(self.handle_tree, menu_items)
    
    def _on_double_click(self, tree):
        """双击查看详情"""
        self._show_detail()
    
    def query_handles(self):
        """查询句柄"""
        pid_str = self.handle_pid_entry.get().strip()
        if not pid_str:
            messagebox.showwarning("提示", "请输入进程PID")
            return
        
        try:
            pid = int(pid_str)
        except ValueError:
            messagebox.showwarning("错误", "PID必须是数字")
            return
        
        filter_type = self.handle_filter.get()
        if filter_type == '全部':
            filter_type = None
        
        self.current_pid = pid
        self.handle_stats_label.configure(text=f"状态: 正在查询 PID {pid} 的句柄...")
        self.log(f"🔧 开始查询 PID {pid} 的句柄...", self.output_widget)
        log_action("句柄查询", f"PID: {pid}, 过滤: {filter_type or '全部'}")
        
        def query_thread():
            success, msg, handles = self.manager.query_handles(pid, filter_type)
            self.frame.after(0, lambda: self.display_results(success, msg, handles))
        
        threading.Thread(target=query_thread, daemon=True).start()
    
    def display_results(self, success, msg, handles):
        """显示结果"""
        if not success:
            self.log(f"❌ 查询失败: {msg}", self.output_widget)
            self.handle_stats_label.configure(text=f"状态: 查询失败 - {msg}")
            return
        
        self.handle_data = handles
        self.log(f"✅ 查询完成，找到 {len(handles)} 个句柄", self.output_widget)
        self.filter_handles()
    
    def filter_handles(self):
        """过滤句柄"""
        for item in self.handle_tree.get_children():
            self.handle_tree.delete(item)
        
        search = self.handle_search_var.get().strip().lower() if self.handle_search_var else ""
        type_counts = {}
        
        for h in self.handle_data:
            h_type = h.get('type', '')
            h_name = h.get('name', '')
            
            if search and search not in f"{h_type} {h_name}".lower():
                continue
            
            type_counts[h_type] = type_counts.get(h_type, 0) + 1
            
            # 确定标签
            if h_type == 'File':
                tag = 'file'
            elif h_type == 'Key':
                tag = 'key'
            elif h_type == 'Event':
                tag = 'event'
            elif h_type in ['Mutant', 'Mutex']:
                tag = 'mutex'
            else:
                tag = 'other'
            
            self.handle_tree.insert('', tk.END, values=(
                h_type, h.get('value', 'N/A'), h_name
            ), tags=(tag,))
        
        # 更新状态
        total = len(self.handle_data)
        stats_parts = [f"总计: {total}"]
        for t in ['File', 'Key', 'Event', 'Mutant']:
            if t in type_counts:
                stats_parts.append(f"{t}: {type_counts[t]}")
        
        self.handle_stats_label.configure(text=" | ".join(stats_parts))
    
    def clear_list(self):
        """清空列表"""
        self.handle_data = []
        self.current_pid = None
        for item in self.handle_tree.get_children():
            self.handle_tree.delete(item)
        self.handle_stats_label.configure(text="状态: 等待查询...")
    
    def _get_selected_handle(self):
        """获取选中的句柄"""
        selection = self.handle_tree.selection()
        if not selection:
            return None
        item = self.handle_tree.item(selection[0])
        if item['values']:
            return {
                'type': item['values'][0],
                'value': item['values'][1],
                'name': item['values'][2]
            }
        return None
    
    def _show_detail(self):
        """显示详情"""
        handle = self._get_selected_handle()
        if not handle:
            return
        
        log_action("查看句柄详情", handle.get('name', ''))
        
        detail_data = {
            '句柄类型': handle.get('type'),
            '句柄值': handle.get('value'),
            '名称/路径': handle.get('name'),
            '---1': '',
            '所属进程PID': self.current_pid,
        }
        
        # 如果是文件类型，获取更多信息
        name = handle.get('name', '')
        if handle.get('type') == 'File' and name and os.path.exists(name):
            from datetime import datetime
            st = os.stat(name)
            detail_data['---2'] = ''
            detail_data['文件大小'] = f"{st.st_size / 1024:.1f} KB"
            detail_data['创建时间'] = datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            detail_data['修改时间'] = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        self.show_detail_dialog("句柄详情", detail_data)
    
    def _copy_info(self):
        """复制信息"""
        handle = self._get_selected_handle()
        if handle:
            text = f"类型: {handle['type']}\n句柄值: {handle['value']}\n名称: {handle['name']}"
            self.handle_tree.clipboard_clear()
            self.handle_tree.clipboard_append(text)
            log_action("复制句柄信息", "")
    
    def _copy_column(self, col_idx):
        """复制指定列"""
        selection = self.handle_tree.selection()
        if selection:
            item = self.handle_tree.item(selection[0])
            if item['values'] and len(item['values']) > col_idx:
                self.handle_tree.clipboard_clear()
                self.handle_tree.clipboard_append(str(item['values'][col_idx]))
    
    def _open_location(self):
        """打开位置"""
        handle = self._get_selected_handle()
        if not handle:
            return
        
        name = handle.get('name', '')
        if handle.get('type') == 'File' and name:
            if os.path.exists(name):
                self.open_file_location(name)
            else:
                messagebox.showwarning("警告", f"路径不存在: {name}")
    
    def _show_stats(self):
        """显示统计"""
        if not self.handle_data:
            messagebox.showinfo("提示", "请先查询句柄")
            return
        
        total = len(self.handle_data)
        type_counts = {}
        for h in self.handle_data:
            t = h.get('type', 'Unknown')
            type_counts[t] = type_counts.get(t, 0) + 1
        
        stats = {
            '查询进程PID': self.current_pid,
            '句柄总数': total,
            '---1': '',
        }
        
        # 按类型统计
        for t, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            stats[f'类型-{t}'] = count
        
        self.show_detail_dialog("句柄查询统计", stats)
