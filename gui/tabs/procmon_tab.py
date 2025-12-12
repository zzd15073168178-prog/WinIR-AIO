#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Procmon监控选项卡"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any
import threading
import os
from datetime import datetime
from .base_tab import BaseTab
from console_logger import log_action, console_log


class ProcmonTab(BaseTab):
    """Procmon监控选项卡"""
    
    def __init__(self, parent, manager: Any, output_widget):
        self.output_widget = output_widget
        self.log_files = []
        self.procmon_start_btn = None
        self.procmon_stop_btn = None
        self.procmon_status_label = None
        super().__init__(parent, manager, "📊 Procmon监控")
        # parent.add(self.frame, text=self.title)
    
    def setup_ui(self):
        """设置UI"""
        # 控制按钮
        btn_frame = self.create_button_frame(self.frame)
        
        self.procmon_start_btn = ttk.Button(btn_frame, text="启动监控", command=self.start_procmon)
        self.procmon_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.procmon_stop_btn = ttk.Button(btn_frame, text="停止监控", command=self.stop_procmon, state=tk.DISABLED)
        self.procmon_stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="打开日志目录", command=self.open_procmon_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="刷新列表", command=self.refresh_list).pack(side=tk.LEFT, padx=5)
        
        # 状态显示
        self.procmon_status_label = ttk.Label(self.frame, text="状态: 未启动", font=("微软雅黑", 12, "bold"))
        self.procmon_status_label.pack(pady=5)
        
        # 日志文件列表
        list_frame_container = ttk.LabelFrame(self.frame, text="已保存的监控日志", padding=5)
        list_frame_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
        list_frame = ttk.Frame(list_frame_container)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('文件名', '大小', '创建时间', '路径')
        self.log_tree = self.create_tree(list_frame, columns, height=10)
        
        self.log_tree.column('文件名', width=200)
        self.log_tree.column('大小', width=100)
        self.log_tree.column('创建时间', width=150)
        self.log_tree.column('路径', width=400)
        
        scrollbar = self.add_scrollbar(list_frame, self.log_tree)
        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 右键菜单
        self._setup_context_menu()
        
        # 说明
        info_text = "Procmon监控说明：实时监控系统活动。点击启动监控开始记录，停止监控结束并保存日志。日志文件(.pml)可用Procmon.exe打开查看。"
        info_label = ttk.Label(self.frame, text=info_text, wraplength=800)
        info_label.pack(pady=5)
        
        self.refresh_list()
    
    def _setup_context_menu(self):
        """设置右键菜单"""
        menu_items = [
            {'label': '📋 查看详情', 'command': self._show_detail},
            {'label': '📄 复制路径', 'command': self._copy_path},
            {'separator': True, 'label': '---'},
            {'label': '📂 打开文件位置', 'command': self._open_location},
            {'label': '▶️ 用Procmon打开', 'command': self._open_with_procmon},
            {'separator': True, 'label': '---'},
            {'label': '🗑️ 删除文件', 'command': self._delete_file},
        ]
        self.setup_tree_context_menu(self.log_tree, menu_items)
    
    def _on_double_click(self, tree):
        """双击查看详情"""
        self._show_detail()
    
    def refresh_list(self):
        """刷新日志文件列表"""
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        
        from constants import PROCMON_LOGS_DIR
        from utils.filesystem import ensure_directory
        
        ensure_directory(PROCMON_LOGS_DIR)
        self.log_files = []
        
        if os.path.exists(PROCMON_LOGS_DIR):
            for f in os.listdir(PROCMON_LOGS_DIR):
                if f.endswith('.pml') or f.endswith('.csv'):
                    path = os.path.join(PROCMON_LOGS_DIR, f)
                    st = os.stat(path)
                    size = f"{st.st_size / 1024 / 1024:.1f} MB" if st.st_size > 1024*1024 else f"{st.st_size / 1024:.1f} KB"
                    ctime = datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    
                    self.log_files.append({
                        'name': f, 'size': size, 'ctime': ctime, 'path': path
                    })
                    
                    self.log_tree.insert('', tk.END, values=(f, size, ctime, path))
        
        self.log(f"📊 找到 {len(self.log_files)} 个监控日志", self.output_widget)
    
    def start_procmon(self):
        """启动Procmon监控"""
        self.log("📊 启动Procmon监控...", self.output_widget)
        log_action("启动监控", "")
        
        def start_thread():
            success, message, log_file = self.manager.start_monitor()
            self.frame.after(0, lambda: self.update_procmon_status(success, message, log_file, True))
        
        threading.Thread(target=start_thread, daemon=True).start()
    
    def stop_procmon(self):
        """停止Procmon监控"""
        self.log("📊 停止Procmon监控...", self.output_widget)
        log_action("停止监控", "")
        
        def stop_thread():
            success, message, log_file = self.manager.stop_monitor()
            self.frame.after(0, lambda: self.update_procmon_status(success, message, log_file, False))
        
        threading.Thread(target=stop_thread, daemon=True).start()
    
    def update_procmon_status(self, success, message, log_file, is_running):
        """更新Procmon状态"""
        if success:
            self.log(f"✅ {message}", self.output_widget)
            if log_file:
                self.log(f"📁 日志文件: {log_file}", self.output_widget)
            
            if is_running:
                self.procmon_status_label.configure(text="状态: 监控中...", foreground='green')
                self.procmon_start_btn.configure(state=tk.DISABLED)
                self.procmon_stop_btn.configure(state=tk.NORMAL)
            else:
                self.procmon_status_label.configure(text="状态: 已停止", foreground='black')
                self.procmon_start_btn.configure(state=tk.NORMAL)
                self.procmon_stop_btn.configure(state=tk.DISABLED)
                self.refresh_list()
        else:
            self.log(f"❌ {message}", self.output_widget)
    
    def _get_selected_file(self):
        """获取选中的文件"""
        selection = self.log_tree.selection()
        if not selection:
            return None
        item = self.log_tree.item(selection[0])
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
            detail_data['---2'] = ''
            detail_data['文件类型'] = '.pml (Procmon日志)' if path.endswith('.pml') else '.csv (CSV格式)'
        
        self.show_detail_dialog(f"监控日志详情 - {file['name']}", detail_data)
    
    def _copy_path(self):
        """复制路径"""
        file = self._get_selected_file()
        if file:
            self.log_tree.clipboard_clear()
            self.log_tree.clipboard_append(file['path'])
            self.log(f"📋 已复制路径: {file['path']}", self.output_widget)
    
    def _open_location(self):
        """打开位置"""
        file = self._get_selected_file()
        if file:
            self.open_file_location(file['path'])
    
    def _open_with_procmon(self):
        """用Procmon打开"""
        file = self._get_selected_file()
        if not file:
            return
        
        if not file['name'].endswith('.pml'):
            messagebox.showinfo("提示", "只有.pml文件可以用Procmon打开")
            return
        
        from constants import TOOLS
        procmon_path = TOOLS.get('procmon')
        
        if not os.path.exists(procmon_path):
            messagebox.showerror("错误", f"Procmon.exe未找到: {procmon_path}")
            return
        
        try:
            import subprocess
            subprocess.Popen([procmon_path, '/OpenLog', file['path']])
            self.log(f"▶️ 正在用Procmon打开: {file['name']}", self.output_widget)
        except Exception as e:
            messagebox.showerror("错误", f"打开失败: {e}")
    
    def _delete_file(self):
        """删除文件"""
        file = self._get_selected_file()
        if not file:
            return
        
        if messagebox.askyesno("确认删除", f"确定要删除日志文件 {file['name']} 吗?"):
            try:
                os.remove(file['path'])
                self.log(f"🗑️ 已删除: {file['name']}", self.output_widget)
                self.refresh_list()
            except Exception as e:
                messagebox.showerror("错误", f"删除失败: {e}")
    
    def open_procmon_logs(self):
        """打开Procmon日志目录"""
        from utils.filesystem import ensure_directory
        from constants import PROCMON_LOGS_DIR
        
        ensure_directory(PROCMON_LOGS_DIR)
        os.startfile(PROCMON_LOGS_DIR)
