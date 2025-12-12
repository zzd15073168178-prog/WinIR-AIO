#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DLL注入检测选项卡"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any
import threading
import os
from .base_tab import BaseTab
from console_logger import log_action, console_log


class DllTab(BaseTab):
    """DLL注入检测选项卡"""
    
    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.dll_data = []
        self.dll_search_var = None
        self.dll_stats_label = None
        self.current_pid = None
        super().__init__(parent, manager, "💉 DLL检测")
        # parent.add(self.frame, text=self.title)
    
    def setup_ui(self):
        """设置UI"""
        # 输入区
        input_frame = ttk.Frame(self.frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="进程PID:").pack(side=tk.LEFT, padx=5)
        self.dll_pid_entry = ttk.Entry(input_frame, width=15)
        self.dll_pid_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="检测DLL", command=self.check_dll).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="清空结果", command=self.clear_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="显示统计", command=self._show_stats).pack(side=tk.LEFT, padx=5)
        
        # 搜索框
        search_frame, self.dll_search_var = self.create_search_frame(
            self.frame, "过滤:", "输入关键词", width=30)
        self.dll_search_var.trace('w', lambda *a: self.filter_dll())
        
        # DLL列表
        list_frame = ttk.Frame(self.frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        columns = ('DLL路径', '基址', '大小', '版本', '状态')
        self.dll_tree = self.create_tree(list_frame, columns, height=18)
        
        self.dll_tree.column('DLL路径', width=400)
        self.dll_tree.column('基址', width=120)
        self.dll_tree.column('大小', width=100)
        self.dll_tree.column('版本', width=120)
        self.dll_tree.column('状态', width=80)
        
        self.dll_tree.tag_configure('suspicious', background='#ffcccc', foreground='red')
        self.dll_tree.tag_configure('system', background='#ccffcc', foreground='darkgreen')
        self.dll_tree.tag_configure('normal', background='white', foreground='black')
        
        scrollbar = self.add_scrollbar(list_frame, self.dll_tree)
        self.dll_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 右键菜单
        self._setup_context_menu()
        
        # 状态栏
        self.dll_stats_label = ttk.Label(self.frame, text="状态: 等待检测...")
        self.dll_stats_label.pack(pady=5)
    
    def _setup_context_menu(self):
        """设置右键菜单"""
        menu_items = [
            {'label': '📋 查看详情', 'command': self._show_detail},
            {'label': '📄 复制路径', 'command': self._copy_path},
            {'separator': True, 'label': '---'},
            {'label': '📁 打开文件位置', 'command': self._open_location},
            {'label': '🔍 查看文件属性', 'command': self._view_properties},
            {'separator': True, 'label': '---'},
            {'label': '📋 复制哈希值', 'command': self._copy_hash},
        ]
        self.setup_tree_context_menu(self.dll_tree, menu_items)
    
    def _on_double_click(self, tree):
        """双击查看详情"""
        self._show_detail()
    
    def check_dll(self):
        """检测DLL"""
        pid_str = self.dll_pid_entry.get().strip()
        if not pid_str:
            messagebox.showwarning("提示", "请输入进程PID")
            return
        
        try:
            pid = int(pid_str)
        except ValueError:
            messagebox.showwarning("错误", "PID必须是数字")
            return
        
        self.current_pid = pid
        self.dll_stats_label.configure(text=f"状态: 正在检测 PID {pid} 的DLL...")
        self.log(f"💉 开始检测 PID {pid} 的DLL注入...", self.output_widget)
        log_action("DLL检测", f"PID: {pid}")
        
        def check_thread():
            success, msg, dll_list = self.manager.check_dll_injection(pid)
            try:
                if self.frame.winfo_exists():
                    self.frame.after(0, lambda: self.display_results(success, msg, dll_list))
            except tk.TclError:
                pass

        threading.Thread(target=check_thread, daemon=True).start()
    
    def display_results(self, success, msg, dll_list):
        """显示结果"""
        if not success:
            self.log(f"❌ 检测失败: {msg}", self.output_widget)
            self.dll_stats_label.configure(text=f"状态: 检测失败 - {msg}")
            return
        
        self.dll_data = dll_list
        suspicious_count = len([d for d in dll_list if d.get('is_suspicious')])
        
        self.log(f"✅ 检测完成，找到 {len(dll_list)} 个DLL，可疑: {suspicious_count}", self.output_widget)
        
        if suspicious_count > 0:
            self.log(f"⚠️ 发现 {suspicious_count} 个可疑DLL!", self.output_widget)
        
        self.filter_dll()
    
    def filter_dll(self):
        """过滤DLL"""
        for item in self.dll_tree.get_children():
            self.dll_tree.delete(item)
        
        search = self.dll_search_var.get().strip().lower() if self.dll_search_var else ""
        suspicious_count = 0
        system_count = 0
        
        for dll in self.dll_data:
            path = dll.get('path', '')
            if search and search not in path.lower():
                continue
            
            # 确定标签
            if dll.get('is_suspicious'):
                tag = 'suspicious'
                suspicious_count += 1
            elif self._is_system_dll(path):
                tag = 'system'
                system_count += 1
            else:
                tag = 'normal'
            
            status = '可疑' if dll.get('is_suspicious') else '正常'
            
            self.dll_tree.insert('', tk.END, values=(
                path, dll.get('base_addr', 'N/A'), dll.get('size', 'N/A'),
                dll.get('version', 'N/A'), status
            ), tags=(tag,))
        
        # 更新状态
        total = len(self.dll_data)
        self.dll_stats_label.configure(
            text=f"总计: {total} | 系统DLL: {system_count} | 可疑: {suspicious_count}")
    
    def _is_system_dll(self, path):
        """判断是否为系统DLL"""
        if not path:
            return False
        path_upper = path.upper()
        system_paths = ['\\WINDOWS\\SYSTEM32', '\\WINDOWS\\SYSWOW64', '\\WINDOWS\\WINSXS']
        return any(sp in path_upper for sp in system_paths)
    
    def clear_list(self):
        """清空列表"""
        self.dll_data = []
        self.current_pid = None
        for item in self.dll_tree.get_children():
            self.dll_tree.delete(item)
        self.dll_stats_label.configure(text="状态: 等待检测...")
    
    def _get_selected_dll(self):
        """获取选中的DLL"""
        selection = self.dll_tree.selection()
        if not selection:
            return None
        item = self.dll_tree.item(selection[0])
        if item['values']:
            path = item['values'][0]
            return next((d for d in self.dll_data if d.get('path') == path), None)
        return None
    
    def _show_detail(self):
        """显示详情"""
        dll = self._get_selected_dll()
        if not dll:
            return
        
        path = dll.get('path', 'N/A')
        log_action("查看DLL详情", path)
        
        detail_data = {
            'DLL路径': path,
            '基址': dll.get('base_addr', 'N/A'),
            '大小': dll.get('size', 'N/A'),
            '版本': dll.get('version', 'N/A'),
            '状态': '可疑' if dll.get('is_suspicious') else '正常',
            '---1': '',
        }
        
        # 文件信息
        if os.path.exists(path):
            import stat
            from datetime import datetime
            st = os.stat(path)
            detail_data['文件大小'] = f"{st.st_size / 1024:.1f} KB"
            detail_data['创建时间'] = datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            detail_data['修改时间'] = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            detail_data['访问时间'] = datetime.fromtimestamp(st.st_atime).strftime('%Y-%m-%d %H:%M:%S')
            
            # 计算哈希
            try:
                import hashlib
                with open(path, 'rb') as f:
                    content = f.read()
                    detail_data['---2'] = ''
                    detail_data['MD5'] = hashlib.md5(content).hexdigest()
                    detail_data['SHA1'] = hashlib.sha1(content).hexdigest()
                    detail_data['SHA256'] = hashlib.sha256(content).hexdigest()
            except:
                pass
        
        self.show_detail_dialog(f"DLL详情 - {os.path.basename(path)}", detail_data)
    
    def _copy_path(self):
        """复制路径"""
        dll = self._get_selected_dll()
        if dll:
            path = dll.get('path', '')
            self.dll_tree.clipboard_clear()
            self.dll_tree.clipboard_append(path)
            self.log(f"📋 已复制路径: {path}", self.output_widget)
    
    def _copy_hash(self):
        """复制哈希"""
        dll = self._get_selected_dll()
        if not dll:
            return
        
        path = dll.get('path', '')
        if not os.path.exists(path):
            messagebox.showwarning("警告", "文件不存在")
            return
        
        try:
            import hashlib
            with open(path, 'rb') as f:
                md5 = hashlib.md5(f.read()).hexdigest()
            self.dll_tree.clipboard_clear()
            self.dll_tree.clipboard_append(md5)
            self.log(f"📋 已复制MD5: {md5}", self.output_widget)
        except Exception as e:
            messagebox.showerror("错误", f"计算哈希失败: {e}")
    
    def _open_location(self):
        """打开位置"""
        dll = self._get_selected_dll()
        if dll:
            self.open_file_location(dll.get('path', ''))
    
    def _view_properties(self):
        """查看属性"""
        dll = self._get_selected_dll()
        if not dll:
            return
        
        path = dll.get('path', '')
        if not os.path.exists(path):
            messagebox.showwarning("警告", "文件不存在")
            return
        
        try:
            import subprocess
            subprocess.run(['explorer', '/select,', path])
        except Exception as e:
            messagebox.showerror("错误", f"无法打开: {e}")
    
    def _show_stats(self):
        """显示统计"""
        if not self.dll_data:
            messagebox.showinfo("提示", "请先检测DLL")
            return
        
        total = len(self.dll_data)
        suspicious = len([d for d in self.dll_data if d.get('is_suspicious')])
        system = len([d for d in self.dll_data if self._is_system_dll(d.get('path', ''))])
        other = total - system
        
        # 按目录统计
        dirs = {}
        for dll in self.dll_data:
            path = dll.get('path', '')
            if path:
                dir_name = os.path.dirname(path)
                dirs[dir_name] = dirs.get(dir_name, 0) + 1
        
        stats = {
            '检测进程PID': self.current_pid,
            'DLL总数': total,
            '系统DLL': system,
            '其他DLL': other,
            '可疑DLL': f"{suspicious} ({'⚠️ 有可疑!' if suspicious > 0 else '✅ 无'})",
            '---1': '',
        }
        
        # 显示前5个目录
        sorted_dirs = sorted(dirs.items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (dir_path, count) in enumerate(sorted_dirs, 1):
            stats[f'目录{i}'] = f"{count}个 - {dir_path}"
        
        self.show_detail_dialog("DLL检测统计", stats)
