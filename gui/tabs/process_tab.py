#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进程列表选项卡"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any
from datetime import datetime
from .base_tab import BaseTab
from console_logger import log_action, console_log


class ProcessTab(BaseTab):
    """进程列表选项卡"""
    
    def __init__(self, parent, manager: Any, output_widget):
        self.output_widget = output_widget
        self.process_data = []
        self.process_sort_column = None
        self.process_sort_reverse = False
        self.process_search_var = None
        super().__init__(parent, manager, "📋 进程列表")
        # parent.add(self.frame, text=self.title) # No longer needed as we pass the tab frame directly
    
    def setup_ui(self):
        """设置UI"""
        # 搜索框
        search_frame, self.process_search_var = self.create_search_frame(
            self.frame, "搜索:", "输入PID或进程名", width=30)
        self.process_search_var.trace('w', lambda *args: self.filter_processes())
        
        # 按钮
        btn_frame = self.create_button_frame(self.frame)
        ttk.Button(btn_frame, text="刷新列表", command=self.refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="显示统计", command=self._show_stats).pack(side=tk.LEFT, padx=5)
        
        # 进程列表
        list_frame = ttk.Frame(self.frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('PID', '进程名', 'CPU%', '内存(MB)', '状态', '用户')
        self.process_tree = self.create_tree(list_frame, columns, height=20)
        
        self.process_tree.column('PID', width=70)
        self.process_tree.column('进程名', width=200)
        self.process_tree.column('CPU%', width=70)
        self.process_tree.column('内存(MB)', width=90)
        self.process_tree.column('状态', width=80)
        self.process_tree.column('用户', width=150)
        
        # 排序
        for col in columns:
            self.process_tree.heading(col, text=col, command=lambda c=col: self.sort_process_tree(c))
        
        # 颜色标签
        self.process_tree.tag_configure('high_cpu', background='#ffcccc', foreground='red')
        self.process_tree.tag_configure('high_mem', background='#ffe0cc', foreground='darkorange')
        self.process_tree.tag_configure('normal', background='white', foreground='black')
        
        scrollbar = self.add_scrollbar(list_frame, self.process_tree)
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 右键菜单
        self._setup_context_menu()
        # 延迟刷新，避免阻塞启动
        self.frame.after(100, self.refresh)
    
    def _setup_context_menu(self):
        """设置右键菜单"""
        menu_items = [
            {'label': '📋 查看详情', 'command': self._show_process_detail},
            {'label': '📄 复制信息', 'command': self._copy_process_info},
            {'separator': True, 'label': '---'},
            {'label': '🔍 检测DLL注入', 'command': self._check_dll},
            {'label': '🔧 查询句柄', 'command': self._query_handle},
            {'label': '🌐 查看网络连接', 'command': self._view_network},
            {'label': '💾 转储进程', 'command': self._dump_process},
            {'separator': True, 'label': '---'},
            {'label': '📁 打开文件位置', 'command': self._open_process_location},
            {'separator': True, 'label': '---'},
            {'label': '❌ 结束进程', 'command': self._kill_process},
        ]
        self.setup_tree_context_menu(self.process_tree, menu_items)
    
    def _on_double_click(self, tree):
        """双击查看详情"""
        self._show_process_detail()
    
    def refresh(self):
        """刷新进程列表"""
        processes = self.manager.get_all_processes()
        self.process_data = processes
        self.log(f"📋 找到 {len(processes)} 个进程", self.output_widget)
        self.filter_processes()
    
    def filter_processes(self):
        """过滤进程"""
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        search_text = self.process_search_var.get().strip().lower() if self.process_search_var else ""
        
        for proc in self.process_data:
            if search_text:
                if search_text not in str(proc['pid']) and search_text not in proc['name'].lower():
                    continue
            
            # 确定标签颜色
            if proc['cpu_percent'] > 50:
                tag = 'high_cpu'
            elif proc['memory_mb'] > 500:
                tag = 'high_mem'
            else:
                tag = 'normal'
            
            username = proc.get('username', 'N/A')
            if username and '\\' in username:
                username = username.split('\\')[-1]
            
            self.process_tree.insert('', tk.END, values=(
                proc['pid'], proc['name'], f"{proc['cpu_percent']:.1f}",
                f"{proc['memory_mb']:.1f}", proc['status'], username
            ), tags=(tag,))
    
    def sort_process_tree(self, col: str):
        """排序"""
        if self.process_sort_column == col:
            self.process_sort_reverse = not self.process_sort_reverse
        else:
            self.process_sort_column = col
            self.process_sort_reverse = False
        
        sort_keys = {
            'PID': 'pid', '进程名': 'name', 'CPU%': 'cpu_percent',
            '内存(MB)': 'memory_mb', '状态': 'status', '用户': 'username'
        }
        if col in sort_keys:
            key = sort_keys[col]
            self.process_data.sort(
                key=lambda x: (x.get(key) or '') if key in ['name', 'status', 'username'] else (x.get(key) or 0),
                reverse=self.process_sort_reverse
            )
        self.filter_processes()
        
        # 更新标题箭头
        for c in ['PID', '进程名', 'CPU%', '内存(MB)', '状态', '用户']:
            arrow = ' ▼' if c == col and self.process_sort_reverse else (' ▲' if c == col else '')
            self.process_tree.heading(c, text=c + arrow)
    
    def _show_process_detail(self):
        """显示进程详情"""
        pid = self._get_selected_pid()
        if not pid:
            return
        
        log_action("查看进程详情", f"PID: {pid}")
        proc_data = next((p for p in self.process_data if p['pid'] == pid), None)
        if not proc_data:
            return
        
        import psutil
        detail_data = {
            'PID': proc_data['pid'],
            '进程名': proc_data['name'],
            'CPU使用率': f"{proc_data['cpu_percent']:.1f}%",
            '内存使用': f"{proc_data['memory_mb']:.1f} MB",
            '状态': proc_data['status'],
            '---1': '',
        }
        
        try:
            p = psutil.Process(pid)
            detail_data['创建时间'] = datetime.fromtimestamp(p.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            detail_data['命令行'] = ' '.join(p.cmdline()) if p.cmdline() else 'N/A'
            detail_data['可执行路径'] = p.exe() if hasattr(p, 'exe') else 'N/A'
            detail_data['工作目录'] = p.cwd() if hasattr(p, 'cwd') else 'N/A'
            detail_data['---2'] = ''
            detail_data['父进程PID'] = p.ppid()
            detail_data['线程数'] = p.num_threads()
            detail_data['用户'] = p.username() if hasattr(p, 'username') else 'N/A'
            
            mem_info = p.memory_info()
            detail_data['---3'] = ''
            detail_data['虚拟内存'] = f"{mem_info.vms / 1024 / 1024:.1f} MB"
            detail_data['物理内存'] = f"{mem_info.rss / 1024 / 1024:.1f} MB"
            
            try:
                io = p.io_counters()
                detail_data['IO读取'] = f"{io.read_bytes / 1024 / 1024:.1f} MB"
                detail_data['IO写入'] = f"{io.write_bytes / 1024 / 1024:.1f} MB"
            except:
                pass
        except Exception as e:
            detail_data['错误'] = str(e)
        
        self.show_detail_dialog(f"进程详情 - {proc_data['name']}", detail_data)
    
    def _copy_process_info(self):
        """复制进程信息"""
        self.copy_selected_to_clipboard(self.process_tree, ['PID', '进程名', 'CPU%', '内存(MB)', '状态', '用户'])
    
    def _check_dll(self):
        """检测DLL"""
        pid = self._get_selected_pid()
        if pid:
            self.log(f"💉 请在DLL检测选项卡中输入PID: {pid}", self.output_widget)
            log_action("DLL检测请求", f"PID: {pid}")
    
    def _query_handle(self):
        """查询句柄"""
        pid = self._get_selected_pid()
        if pid:
            self.log(f"🔧 请在句柄查询选项卡中输入PID: {pid}", self.output_widget)
            log_action("句柄查询请求", f"PID: {pid}")
    
    def _view_network(self):
        """查看网络连接"""
        pid = self._get_selected_pid()
        if pid:
            self.log(f"🌐 请在网络连接选项卡中搜索PID: {pid}", self.output_widget)
            log_action("网络连接查询", f"PID: {pid}")
    
    def _dump_process(self):
        """转储进程"""
        pid = self._get_selected_pid()
        name = self._get_selected_process_name()
        if pid:
            self.log(f"💾 请在进程转储选项卡中输入PID: {pid} ({name})", self.output_widget)
            log_action("进程转储请求", f"PID: {pid}")
    
    def _open_process_location(self):
        """打开进程位置"""
        pid = self._get_selected_pid()
        if not pid:
            return
        try:
            import psutil
            p = psutil.Process(pid)
            if p.exe():
                self.open_file_location(p.exe())
        except Exception as e:
            messagebox.showwarning("警告", f"无法获取进程路径: {e}")
    
    def _kill_process(self):
        """结束进程"""
        pid = self._get_selected_pid()
        name = self._get_selected_process_name()
        if not pid:
            return
        
        log_action("结束进程请求", f"{name} (PID: {pid})")
        
        if messagebox.askyesno("确认", f"确定要结束进程 {name} (PID: {pid}) 吗?\n\n此操作不可撤销!"):
            try:
                import psutil
                p = psutil.Process(pid)
                p.terminate()
                self.log(f"✅ 已结束进程: {name} (PID: {pid})", self.output_widget)
                self.frame.after(500, self.refresh)
            except Exception as e:
                console_log(f"结束进程失败: {e}", "ERROR")
                messagebox.showerror("错误", f"无法结束进程: {e}")
    
    def _show_stats(self):
        """显示统计"""
        total = len(self.process_data)
        total_cpu = sum(p['cpu_percent'] for p in self.process_data)
        total_mem = sum(p['memory_mb'] for p in self.process_data)
        high_cpu = len([p for p in self.process_data if p['cpu_percent'] > 50])
        high_mem = len([p for p in self.process_data if p['memory_mb'] > 500])
        
        stats = {
            '进程总数': total,
            'CPU总使用率': f"{total_cpu:.1f}%",
            '内存总使用': f"{total_mem:.1f} MB",
            '---': '',
            '高CPU进程(>50%)': high_cpu,
            '高内存进程(>500MB)': high_mem,
        }
        self.show_detail_dialog("进程统计", stats)
    
    def _get_selected_pid(self) -> int:
        """获取选中的PID"""
        selection = self.process_tree.selection()
        if not selection:
            return None
        item = self.process_tree.item(selection[0])
        return item['values'][0] if item['values'] else None
    
    def _get_selected_process_name(self) -> str:
        """获取选中的进程名"""
        selection = self.process_tree.selection()
        if not selection:
            return None
        item = self.process_tree.item(selection[0])
        return item['values'][1] if item['values'] else None
