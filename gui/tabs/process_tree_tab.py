#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进程树选项卡"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any
from datetime import datetime
from .base_tab import BaseTab
from console_logger import log_action


class ProcessTreeTab(BaseTab):
    """进程树选项卡"""
    
    def __init__(self, parent, manager: Any, output_widget):
        self.output_widget = output_widget
        self.all_procs = {}
        super().__init__(parent, manager, "🌲 进程树")
        # parent.add(self.frame, text=self.title)
    
    def setup_ui(self):
        """设置UI"""
        btn_frame = self.create_button_frame(self.frame)
        ttk.Button(btn_frame, text="刷新进程树", command=self.refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="展开全部", command=self._expand_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="折叠全部", command=self._collapse_all).pack(side=tk.LEFT, padx=5)
        
        tree_frame = ttk.Frame(self.frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('PID', '进程名', 'CPU%', '内存(MB)', '用户')
        self.hierarchy_tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings', height=20)
        
        self.hierarchy_tree.heading('#0', text='进程层级')
        for col in columns:
            self.hierarchy_tree.heading(col, text=col)
        
        self.hierarchy_tree.column('#0', width=300)
        self.hierarchy_tree.column('PID', width=70)
        self.hierarchy_tree.column('进程名', width=150)
        self.hierarchy_tree.column('CPU%', width=70)
        self.hierarchy_tree.column('内存(MB)', width=90)
        self.hierarchy_tree.column('用户', width=120)
        
        self.hierarchy_tree.tag_configure('system', background='#ccffcc', foreground='darkgreen')
        self.hierarchy_tree.tag_configure('user', background='#ffffcc', foreground='darkorange')
        self.hierarchy_tree.tag_configure('high_cpu', background='#ffcccc', foreground='red')
        
        scrollbar = self.add_scrollbar(tree_frame, self.hierarchy_tree)
        self.hierarchy_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._setup_context_menu()
        self.refresh()
    
    def _setup_context_menu(self):
        """设置右键菜单"""
        menu_items = [
            {'label': '📋 查看详情', 'command': self._show_process_detail},
            {'label': '📄 复制信息', 'command': self._copy_process_info},
            {'separator': True, 'label': '---'},
            {'label': '🔍 检测DLL注入', 'command': self._check_dll},
            {'label': '🔧 查询句柄', 'command': self._query_handle},
            {'label': '🌐 查看网络连接', 'command': self._view_network},
            {'separator': True, 'label': '---'},
            {'label': '📁 打开文件位置', 'command': self._open_process_location},
            {'separator': True, 'label': '---'},
            {'label': '❌ 结束进程', 'command': self._kill_process},
            {'label': '❌ 结束进程树', 'command': self._kill_process_tree},
        ]
        self.setup_tree_context_menu(self.hierarchy_tree, menu_items)
    
    def _on_double_click(self, tree):
        """双击查看详情"""
        self._show_process_detail()
    
    def refresh(self):
        """刷新进程树"""
        for item in self.hierarchy_tree.get_children():
            self.hierarchy_tree.delete(item)
        
        tree_data = self.manager.get_process_tree()
        self.all_procs = tree_data['all_procs']
        root_procs = tree_data['root_procs']
        
        from utils.processes import is_system_process
        import psutil
        
        visited = set()
        
        def add_process_node(parent_id, pid, depth=0):
            if depth > 50 or pid in visited or pid not in self.all_procs:
                return
            visited.add(pid)
            proc_info = self.all_procs[pid]
            
            try:
                p = psutil.Process(pid)
                cpu = p.cpu_percent(interval=0)
                mem = p.memory_info().rss / 1024 / 1024
                user = p.username().split('\\')[-1] if hasattr(p, 'username') else 'N/A'
            except:
                cpu, mem, user = 0.0, 0.0, 'N/A'
            
            # 确定标签
            if cpu > 50:
                tag = 'high_cpu'
            elif is_system_process(proc_info['name']):
                tag = 'system'
            else:
                tag = 'user'
            
            node_id = self.hierarchy_tree.insert(
                parent_id, tk.END, text=proc_info['name'],
                values=(pid, proc_info['name'], f"{cpu:.1f}", f"{mem:.1f}", user),
                tags=(tag,)
            )
            
            for child_pid in proc_info['children']:
                add_process_node(node_id, child_pid, depth + 1)
        
        for root_pid in root_procs:
            add_process_node('', root_pid)
        
        self.log(f"🌲 进程树已刷新，根进程: {len(root_procs)}", self.output_widget)
    
    def _expand_all(self):
        """展开全部"""
        def expand(item):
            self.hierarchy_tree.item(item, open=True)
            for child in self.hierarchy_tree.get_children(item):
                expand(child)
        for item in self.hierarchy_tree.get_children():
            expand(item)
    
    def _collapse_all(self):
        """折叠全部"""
        def collapse(item):
            self.hierarchy_tree.item(item, open=False)
            for child in self.hierarchy_tree.get_children(item):
                collapse(child)
        for item in self.hierarchy_tree.get_children():
            collapse(item)
    
    def _get_selected_info(self):
        """获取选中进程信息"""
        selection = self.hierarchy_tree.selection()
        if not selection:
            return None, None
        item = self.hierarchy_tree.item(selection[0])
        values = item['values']
        return (int(values[0]), values[1]) if values else (None, None)
    
    def _show_process_detail(self):
        """显示进程详情"""
        pid, name = self._get_selected_info()
        if not pid:
            return
        
        log_action("查看进程详情", f"PID: {pid}")
        
        import psutil
        detail_data = {'PID': pid, '进程名': name}
        
        try:
            p = psutil.Process(pid)
            detail_data['CPU使用率'] = f"{p.cpu_percent(interval=0.1):.1f}%"
            detail_data['内存使用'] = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
            detail_data['状态'] = p.status()
            detail_data['---1'] = ''
            detail_data['创建时间'] = datetime.fromtimestamp(p.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            detail_data['可执行路径'] = p.exe() if hasattr(p, 'exe') else 'N/A'
            detail_data['工作目录'] = p.cwd() if hasattr(p, 'cwd') else 'N/A'
            detail_data['命令行'] = ' '.join(p.cmdline()) if p.cmdline() else 'N/A'
            detail_data['---2'] = ''
            detail_data['父进程PID'] = p.ppid()
            detail_data['线程数'] = p.num_threads()
            detail_data['用户'] = p.username() if hasattr(p, 'username') else 'N/A'
            
            # 子进程
            children = p.children()
            detail_data['---3'] = ''
            detail_data['子进程数量'] = len(children)
            if children:
                child_list = ', '.join([f"{c.pid}({c.name()})" for c in children[:5]])
                if len(children) > 5:
                    child_list += f" ... 等{len(children)}个"
                detail_data['子进程列表'] = child_list
        except Exception as e:
            detail_data['错误'] = str(e)
        
        self.show_detail_dialog(f"进程详情 - {name}", detail_data)
    
    def _copy_process_info(self):
        """复制进程信息"""
        pid, name = self._get_selected_info()
        if pid:
            self.hierarchy_tree.clipboard_clear()
            self.hierarchy_tree.clipboard_append(f"PID: {pid}\n进程名: {name}")
            log_action("复制信息", f"PID: {pid}")
    
    def _check_dll(self):
        """检测DLL"""
        pid, name = self._get_selected_info()
        if pid:
            self.log(f"💉 请在DLL检测选项卡中输入PID: {pid} ({name})", self.output_widget)
    
    def _query_handle(self):
        """查询句柄"""
        pid, name = self._get_selected_info()
        if pid:
            self.log(f"🔧 请在句柄查询选项卡中输入PID: {pid} ({name})", self.output_widget)
    
    def _view_network(self):
        """查看网络"""
        pid, name = self._get_selected_info()
        if pid:
            self.log(f"🌐 请在网络连接选项卡中搜索PID: {pid} ({name})", self.output_widget)
    
    def _open_process_location(self):
        """打开进程位置"""
        pid, _ = self._get_selected_info()
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
        pid, name = self._get_selected_info()
        if not pid:
            return
        
        if messagebox.askyesno("确认", f"确定要结束进程 {name} (PID: {pid}) 吗?"):
            try:
                import psutil
                p = psutil.Process(pid)
                p.terminate()
                self.log(f"✅ 已结束进程: {name} (PID: {pid})", self.output_widget)
                self.frame.after(500, self.refresh)
            except Exception as e:
                messagebox.showerror("错误", f"无法结束进程: {e}")
    
    def _kill_process_tree(self):
        """结束进程树"""
        pid, name = self._get_selected_info()
        if not pid:
            return
        
        if messagebox.askyesno("确认", f"确定要结束进程 {name} (PID: {pid}) 及其所有子进程吗?\n\n⚠️ 此操作不可撤销!"):
            try:
                import psutil
                p = psutil.Process(pid)
                children = p.children(recursive=True)
                
                # 先结束子进程
                for child in children:
                    try:
                        child.terminate()
                    except:
                        pass
                
                # 再结束父进程
                p.terminate()
                
                self.log(f"✅ 已结束进程树: {name} (PID: {pid})，共 {len(children) + 1} 个进程", self.output_widget)
                self.frame.after(500, self.refresh)
            except Exception as e:
                messagebox.showerror("错误", f"无法结束进程树: {e}")
