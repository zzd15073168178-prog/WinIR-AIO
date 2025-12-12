#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sysmon 简化版 GUI - 纯 Tkinter，无美化依赖
专注功能性，适合应急响应场景
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
from datetime import datetime

# 确保模块路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from process_manager import ProcessManager
from network_manager import NetworkManager
from dll_manager import DLLManager
from handle_manager import HandleManager
from dump_manager import DumpManager
from persistence_detector import PersistenceDetector


class SimpleGUI:
    """简化版 Sysmon GUI"""

    def __init__(self, root):
        self.root = root
        self.root.title("Sysmon 应急响应工具")
        self.root.geometry("1200x700")

        # 管理器
        self.process_manager = ProcessManager()
        self.network_manager = NetworkManager()
        self.dll_manager = DLLManager()
        self.handle_manager = HandleManager()
        self.dump_manager = DumpManager()
        self.persistence_detector = PersistenceDetector()

        self._create_ui()

    def _create_ui(self):
        """创建界面"""
        # 创建 Notebook（标签页）
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 各功能标签页
        self._create_process_tab()
        self._create_network_tab()
        self._create_dll_tab()
        self._create_handle_tab()
        self._create_persistence_tab()
        self._create_log_tab()

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    # ==================== 进程标签页 ====================

    def _create_process_tab(self):
        """进程标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="进程列表")

        # 工具栏
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="刷新", command=self._refresh_processes).pack(side=tk.LEFT, padx=2)

        ttk.Label(toolbar, text="过滤:").pack(side=tk.LEFT, padx=(10, 2))
        self.process_filter_var = tk.StringVar()
        filter_entry = ttk.Entry(toolbar, textvariable=self.process_filter_var, width=20)
        filter_entry.pack(side=tk.LEFT, padx=2)
        filter_entry.bind('<Return>', lambda e: self._refresh_processes())

        ttk.Button(toolbar, text="终止进程", command=self._kill_selected_process).pack(side=tk.RIGHT, padx=2)
        ttk.Button(toolbar, text="转储内存", command=self._dump_selected_process).pack(side=tk.RIGHT, padx=2)

        # 进程列表
        columns = ('PID', 'PPID', '进程名', '路径')
        self.process_tree = ttk.Treeview(frame, columns=columns, show='headings')

        for col in columns:
            self.process_tree.heading(col, text=col, command=lambda c=col: self._sort_treeview(self.process_tree, c))
            self.process_tree.column(col, width=100 if col in ('PID', 'PPID') else 200)

        # 滚动条
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)

        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 右键菜单
        self.process_menu = tk.Menu(self.root, tearoff=0)
        self.process_menu.add_command(label="查看 DLL", command=self._view_process_dll)
        self.process_menu.add_command(label="查看句柄", command=self._view_process_handles)
        self.process_menu.add_separator()
        self.process_menu.add_command(label="转储内存", command=self._dump_selected_process)
        self.process_menu.add_command(label="终止进程", command=self._kill_selected_process)

        self.process_tree.bind('<Button-3>', self._show_process_menu)
        self.process_tree.bind('<Double-1>', lambda e: self._view_process_dll())

    def _refresh_processes(self):
        """刷新进程列表"""
        self.status_var.set("正在刷新进程列表...")
        self.root.update()

        try:
            data = self.process_manager.get_process_tree()
            procs = data.get('all_procs', {})

            # 清空
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)

            # 过滤
            filter_text = self.process_filter_var.get().lower()

            for pid, info in procs.items():
                name = info.get('name', 'N/A')
                if filter_text and filter_text not in name.lower():
                    continue

                ppid = info.get('ppid', 'N/A')
                path = info.get('path', '') or ''

                self.process_tree.insert('', tk.END, values=(pid, ppid, name, path))

            self.status_var.set(f"进程列表已刷新，共 {len(self.process_tree.get_children())} 个")

        except Exception as e:
            self.status_var.set(f"刷新失败: {e}")
            messagebox.showerror("错误", f"获取进程列表失败:\n{e}")

    def _get_selected_pid(self):
        """获取选中的 PID"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("提示", "请先选择一个进程")
            return None
        item = self.process_tree.item(selection[0])
        return int(item['values'][0])

    def _kill_selected_process(self):
        """终止选中进程"""
        pid = self._get_selected_pid()
        if not pid:
            return

        if not messagebox.askyesno("确认", f"确定要终止进程 {pid} 吗？"):
            return

        try:
            import psutil
            p = psutil.Process(pid)
            p.terminate()
            messagebox.showinfo("成功", f"进程 {pid} 已终止")
            self._refresh_processes()
        except Exception as e:
            messagebox.showerror("错误", f"终止进程失败:\n{e}")

    def _dump_selected_process(self):
        """转储选中进程内存"""
        pid = self._get_selected_pid()
        if not pid:
            return

        self.status_var.set(f"正在转储进程 {pid} 的内存...")
        self.root.update()

        success, msg, filepath = self.dump_manager.create_dump(pid)

        if success:
            messagebox.showinfo("成功", f"{msg}\n\n文件: {filepath}")
        else:
            messagebox.showerror("错误", msg)

        self.status_var.set("就绪")

    def _show_process_menu(self, event):
        """显示右键菜单"""
        item = self.process_tree.identify_row(event.y)
        if item:
            self.process_tree.selection_set(item)
            self.process_menu.post(event.x_root, event.y_root)

    def _view_process_dll(self):
        """查看进程 DLL"""
        pid = self._get_selected_pid()
        if pid:
            self.notebook.select(2)  # 切换到 DLL 标签页
            self.dll_pid_var.set(str(pid))
            self._refresh_dll()

    def _view_process_handles(self):
        """查看进程句柄"""
        pid = self._get_selected_pid()
        if pid:
            self.notebook.select(3)  # 切换到句柄标签页
            self.handle_pid_var.set(str(pid))
            self._refresh_handles()

    # ==================== 网络标签页 ====================

    def _create_network_tab(self):
        """网络标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="网络连接")

        # 工具栏
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="刷新", command=self._refresh_network).pack(side=tk.LEFT, padx=2)

        self.net_filter_var = tk.StringVar(value="全部")
        ttk.Label(toolbar, text="过滤:").pack(side=tk.LEFT, padx=(10, 2))
        filter_combo = ttk.Combobox(toolbar, textvariable=self.net_filter_var, width=15,
                                   values=["全部", "LISTEN", "ESTABLISHED", "CLOSE_WAIT"])
        filter_combo.pack(side=tk.LEFT, padx=2)
        filter_combo.bind('<<ComboboxSelected>>', lambda e: self._refresh_network())

        # 网络列表
        columns = ('协议', '本地地址', '本地端口', '远程地址', '远程端口', '状态', 'PID', '进程名')
        self.network_tree = ttk.Treeview(frame, columns=columns, show='headings')

        for col in columns:
            self.network_tree.heading(col, text=col)
            self.network_tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=scrollbar.set)

        self.network_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _refresh_network(self):
        """刷新网络连接"""
        self.status_var.set("正在刷新网络连接...")
        self.root.update()

        try:
            connections = self.network_manager.get_all_connections()

            # 过滤
            filter_status = self.net_filter_var.get()
            if filter_status != "全部":
                connections = [c for c in connections if c.get('status') == filter_status]

            # 清空
            for item in self.network_tree.get_children():
                self.network_tree.delete(item)

            for conn in connections:
                self.network_tree.insert('', tk.END, values=(
                    conn.get('protocol', ''),
                    conn.get('local_addr', ''),
                    conn.get('local_port', ''),
                    conn.get('remote_addr', ''),
                    conn.get('remote_port', ''),
                    conn.get('status', ''),
                    conn.get('pid', ''),
                    conn.get('process_name', '')
                ))

            self.status_var.set(f"网络连接已刷新，共 {len(connections)} 个")

        except Exception as e:
            self.status_var.set(f"刷新失败: {e}")

    # ==================== DLL 标签页 ====================

    def _create_dll_tab(self):
        """DLL 标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="DLL 检测")

        # 工具栏
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(toolbar, text="PID:").pack(side=tk.LEFT, padx=2)
        self.dll_pid_var = tk.StringVar()
        ttk.Entry(toolbar, textvariable=self.dll_pid_var, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="查询", command=self._refresh_dll).pack(side=tk.LEFT, padx=2)

        # DLL 列表
        columns = ('基址', '大小', '路径', '签名')
        self.dll_tree = ttk.Treeview(frame, columns=columns, show='headings')

        for col in columns:
            self.dll_tree.heading(col, text=col)
            self.dll_tree.column(col, width=150 if col != '路径' else 400)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.dll_tree.yview)
        self.dll_tree.configure(yscrollcommand=scrollbar.set)

        self.dll_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _refresh_dll(self):
        """刷新 DLL 列表"""
        pid_str = self.dll_pid_var.get().strip()
        if not pid_str.isdigit():
            messagebox.showwarning("提示", "请输入有效的 PID")
            return

        pid = int(pid_str)
        self.status_var.set(f"正在查询 PID {pid} 的 DLL...")
        self.root.update()

        success, msg, dlls = self.dll_manager.check_dll_injection(pid)

        # 清空
        for item in self.dll_tree.get_children():
            self.dll_tree.delete(item)

        if not success:
            self.status_var.set(msg)
            messagebox.showerror("错误", msg)
            return

        for dll in dlls:
            path = dll.get('path', '')
            # 标记可疑
            tag = ''
            if path and not path.lower().startswith(('c:\\windows', 'c:\\program files')):
                tag = 'suspicious'

            self.dll_tree.insert('', tk.END, values=(
                dll.get('base', ''),
                dll.get('size', ''),
                path,
                dll.get('signed', 'N/A')
            ), tags=(tag,))

        self.dll_tree.tag_configure('suspicious', background='#ffcccc')
        self.status_var.set(f"找到 {len(dlls)} 个 DLL")

    # ==================== 句柄标签页 ====================

    def _create_handle_tab(self):
        """句柄标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="句柄查询")

        # 工具栏
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(toolbar, text="PID:").pack(side=tk.LEFT, padx=2)
        self.handle_pid_var = tk.StringVar()
        ttk.Entry(toolbar, textvariable=self.handle_pid_var, width=10).pack(side=tk.LEFT, padx=2)

        ttk.Label(toolbar, text="类型:").pack(side=tk.LEFT, padx=(10, 2))
        self.handle_type_var = tk.StringVar(value="全部")
        ttk.Combobox(toolbar, textvariable=self.handle_type_var, width=12,
                    values=["全部", "File", "Key", "Process", "Thread", "Section"]).pack(side=tk.LEFT, padx=2)

        ttk.Button(toolbar, text="查询", command=self._refresh_handles).pack(side=tk.LEFT, padx=2)

        # 句柄列表
        columns = ('句柄', '类型', '名称')
        self.handle_tree = ttk.Treeview(frame, columns=columns, show='headings')

        for col in columns:
            self.handle_tree.heading(col, text=col)
            self.handle_tree.column(col, width=100 if col != '名称' else 500)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.handle_tree.yview)
        self.handle_tree.configure(yscrollcommand=scrollbar.set)

        self.handle_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _refresh_handles(self):
        """刷新句柄列表"""
        pid_str = self.handle_pid_var.get().strip()
        if not pid_str.isdigit():
            messagebox.showwarning("提示", "请输入有效的 PID")
            return

        pid = int(pid_str)
        filter_type = self.handle_type_var.get()

        self.status_var.set(f"正在查询 PID {pid} 的句柄...")
        self.root.update()

        success, msg, handles = self.handle_manager.query_handles(pid, filter_type)

        # 清空
        for item in self.handle_tree.get_children():
            self.handle_tree.delete(item)

        if not success:
            self.status_var.set(msg)
            messagebox.showerror("错误", msg)
            return

        for h in handles:
            self.handle_tree.insert('', tk.END, values=(
                h.get('handle', ''),
                h.get('type', ''),
                h.get('name', '')
            ))

        self.status_var.set(f"找到 {len(handles)} 个句柄")

    # ==================== 持久化标签页 ====================

    def _create_persistence_tab(self):
        """持久化检测标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="持久化检测")

        # 工具栏
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="扫描启动项", command=self._scan_persistence).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="扫描服务", command=self._scan_services).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="扫描计划任务", command=self._scan_tasks).pack(side=tk.LEFT, padx=2)

        # 结果列表
        columns = ('类型', '名称', '路径/命令', '状态')
        self.persist_tree = ttk.Treeview(frame, columns=columns, show='headings')

        for col in columns:
            self.persist_tree.heading(col, text=col)
            self.persist_tree.column(col, width=150 if col != '路径/命令' else 400)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.persist_tree.yview)
        self.persist_tree.configure(yscrollcommand=scrollbar.set)

        self.persist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _scan_persistence(self):
        """扫描启动项"""
        self.status_var.set("正在扫描启动项...")
        self.root.update()

        # 清空
        for item in self.persist_tree.get_children():
            self.persist_tree.delete(item)

        try:
            items = self.persistence_detector.get_startup_items()
            for item in items:
                self.persist_tree.insert('', tk.END, values=(
                    '启动项',
                    item.get('name', item.get('entry', '')),
                    item.get('path', item.get('command', '')),
                    item.get('location', '')
                ))
            self.status_var.set(f"找到 {len(items)} 个启动项")
        except Exception as e:
            self.status_var.set(f"扫描失败: {e}")

    def _scan_services(self):
        """扫描服务"""
        self.status_var.set("正在扫描服务...")
        self.root.update()

        try:
            services = self.persistence_detector.get_services()
            auto_services = [s for s in services if s.get('start_type') == 'auto']

            for svc in auto_services:
                self.persist_tree.insert('', tk.END, values=(
                    '服务',
                    svc.get('name', ''),
                    svc.get('path', ''),
                    svc.get('status', '')
                ))
            self.status_var.set(f"找到 {len(auto_services)} 个自动启动服务")
        except Exception as e:
            self.status_var.set(f"扫描失败: {e}")

    def _scan_tasks(self):
        """扫描计划任务"""
        self.status_var.set("正在扫描计划任务...")
        self.root.update()

        try:
            tasks = self.persistence_detector.get_scheduled_tasks()
            for task in tasks:
                self.persist_tree.insert('', tk.END, values=(
                    '计划任务',
                    task.get('name', ''),
                    task.get('command', ''),
                    task.get('status', '')
                ))
            self.status_var.set(f"找到 {len(tasks)} 个计划任务")
        except Exception as e:
            self.status_var.set(f"扫描失败: {e}")

    # ==================== 日志标签页 ====================

    def _create_log_tab(self):
        """日志标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="操作日志")

        self.log_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=('Consolas', 10))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self._log("Sysmon 简化版 GUI 已启动")
        self._log(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def _log(self, msg):
        """写入日志"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log_text.see(tk.END)

    # ==================== 工具方法 ====================

    def _sort_treeview(self, tree, col):
        """排序 Treeview"""
        items = [(tree.set(item, col), item) for item in tree.get_children('')]

        # 尝试数字排序
        try:
            items.sort(key=lambda x: int(x[0]))
        except ValueError:
            items.sort(key=lambda x: x[0])

        for index, (_, item) in enumerate(items):
            tree.move(item, '', index)


def main():
    root = tk.Tk()

    # 设置 DPI 感知（Windows）
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

    app = SimpleGUI(root)

    # 初始加载
    root.after(100, app._refresh_processes)

    root.mainloop()


if __name__ == '__main__':
    main()
