#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文件监控标签页 - 检测病毒文件生成行为"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import os
from pathlib import Path
from datetime import datetime

from .base_tab import BaseTab


class FileMonitorTab(BaseTab):
    """文件监控标签页"""

    def __init__(self, parent, manager, output_window):
        super().__init__(parent, manager, output_window)
        self.monitoring = False
        self.monitor_thread = None
        self.previous_files = {}
        self.created_count = 0
        self.modified_count = 0
        self.deleted_count = 0
        self.setup_ui()

    def setup_ui(self):
        """设置界面"""
        # 工具栏
        toolbar = ttk.Frame(self.parent)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        # 路径选择
        ttk.Label(toolbar, text="监控路径:").pack(side=tk.LEFT, padx=(0, 5))
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(toolbar, textvariable=self.path_var, width=50)
        path_entry.pack(side=tk.LEFT, padx=2)

        ttk.Button(toolbar, text="浏览", command=self._browse_path, width=6).pack(side=tk.LEFT, padx=2)

        # 选项
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="递归子目录", variable=self.recursive_var).pack(side=tk.LEFT, padx=10)

        ttk.Label(toolbar, text="间隔(秒):").pack(side=tk.LEFT, padx=(10, 2))
        self.interval_var = tk.StringVar(value="1.0")
        ttk.Entry(toolbar, textvariable=self.interval_var, width=5).pack(side=tk.LEFT, padx=2)

        # 控制按钮
        self.start_btn = ttk.Button(toolbar, text="开始监控", command=self._toggle_monitor, width=10)
        self.start_btn.pack(side=tk.RIGHT, padx=2)

        ttk.Button(toolbar, text="清空记录", command=self._clear_log, width=8).pack(side=tk.RIGHT, padx=2)

        # 状态栏
        status_frame = ttk.Frame(self.parent)
        status_frame.pack(fill=tk.X, padx=5, pady=2)

        self.status_label = ttk.Label(status_frame, text="状态: 未启动")
        self.status_label.pack(side=tk.LEFT)

        self.stats_label = ttk.Label(status_frame, text="新建: 0 | 修改: 0 | 删除: 0")
        self.stats_label.pack(side=tk.RIGHT)

        # 事件列表
        columns = ('时间', '事件', '文件路径', '大小', '可能的进程')
        self.tree = ttk.Treeview(self.parent, columns=columns, show='headings')

        self.tree.heading('时间', text='时间')
        self.tree.heading('事件', text='事件')
        self.tree.heading('文件路径', text='文件路径')
        self.tree.heading('大小', text='大小')
        self.tree.heading('可能的进程', text='可能的进程')

        self.tree.column('时间', width=80)
        self.tree.column('事件', width=60)
        self.tree.column('文件路径', width=400)
        self.tree.column('大小', width=80)
        self.tree.column('可能的进程', width=150)

        # 标签样式
        self.tree.tag_configure('created', foreground='green')
        self.tree.tag_configure('modified', foreground='orange')
        self.tree.tag_configure('deleted', foreground='red')

        # 滚动条
        scrollbar_y = ttk.Scrollbar(self.parent, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(self.parent, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        # 右键菜单
        self.context_menu = tk.Menu(self.parent, tearoff=0)
        self.context_menu.add_command(label="打开文件位置", command=self._open_file_location)
        self.context_menu.add_command(label="查看文件信息", command=self._show_file_info)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="复制路径", command=self._copy_path)

        self.tree.bind('<Button-3>', self._show_context_menu)

    def _browse_path(self):
        """浏览选择文件夹"""
        path = filedialog.askdirectory(title="选择要监控的文件夹")
        if path:
            self.path_var.set(path)

    def _toggle_monitor(self):
        """切换监控状态"""
        if self.monitoring:
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self):
        """开始监控"""
        watch_path = self.path_var.get().strip()
        if not watch_path:
            messagebox.showwarning("提示", "请先选择要监控的文件夹")
            return

        if not os.path.isdir(watch_path):
            messagebox.showerror("错误", f"路径不存在或不是文件夹:\n{watch_path}")
            return

        try:
            interval = float(self.interval_var.get())
            if interval < 0.1:
                interval = 0.1
        except ValueError:
            interval = 1.0

        self.monitoring = True
        self.start_btn.config(text="停止监控")
        self.status_label.config(text=f"状态: 正在监控 - {watch_path}")

        # 重置计数
        self.created_count = 0
        self.modified_count = 0
        self.deleted_count = 0

        # 记录初始文件状态
        self.previous_files = self._get_files(watch_path, self.recursive_var.get())
        self.log(f"开始监控: {watch_path}")
        self.log(f"初始文件数: {len(self.previous_files)}")

        # 启动监控线程
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(watch_path, interval),
            daemon=True
        )
        self.monitor_thread.start()

    def _stop_monitor(self):
        """停止监控"""
        self.monitoring = False
        self.start_btn.config(text="开始监控")
        self.status_label.config(text="状态: 已停止")
        self.log(f"监控已停止 - 新建: {self.created_count}, 修改: {self.modified_count}, 删除: {self.deleted_count}")

    def _get_files(self, path, recursive=False):
        """获取文件列表及状态"""
        p = Path(path)
        pattern = '**/*' if recursive else '*'
        files = {}
        try:
            for f in p.glob(pattern):
                if f.is_file():
                    try:
                        stat = f.stat()
                        files[str(f)] = {
                            'size': stat.st_size,
                            'mtime': stat.st_mtime
                        }
                    except:
                        pass
        except:
            pass
        return files

    def _monitor_loop(self, watch_path, interval):
        """监控循环"""
        while self.monitoring:
            time.sleep(interval)
            if not self.monitoring:
                break

            current_files = self._get_files(watch_path, self.recursive_var.get())

            # 检测新文件
            for filepath, info in current_files.items():
                if filepath not in self.previous_files:
                    self.created_count += 1
                    process_name = self._find_process_for_file(filepath)
                    self._add_event('新建', filepath, info['size'], process_name, 'created')

                elif info['mtime'] != self.previous_files[filepath]['mtime']:
                    self.modified_count += 1
                    process_name = self._find_process_for_file(filepath)
                    self._add_event('修改', filepath, info['size'], process_name, 'modified')

            # 检测删除的文件
            for filepath in self.previous_files:
                if filepath not in current_files:
                    self.deleted_count += 1
                    self._add_event('删除', filepath, '-', '-', 'deleted')

            self.previous_files = current_files

            # 更新统计
            self.parent.after(0, self._update_stats)

    def _find_process_for_file(self, filepath):
        """尝试找到打开文件的进程"""
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    open_files = proc.info.get('open_files') or []
                    for f in open_files:
                        if filepath.lower() in f.path.lower():
                            return f"{proc.info['name']} ({proc.info['pid']})"
                except:
                    pass
        except:
            pass
        return "-"

    def _add_event(self, event_type, filepath, size, process, tag):
        """添加事件到列表（线程安全）"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        size_str = f"{size:,}" if isinstance(size, int) else size

        def insert():
            self.tree.insert('', 0, values=(timestamp, event_type, filepath, size_str, process), tags=(tag,))
            # 限制显示条数
            children = self.tree.get_children()
            if len(children) > 1000:
                for item in children[1000:]:
                    self.tree.delete(item)

        self.parent.after(0, insert)
        self.log(f"[{event_type}] {filepath}")

    def _update_stats(self):
        """更新统计信息"""
        self.stats_label.config(
            text=f"新建: {self.created_count} | 修改: {self.modified_count} | 删除: {self.deleted_count}"
        )

    def _clear_log(self):
        """清空记录"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.created_count = 0
        self.modified_count = 0
        self.deleted_count = 0
        self._update_stats()

    def _show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _get_selected_path(self):
        """获取选中的文件路径"""
        selection = self.tree.selection()
        if not selection:
            return None
        item = self.tree.item(selection[0])
        return item['values'][2]  # 文件路径列

    def _open_file_location(self):
        """打开文件所在位置"""
        filepath = self._get_selected_path()
        if filepath and os.path.exists(filepath):
            os.system(f'explorer /select,"{filepath}"')
        elif filepath:
            # 文件已删除，打开父目录
            parent = os.path.dirname(filepath)
            if os.path.exists(parent):
                os.startfile(parent)

    def _show_file_info(self):
        """显示文件详细信息"""
        filepath = self._get_selected_path()
        if not filepath:
            return

        if not os.path.exists(filepath):
            messagebox.showinfo("文件信息", f"文件已不存在:\n{filepath}")
            return

        try:
            stat = os.stat(filepath)
            info = f"""文件路径: {filepath}

大小: {stat.st_size:,} 字节
创建时间: {datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')}
修改时间: {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
访问时间: {datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')}"""

            # 查找打开此文件的进程
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    open_files = proc.info.get('open_files') or []
                    for f in open_files:
                        if os.path.normpath(filepath).lower() == os.path.normpath(f.path).lower():
                            processes.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
                except:
                    pass

            if processes:
                info += f"\n\n打开此文件的进程:\n" + "\n".join(processes)

            messagebox.showinfo("文件信息", info)

        except Exception as e:
            messagebox.showerror("错误", f"获取文件信息失败:\n{e}")

    def _copy_path(self):
        """复制文件路径到剪贴板"""
        filepath = self._get_selected_path()
        if filepath:
            self.parent.clipboard_clear()
            self.parent.clipboard_append(filepath)
            self.log(f"已复制路径: {filepath}")
