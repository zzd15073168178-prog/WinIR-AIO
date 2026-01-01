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
        # 先初始化自己的属性（在调用父类之前，因为父类会调用 setup_ui）
        self.output_window = output_window
        self.monitoring = False
        self.monitor_thread = None
        self.previous_files = {}
        self.created_count = 0
        self.modified_count = 0
        self.deleted_count = 0
        # 调用父类构造函数（会自动调用 setup_ui）
        super().__init__(parent, manager, "📁 文件监控")

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

        # 是否查找进程（耗时操作）
        self.find_process_var = tk.BooleanVar(value=False)
        process_cb = ttk.Checkbutton(toolbar, text="查找进程(慢)", variable=self.find_process_var)
        process_cb.pack(side=tk.LEFT, padx=10)

        # 添加工具提示
        self._create_tooltip(process_cb, "只能检测当前正在打开文件的进程。\n"
                                         "要追踪文件创建者，请使用 Procmon 监控。")

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
        self._log(f"📁 开始监控: {watch_path}")
        self._log(f"📊 初始文件数: {len(self.previous_files)}")

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
        self._log(f"⏹ 监控已停止 - 新建: {self.created_count}, 修改: {self.modified_count}, 删除: {self.deleted_count}")

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
        find_process = self.find_process_var.get()  # 获取一次，避免在循环中频繁访问

        while self.monitoring:
            time.sleep(interval)
            if not self.monitoring:
                break

            current_files = self._get_files(watch_path, self.recursive_var.get())

            # 检测新文件
            for filepath, info in current_files.items():
                if filepath not in self.previous_files:
                    self.created_count += 1
                    process_name = self._find_process_for_file(filepath) if find_process else "-"
                    self._add_event('新建', filepath, info['size'], process_name, 'created')

                elif info['mtime'] != self.previous_files[filepath]['mtime']:
                    self.modified_count += 1
                    process_name = self._find_process_for_file(filepath) if find_process else "-"
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
        """尝试找到打开/操作文件的进程

        注意：这个方法只能找到当前正在打开文件的进程。
        如果文件已经被创建并关闭（如资源管理器复制），则无法找到创建者。
        要追踪文件创建者，需要使用 Procmon 或 ETW。
        """
        try:
            import psutil

            # 方法1：检查当前打开文件的进程
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    open_files = proc.info.get('open_files') or []
                    for f in open_files:
                        if filepath.lower() in f.path.lower():
                            return f"{proc.info['name']} ({proc.info['pid']})"
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # 方法2：检查最近访问该目录的进程（不太准确，但可能有用）
            file_dir = os.path.dirname(filepath)
            for proc in psutil.process_iter(['pid', 'name', 'cwd']):
                try:
                    cwd = proc.info.get('cwd')
                    if cwd and os.path.normpath(cwd).lower() == os.path.normpath(file_dir).lower():
                        return f"{proc.info['name']} ({proc.info['pid']}) [工作目录]"
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

        except Exception:
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
        self._log(f"[{event_type}] {filepath}")

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
            self._log(f"📋 已复制路径: {filepath}")

    def _log(self, message):
        """输出日志到 output_window"""
        if self.output_window and hasattr(self.output_window, 'log'):
            self.output_window.log(message)
        else:
            print(message)

    def _create_tooltip(self, widget, text):
        """创建鼠标悬停提示"""
        tooltip = None

        def show_tooltip(event):
            nonlocal tooltip
            x, y, _, _ = widget.bbox("insert") if hasattr(widget, 'bbox') else (0, 0, 0, 0)
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 25

            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{x}+{y}")

            label = ttk.Label(tooltip, text=text, background="#ffffe0",
                             relief="solid", borderwidth=1, padding=5)
            label.pack()

        def hide_tooltip(event):
            nonlocal tooltip
            if tooltip:
                tooltip.destroy()
                tooltip = None

        widget.bind("<Enter>", show_tooltip)
        widget.bind("<Leave>", hide_tooltip)
