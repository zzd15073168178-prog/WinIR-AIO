#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文件解锁与强制删除选项卡"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os

from .base_tab import BaseTab


class FileLockerTab(BaseTab):
    """文件解锁与强制删除选项卡"""

    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.current_path = ""
        super().__init__(parent, manager, "🔓 文件解锁")

    def setup_ui(self):
        """设置 UI"""
        # 顶部说明
        info_frame = ttk.LabelFrame(self.frame, text="功能说明", padding=5)
        info_frame.pack(fill=tk.X, padx=5, pady=5)

        info_text = ("查找锁定文件/文件夹的进程，支持终止占用进程后强制删除。\n"
                    "适用于：病毒文件删除、被占用文件清理、顽固文件处理等场景。")
        ttk.Label(info_frame, text=info_text, foreground='#666').pack(anchor=tk.W)

        # 路径选择区域
        path_frame = ttk.LabelFrame(self.frame, text="目标路径", padding=5)
        path_frame.pack(fill=tk.X, padx=5, pady=5)

        path_input_frame = ttk.Frame(path_frame)
        path_input_frame.pack(fill=tk.X, pady=2)

        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_input_frame, textvariable=self.path_var, width=70)
        path_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)

        ttk.Button(path_input_frame, text="📄 选择文件", command=self.select_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(path_input_frame, text="📁 选择文件夹", command=self.select_folder).pack(side=tk.LEFT, padx=2)

        # 操作按钮
        btn_frame = ttk.Frame(path_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="🔍 查找占用进程", command=self.find_locking).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="📋 查看文件信息", command=self.show_file_info).pack(side=tk.LEFT, padx=3)

        ttk.Separator(btn_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        ttk.Button(btn_frame, text="⚡ 终止所有占用进程", command=self.kill_all_locking).pack(side=tk.LEFT, padx=3)

        ttk.Separator(btn_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        ttk.Button(btn_frame, text="🗑️ 强制删除", command=self.force_delete).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="⏰ 重启后删除", command=self.schedule_delete).pack(side=tk.LEFT, padx=3)

        # 占用进程列表
        list_frame = ttk.LabelFrame(self.frame, text="占用进程列表", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ('name', 'pid', 'type', 'handle', 'path')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)

        self.tree.heading('name', text='进程名')
        self.tree.heading('pid', text='PID')
        self.tree.heading('type', text='类型')
        self.tree.heading('handle', text='句柄')
        self.tree.heading('path', text='锁定路径')

        self.tree.column('name', width=150)
        self.tree.column('pid', width=80)
        self.tree.column('type', width=80)
        self.tree.column('handle', width=100)
        self.tree.column('path', width=400)

        scrollbar_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar_y.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        # 右键菜单
        self._setup_context_menu()

        # 状态栏
        status_frame = ttk.Frame(self.frame)
        status_frame.pack(fill=tk.X, padx=5, pady=5)

        self.status_label = ttk.Label(status_frame, text="状态: 就绪 | 选择文件或文件夹开始分析")
        self.status_label.pack(side=tk.LEFT)

        # 工具状态
        tool_status = "✅ handle.exe 已就绪" if self.manager.is_tool_available() else "⚠️ handle.exe 未找到 (部分功能受限)"
        ttk.Label(status_frame, text=tool_status, foreground='green' if self.manager.is_tool_available() else 'orange').pack(side=tk.RIGHT)

    def _setup_context_menu(self):
        """设置右键菜单"""
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="⚡ 终止此进程", command=self.kill_selected_process)
        self.context_menu.add_command(label="🔒 关闭此句柄", command=self.close_selected_handle)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 复制进程名", command=lambda: self._copy_column(0))
        self.context_menu.add_command(label="📋 复制 PID", command=lambda: self._copy_column(1))

        self.tree.bind('<Button-3>', self._show_context_menu)

    def _show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _copy_column(self, col_idx):
        """复制指定列"""
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])['values']
            if values and col_idx < len(values):
                self.tree.clipboard_clear()
                self.tree.clipboard_append(str(values[col_idx]))

    def select_file(self):
        """选择文件"""
        path = filedialog.askopenfilename(title="选择文件")
        if path:
            self.path_var.set(path)
            self.current_path = path

    def select_folder(self):
        """选择文件夹"""
        path = filedialog.askdirectory(title="选择文件夹")
        if path:
            self.path_var.set(path)
            self.current_path = path

    def find_locking(self):
        """查找占用进程"""
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("提示", "请先选择文件或文件夹")
            return

        if not os.path.exists(path):
            messagebox.showwarning("提示", "路径不存在")
            return

        self.current_path = path
        self.status_label.configure(text="状态: 正在查找占用进程...")
        self.log(f"🔍 查找占用进程: {path}", self.output_widget)

        # 清空列表
        for item in self.tree.get_children():
            self.tree.delete(item)

        def find():
            def callback(msg):
                self.frame.after(0, lambda m=msg: self.log(f"  {m}", self.output_widget))

            processes = self.manager.find_locking_processes(path, progress_callback=callback)
            self.frame.after(0, lambda: self._find_complete(processes))

        threading.Thread(target=find, daemon=True).start()

    def _find_complete(self, processes):
        """查找完成"""
        for proc in processes:
            values = (
                proc['name'],
                proc['pid'],
                proc['type'],
                proc['handle'],
                proc['path']
            )
            self.tree.insert('', tk.END, values=values)

        count = len(processes)
        if count > 0:
            self.status_label.configure(text=f"状态: 找到 {count} 个占用进程")
            self.log(f"⚠️ 找到 {count} 个进程正在占用此路径", self.output_widget)
        else:
            self.status_label.configure(text="状态: 未发现占用进程")
            self.log("✅ 未发现占用进程，可以直接删除", self.output_widget)

    def show_file_info(self):
        """显示文件信息"""
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("提示", "请先选择文件或文件夹")
            return

        info = self.manager.get_file_info(path)

        detail = {
            '路径': info['path'],
            '存在': '是' if info['exists'] else '否',
            '类型': '文件' if info['is_file'] else ('文件夹' if info['is_dir'] else '未知'),
            '大小': info['size_str'] if info['is_file'] else '-',
            '属性': ', '.join(info['attributes']) if info['attributes'] else '无特殊属性',
        }

        self.show_detail_dialog(f"文件信息 - {os.path.basename(path)}", detail)

    def kill_selected_process(self):
        """终止选中的进程"""
        selection = self.tree.selection()
        if not selection:
            return

        values = self.tree.item(selection[0])['values']
        if not values:
            return

        name = values[0]
        pid = int(values[1])

        if messagebox.askyesno("确认", f"确定要终止进程 {name} (PID: {pid}) 吗？"):
            success = self.manager.kill_process(pid, force=True)
            if success:
                self.log(f"✅ 已终止进程: {name} (PID: {pid})", self.output_widget)
                self.tree.delete(selection[0])
            else:
                self.log(f"❌ 终止进程失败: {name} (PID: {pid})", self.output_widget)
                messagebox.showerror("错误", f"无法终止进程 {name}")

    def close_selected_handle(self):
        """关闭选中的句柄"""
        if not self.manager.is_tool_available():
            messagebox.showwarning("提示", "需要 handle.exe 才能关闭句柄")
            return

        selection = self.tree.selection()
        if not selection:
            return

        values = self.tree.item(selection[0])['values']
        if not values:
            return

        name = values[0]
        pid = int(values[1])
        handle = str(values[3])

        if not handle:
            messagebox.showwarning("提示", "无法获取句柄值")
            return

        if messagebox.askyesno("确认", f"确定要关闭进程 {name} 的句柄 {handle} 吗？\n这可能导致程序异常。"):
            success = self.manager.close_handle(pid, handle)
            if success:
                self.log(f"✅ 已关闭句柄: {handle} (进程: {name})", self.output_widget)
                self.tree.delete(selection[0])
            else:
                self.log(f"❌ 关闭句柄失败", self.output_widget)

    def kill_all_locking(self):
        """终止所有占用进程"""
        if not self.manager.locking_processes:
            messagebox.showinfo("提示", "没有发现占用进程")
            return

        count = len(self.manager.locking_processes)
        if not messagebox.askyesno("确认", f"确定要终止所有 {count} 个占用进程吗？\n\n"
                                          "注意: 系统关键进程将被跳过。"):
            return

        self.log(f"⚡ 正在终止 {count} 个占用进程...", self.output_widget)

        results = self.manager.kill_all_locking_processes(force=True)

        self.log(f"  成功: {results['success']}, 失败: {results['failed']}", self.output_widget)

        for detail in results['details']:
            status = '✅' if detail['success'] else '❌'
            self.log(f"  {status} {detail['name']} (PID: {detail['pid']}): {detail['reason']}", self.output_widget)

        # 刷新列表
        self.find_locking()

    def force_delete(self):
        """强制删除"""
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("提示", "请先选择文件或文件夹")
            return

        if not os.path.exists(path):
            messagebox.showinfo("提示", "路径已不存在")
            return

        type_str = "文件" if os.path.isfile(path) else "文件夹"

        if not messagebox.askyesno("确认删除",
                                   f"确定要强制删除此{type_str}吗？\n\n"
                                   f"路径: {path}\n\n"
                                   "此操作将:\n"
                                   "1. 终止所有占用进程\n"
                                   "2. 移除只读属性\n"
                                   "3. 删除文件/文件夹\n\n"
                                   "⚠️ 此操作不可撤销！"):
            return

        self.log(f"🗑️ 正在强制删除: {path}", self.output_widget)
        self.status_label.configure(text="状态: 正在删除...")

        def delete():
            result = self.manager.delete_file(path, force=True)
            self.frame.after(0, lambda: self._delete_complete(result))

        threading.Thread(target=delete, daemon=True).start()

    def _delete_complete(self, result):
        """删除完成"""
        if result['success']:
            self.log(f"✅ 删除成功! 方法: {result['method']}", self.output_widget)
            self.status_label.configure(text="状态: 删除成功")
            messagebox.showinfo("成功", "文件/文件夹已成功删除!")

            # 清空列表
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.path_var.set("")
        else:
            self.log(f"❌ 删除失败: {result['error']}", self.output_widget)
            self.status_label.configure(text="状态: 删除失败")
            messagebox.showerror("删除失败",
                               f"无法删除文件/文件夹。\n\n"
                               f"错误: {result['error']}\n\n"
                               "建议:\n"
                               "1. 确保以管理员身份运行\n"
                               "2. 尝试'重启后删除'功能")

    def schedule_delete(self):
        """安排重启后删除"""
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("提示", "请先选择文件或文件夹")
            return

        if not os.path.exists(path):
            messagebox.showinfo("提示", "路径已不存在")
            return

        if not messagebox.askyesno("确认",
                                   f"确定要在下次重启时删除此路径吗？\n\n"
                                   f"路径: {path}\n\n"
                                   "此操作将在 Windows 重启时自动删除该文件/文件夹。\n"
                                   "⚠️ 此操作不可撤销！"):
            return

        # 如果是文件夹，需要递归处理
        if os.path.isdir(path):
            success_count = 0
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    file_path = os.path.join(root, name)
                    if self.manager.schedule_delete_on_reboot(file_path):
                        success_count += 1
                for name in dirs:
                    dir_path = os.path.join(root, name)
                    self.manager.schedule_delete_on_reboot(dir_path)

            # 最后删除根目录
            success = self.manager.schedule_delete_on_reboot(path)

            if success:
                self.log(f"⏰ 已安排重启后删除: {path} (包含 {success_count} 个文件)", self.output_widget)
                messagebox.showinfo("成功", f"已安排在下次重启时删除。\n\n路径: {path}")
            else:
                self.log(f"❌ 安排重启删除失败", self.output_widget)
                messagebox.showerror("失败", "无法安排重启后删除，请确保以管理员身份运行。")
        else:
            success = self.manager.schedule_delete_on_reboot(path)

            if success:
                self.log(f"⏰ 已安排重启后删除: {path}", self.output_widget)
                messagebox.showinfo("成功", f"已安排在下次重启时删除。\n\n路径: {path}")
            else:
                self.log(f"❌ 安排重启删除失败", self.output_widget)
                messagebox.showerror("失败", "无法安排重启后删除，请确保以管理员身份运行。")
