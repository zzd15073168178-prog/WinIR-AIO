#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""基础选项卡类 - 所有选项卡的父类"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Optional, Any, Dict, List
import subprocess
import os
from console_logger import console_log, log_action


class BaseTab:
    """所有选项卡的基类"""
    
    def __init__(self, parent, manager: Any, title: str):
        self.parent = parent
        self.manager = manager
        self.title = title
        self.frame = parent  # parent is now the tab frame itself
        self._context_menu = None
        
        # Configure grid for the tab frame
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_rowconfigure(0, weight=1)
        
        self.setup_ui()
    
    def setup_ui(self):
        """设置UI - 子类重写"""
        pass

    def safe_after(self, callback, *args):
        """线程安全地调用 UI 更新回调

        在子线程中使用此方法来安全地更新 UI，防止窗口关闭后出现 TclError 或 RuntimeError
        """
        try:
            # 直接尝试调用 after，如果窗口已销毁会抛出异常
            self.frame.after(0, lambda: callback(*args) if args else callback())
        except (tk.TclError, RuntimeError):
            # 窗口已被销毁或主线程不在 main loop 中，忽略
            pass

    def refresh(self):
        """刷新数据 - 子类重写"""
        pass
    
    def log(self, message: str, output_widget, log_level: str = "INFO"):
        """输出日志 - 兼容 OutputWindow 和 ScrolledText"""
        # 如果是 OutputWindow 对象（有 log 方法）
        if hasattr(output_widget, 'log'):
            output_widget.log(message)
        else:
            # 旧的 ScrolledText 兼容
            output_widget.insert(tk.END, f"{message}\n")
            output_widget.see(tk.END)
            console_log(message, log_level)
    
    def create_tree(self, parent, columns: List[str], show_headings: bool = True, 
                   height: int = 20) -> ttk.Treeview:
        """创建树形视图"""
        tree = ttk.Treeview(parent, columns=columns, show='headings' if show_headings else '', height=height)
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        return tree
    
    def add_scrollbar(self, parent, tree: ttk.Treeview):
        """添加滚动条"""
        # 使用 ctk 滚动条需要包装一下，或者直接使用 ttk 滚动条但样式可能不匹配
        # 这里为了简单和兼容性，我们使用 ttk 滚动条，但尝试应用暗色主题
        # 或者我们可以不使用这个辅助函数，直接在 setup_ui 中布局
        
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        return scrollbar
    
    def create_button_frame(self, parent) -> ttk.Frame:
        """创建按钮框架"""
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)
        return btn_frame
    
    def create_search_frame(self, parent, label_text: str, placeholder: str, width: int = 20):
        """创建搜索框"""
        search_frame = ttk.Frame(parent)
        search_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_frame, text=label_text).pack(side=tk.LEFT, padx=5)
        
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=width)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        return search_frame, search_var
    
    def setup_tree_context_menu(self, tree: ttk.Treeview, menu_items: List[Dict]):
        """设置树形视图右键菜单"""
        menu = tk.Menu(tree, tearoff=0)
        for item in menu_items:
            if item.get('separator'):
                menu.add_separator()
            elif item.get('command'):
                menu.add_command(label=item['label'], command=item['command'])
        
        def on_right_click(event):
            item = tree.identify_row(event.y)
            if item:
                tree.selection_set(item)
                tree.focus(item)
                try:
                    menu.tk_popup(event.x_root, event.y_root)
                finally:
                    menu.grab_release()
        
        tree.bind('<Button-3>', on_right_click)
        tree.bind('<Double-1>', lambda e: self._on_double_click(tree))
        return menu
    
    def _on_double_click(self, tree):
        """双击事件 - 子类可重写"""
        pass
    
    def show_detail_dialog(self, title: str, data: Dict[str, Any], parent=None):
        """显示详情对话框"""
        if parent is None:
            parent = self.frame.winfo_toplevel()
        
        dialog = tk.Toplevel(parent)
        dialog.title(title)
        dialog.geometry("600x450")
        dialog.transient(parent)
        dialog.grab_set()
        
        # 标题
        title_frame = ttk.Frame(dialog)
        title_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(title_frame, text=title, font=("微软雅黑", 12, "bold")).pack(anchor=tk.W)
        
        # 内容区域 - 使用 Text 组件
        content_text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, font=("Consolas", 10))
        content_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 显示数据
        for key, value in data.items():
            if key.startswith('---'):
                content_text.insert(tk.END, "-" * 50 + "\n")
                continue
            value_str = str(value) if value is not None else "N/A"
            content_text.insert(tk.END, f"{key}: {value_str}\n")
        
        content_text.config(state=tk.DISABLED)
        
        # 按钮
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(btn_frame, text="复制全部", command=lambda: self._copy_detail_to_clipboard(data, dialog)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="关闭", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        dialog.wait_window()
    
    def _copy_detail_to_clipboard(self, data: Dict, dialog):
        """复制详情到剪贴板"""
        text = '\n'.join([f"{k}: {v}" for k, v in data.items() if not k.startswith('---')])
        dialog.clipboard_clear()
        dialog.clipboard_append(text)
        log_action("复制详情", "已复制到剪贴板")
    
    def copy_selected_to_clipboard(self, tree: ttk.Treeview, columns: List[str]):
        """复制选中行到剪贴板"""
        selection = tree.selection()
        if not selection:
            return
        item = tree.item(selection[0])
        values = item['values']
        if not values:
            return
        lines = [f"{col}: {values[i]}" for i, col in enumerate(columns) if i < len(values)]
        text = '\n'.join(lines)
        tree.clipboard_clear()
        tree.clipboard_append(text)
        log_action("复制信息", "已复制到剪贴板")
    
    def get_selected_row_data(self, tree: ttk.Treeview, columns: List[str]) -> Optional[Dict[str, Any]]:
        """获取选中行数据"""
        selection = tree.selection()
        if not selection:
            return None
        item = tree.item(selection[0])
        values = item['values']
        if not values:
            return None
        return {col: values[i] for i, col in enumerate(columns) if i < len(values)}
    
    def open_file_location(self, file_path: str):
        """打开文件所在位置"""
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("警告", f"路径不存在: {file_path}")
            return
        try:
            subprocess.run(['explorer', '/select,', file_path], shell=True)
            log_action("打开位置", file_path)
        except Exception as e:
            messagebox.showerror("错误", f"无法打开位置: {e}")
