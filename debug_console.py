#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试控制台模块
独立窗口显示所有程序动作和调试信息
用于开发阶段问题定位
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime
import threading
import queue
import traceback
import sys
import io


class DebugConsole:
    """独立的调试控制台窗口

    功能：
    - 实时显示所有日志（DEBUG/INFO/WARNING/ERROR）
    - 显示异常堆栈
    - 按级别过滤
    - 搜索功能
    - 导出日志
    - 暂停/继续输出
    """

    # 日志级别颜色
    LEVEL_COLORS = {
        'DEBUG': '#808080',    # 灰色
        'INFO': '#000000',     # 黑色
        'ACTION': '#0066CC',   # 蓝色
        'WARNING': '#FF8C00',  # 橙色
        'ERROR': '#FF0000',    # 红色
        'CRITICAL': '#8B0000', # 深红
        'EXCEPTION': '#FF00FF' # 紫色
    }

    def __init__(self, parent=None, title="调试控制台", auto_show=True):
        self.parent = parent
        self.title = title
        self.window = None
        self.output_text = None

        # 日志队列（线程安全）
        self.log_queue = queue.Queue()
        self.log_buffer = []  # 保存所有日志
        self.max_buffer_size = 10000

        # 状态
        self.paused = False
        self.filter_level = 'ALL'
        self.search_text = ''

        # 统计
        self.stats = {
            'DEBUG': 0,
            'INFO': 0,
            'ACTION': 0,
            'WARNING': 0,
            'ERROR': 0,
            'EXCEPTION': 0
        }

        # 自动显示
        if auto_show:
            self.show()

        # 启动日志处理线程
        self._start_log_processor()

    def show(self):
        """显示调试控制台"""
        if self.window is None or not self.window.winfo_exists():
            self._create_window()
        else:
            self.window.lift()
            self.window.focus_force()

    def _create_window(self):
        """创建控制台窗口"""
        if self.parent:
            self.window = tk.Toplevel(self.parent)
        else:
            self.window = tk.Tk()

        self.window.title(self.title)
        self.window.geometry("1000x600")
        self.window.minsize(600, 400)

        # 设置图标颜色（开发模式标识）
        self.window.configure(bg='#1e1e1e')

        self._create_toolbar()
        self._create_filter_bar()
        self._create_text_area()
        self._create_status_bar()

        # 窗口关闭时隐藏而不是销毁
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

        # 恢复缓存的日志
        self._restore_logs()

    def _create_toolbar(self):
        """创建工具栏"""
        toolbar = ttk.Frame(self.window)
        toolbar.pack(fill=tk.X, padx=5, pady=3)

        # 左侧按钮
        ttk.Button(toolbar, text="清空", command=self.clear, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="保存", command=self.save_log, width=6).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=5, fill=tk.Y)

        # 暂停/继续
        self.pause_btn = ttk.Button(toolbar, text="暂停", command=self.toggle_pause, width=6)
        self.pause_btn.pack(side=tk.LEFT, padx=2)

        # 自动滚动
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="自动滚动", variable=self.auto_scroll_var).pack(side=tk.LEFT, padx=5)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=5, fill=tk.Y)

        # 级别过滤
        ttk.Label(toolbar, text="级别:").pack(side=tk.LEFT, padx=2)
        self.level_var = tk.StringVar(value='ALL')
        level_combo = ttk.Combobox(toolbar, textvariable=self.level_var,
                                   values=['ALL', 'DEBUG', 'INFO', 'ACTION', 'WARNING', 'ERROR'],
                                   state='readonly', width=10)
        level_combo.pack(side=tk.LEFT, padx=2)
        level_combo.bind('<<ComboboxSelected>>', lambda e: self._apply_filter())

        # 右侧统计
        self.stats_label = ttk.Label(toolbar, text="")
        self.stats_label.pack(side=tk.RIGHT, padx=5)

    def _create_filter_bar(self):
        """创建搜索过滤栏"""
        filter_frame = ttk.Frame(self.window)
        filter_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(filter_frame, text="搜索:").pack(side=tk.LEFT, padx=2)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=2)
        search_entry.bind('<Return>', lambda e: self._apply_filter())

        ttk.Button(filter_frame, text="搜索", command=self._apply_filter, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="清除", command=self._clear_filter, width=6).pack(side=tk.LEFT, padx=2)

        # 快捷过滤按钮
        ttk.Separator(filter_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        ttk.Button(filter_frame, text="仅错误", command=lambda: self._quick_filter('ERROR'), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="仅警告", command=lambda: self._quick_filter('WARNING'), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="仅动作", command=lambda: self._quick_filter('ACTION'), width=8).pack(side=tk.LEFT, padx=2)

    def _create_text_area(self):
        """创建文本区域"""
        text_frame = ttk.Frame(self.window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=3)

        # 使用等宽字体，深色背景
        self.output_text = scrolledtext.ScrolledText(
            text_frame,
            font=('Consolas', 9),
            wrap=tk.WORD,
            bg='#1e1e1e',
            fg='#d4d4d4',
            insertbackground='white'
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # 配置颜色标签
        for level, color in self.LEVEL_COLORS.items():
            self.output_text.tag_configure(level, foreground=color)

        # 特殊标签
        self.output_text.tag_configure('TIMESTAMP', foreground='#569cd6')
        self.output_text.tag_configure('SEPARATOR', foreground='#4ec9b0')
        self.output_text.tag_configure('HIGHLIGHT', background='#3a3a3a')

    def _create_status_bar(self):
        """创建状态栏"""
        status_frame = ttk.Frame(self.window)
        status_frame.pack(fill=tk.X, padx=5, pady=2)

        self.status_label = ttk.Label(status_frame, text="就绪")
        self.status_label.pack(side=tk.LEFT)

        self.count_label = ttk.Label(status_frame, text="日志: 0")
        self.count_label.pack(side=tk.RIGHT, padx=10)

    def _start_log_processor(self):
        """启动日志处理"""
        def process_logs():
            while True:
                try:
                    # 从队列获取日志
                    log_entry = self.log_queue.get(timeout=0.1)
                    if log_entry is None:
                        break

                    # 添加到缓冲区
                    self.log_buffer.append(log_entry)
                    if len(self.log_buffer) > self.max_buffer_size:
                        self.log_buffer = self.log_buffer[-self.max_buffer_size//2:]

                    # 更新统计
                    level = log_entry.get('level', 'INFO')
                    if level in self.stats:
                        self.stats[level] += 1

                    # 如果没有暂停且窗口存在，显示日志
                    # 使用 safe_after 避免线程问题
                    if not self.paused and self.window:
                        self._safe_display(log_entry)

                except queue.Empty:
                    continue
                except Exception as e:
                    # 静默处理，避免刷屏
                    pass

        self.processor_thread = threading.Thread(target=process_logs, daemon=True)
        self.processor_thread.start()

    def _safe_display(self, entry):
        """线程安全地显示日志"""
        try:
            if self.window:
                self.window.after(0, lambda: self._display_log_entry(entry))
        except (tk.TclError, RuntimeError):
            pass

    def _display_log_entry(self, entry):
        """在UI中显示日志条目"""
        try:
            if not self.output_text:
                return

            level = entry.get('level', 'INFO')

            # 检查过滤
            if self.filter_level != 'ALL' and level != self.filter_level:
                return

            search = self.search_var.get().strip().lower() if hasattr(self, 'search_var') else ''
            if search and search not in entry.get('message', '').lower():
                return

            # 格式化输出
            timestamp = entry.get('timestamp', '')
            message = entry.get('message', '')
            source = entry.get('source', '')

            # 构建日志行
            line = f"[{timestamp}] [{level:8}]"
            if source:
                line += f" [{source}]"
            line += f" {message}\n"

            # 添加到文本框
            self.window.after(0, lambda: self._insert_log(line, level))

        except Exception as e:
            print(f"显示日志错误: {e}")

    def _insert_log(self, line, level):
        """插入日志到文本框（必须在主线程调用）"""
        try:
            if not self.output_text or not self.window.winfo_exists():
                return

            self.output_text.insert(tk.END, line, level)

            if self.auto_scroll_var.get():
                self.output_text.see(tk.END)

            # 更新计数
            self._update_stats()

        except tk.TclError:
            pass

    def _restore_logs(self):
        """恢复缓存的日志"""
        for entry in self.log_buffer:
            self._display_log_entry(entry)

    def _update_stats(self):
        """更新统计显示"""
        if hasattr(self, 'stats_label') and self.stats_label:
            stats_text = f"D:{self.stats['DEBUG']} I:{self.stats['INFO']} A:{self.stats['ACTION']} W:{self.stats['WARNING']} E:{self.stats['ERROR']}"
            self.stats_label.config(text=stats_text)

        if hasattr(self, 'count_label') and self.count_label:
            self.count_label.config(text=f"日志: {len(self.log_buffer)}")

    # ==================== 公共日志方法 ====================

    def log(self, message, level='INFO', source=''):
        """添加日志"""
        entry = {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'level': level.upper(),
            'message': str(message),
            'source': source
        }
        self.log_queue.put(entry)

    def debug(self, message, source=''):
        """调试日志"""
        self.log(message, 'DEBUG', source)

    def info(self, message, source=''):
        """信息日志"""
        self.log(message, 'INFO', source)

    def action(self, message, source=''):
        """动作日志"""
        self.log(message, 'ACTION', source)

    def warning(self, message, source=''):
        """警告日志"""
        self.log(message, 'WARNING', source)

    def error(self, message, source=''):
        """错误日志"""
        self.log(message, 'ERROR', source)

    def exception(self, message='', source=''):
        """异常日志（带堆栈）"""
        exc_info = traceback.format_exc()
        full_message = f"{message}\n{exc_info}" if message else exc_info
        self.log(full_message, 'EXCEPTION', source)

    def separator(self, title=''):
        """分隔线"""
        line = '=' * 60
        if title:
            line = f"{'=' * 20} {title} {'=' * (37 - len(title))}"
        self.log(line, 'INFO')

    # ==================== UI 操作 ====================

    def toggle_pause(self):
        """切换暂停状态"""
        self.paused = not self.paused
        self.pause_btn.config(text="继续" if self.paused else "暂停")
        self.status_label.config(text="已暂停" if self.paused else "就绪")

    def clear(self):
        """清空日志"""
        if self.output_text:
            self.output_text.delete(1.0, tk.END)
        self.log_buffer = []
        self.stats = {k: 0 for k in self.stats}
        self._update_stats()

    def save_log(self):
        """保存日志到文件"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("日志文件", "*.log"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile=f"debug_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for entry in self.log_buffer:
                        line = f"[{entry['timestamp']}] [{entry['level']:8}]"
                        if entry['source']:
                            line += f" [{entry['source']}]"
                        line += f" {entry['message']}\n"
                        f.write(line)
                messagebox.showinfo("成功", f"日志已保存到:\n{file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {e}")

    def _apply_filter(self):
        """应用过滤"""
        self.filter_level = self.level_var.get()
        self.search_text = self.search_var.get().strip().lower()

        # 重新显示过滤后的日志
        if self.output_text:
            self.output_text.delete(1.0, tk.END)
            for entry in self.log_buffer:
                self._display_log_entry(entry)

    def _clear_filter(self):
        """清除过滤"""
        self.level_var.set('ALL')
        self.search_var.set('')
        self._apply_filter()

    def _quick_filter(self, level):
        """快捷过滤"""
        self.level_var.set(level)
        self._apply_filter()

    def _on_close(self):
        """关闭窗口"""
        self.window.withdraw()


# ==================== 全局调试控制台实例 ====================

_debug_console = None


def get_debug_console(parent=None, auto_show=True):
    """获取全局调试控制台实例"""
    global _debug_console
    if _debug_console is None:
        _debug_console = DebugConsole(parent, auto_show=auto_show)
    return _debug_console


def debug_log(message, level='INFO', source=''):
    """全局调试日志函数"""
    console = get_debug_console(auto_show=False)
    console.log(message, level, source)


# ==================== 测试代码 ====================

if __name__ == '__main__':
    root = tk.Tk()
    root.title("主窗口")
    root.geometry("400x300")

    console = DebugConsole(root, auto_show=True)

    # 测试按钮
    def test_logs():
        console.debug("这是调试信息", "TestModule")
        console.info("这是普通信息", "TestModule")
        console.action("用户点击了按钮", "UI")
        console.warning("这是警告信息", "TestModule")
        console.error("这是错误信息", "TestModule")
        console.separator("测试分隔线")

        # 测试异常
        try:
            raise ValueError("测试异常")
        except:
            console.exception("捕获到异常", "TestModule")

    ttk.Button(root, text="测试日志", command=test_logs).pack(pady=20)
    ttk.Button(root, text="显示控制台", command=console.show).pack(pady=10)

    root.mainloop()
