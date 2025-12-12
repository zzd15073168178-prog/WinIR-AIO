#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""主窗口模块"""

import tkinter as tk
from tkinter import scrolledtext, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import os
from datetime import datetime

from console_logger import console_log, log_info
from constants import WINDOW_WIDTH, WINDOW_HEIGHT, TOOLS
from utils import is_admin
from debug_console import DebugConsole

from process_manager import ProcessManager
from network_manager import NetworkManager
from dll_manager import DLLManager
from handle_manager import HandleManager
from dump_manager import DumpManager
from monitor_manager import MonitorManager
from security_manager import SecurityManager
from hash_manager import HashManager
from file_locker import FileLocker
from memory_scanner import MemoryScanner
from yara_scanner import YaraScanner
from process_history_manager import ProcessHistoryManager
from eventlog_manager import EventLogManager
from persistence import PersistenceDetector
from user_audit_manager import UserAuditManager
from sandbox_manager import SandboxManager

from .tabs import ProcessTab, ProcessTreeTab, NetworkTab, DllTab, HandleTab, DumpTab, ProcmonTab, SecurityTab, HashTab, FileLockerTab, MemoryScannerTab, YaraTab, ProcessTraceTab, EventLogTab, PersistenceTab, UserAuditTab, SandboxTab, FileMonitorTab


class OutputWindow:
    """独立的输出日志窗口"""

    def __init__(self, parent, debug_console=None):
        self.parent = parent
        self.debug_console = debug_console
        self.window = None
        self.output_text = None
        self.log_buffer = []  # 缓存日志，窗口关闭时保留

    def show(self):
        """显示或激活输出窗口"""
        if self.window is None or not self.window.winfo_exists():
            self._create_window()
        else:
            self.window.lift()
            self.window.focus_force()

    def _create_window(self):
        """创建输出窗口"""
        self.window = tk.Toplevel(self.parent)
        self.window.title("输出日志")
        self.window.geometry("800x400")
        self.window.minsize(400, 200)

        # 工具栏
        toolbar = ttk.Frame(self.window)
        toolbar.pack(fill=tk.X, padx=5, pady=3)

        ttk.Button(toolbar, text="清空", command=self.clear, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="保存日志", command=self.save_log, width=10).pack(side=tk.LEFT, padx=2)

        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="自动滚动", variable=self.auto_scroll_var).pack(side=tk.LEFT, padx=10)

        ttk.Label(toolbar, text=f"日志条数: ").pack(side=tk.RIGHT)
        self.count_label = ttk.Label(toolbar, text="0")
        self.count_label.pack(side=tk.RIGHT)

        # 输出文本框
        text_frame = ttk.Frame(self.window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=3)

        self.output_text = scrolledtext.ScrolledText(text_frame, font=('Consolas', 9), wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # 配置颜色标签
        self.output_text.tag_configure('info', foreground='black')
        self.output_text.tag_configure('warning', foreground='orange')
        self.output_text.tag_configure('error', foreground='red')
        self.output_text.tag_configure('success', foreground='green')

        # 恢复缓存的日志
        for msg, tag in self.log_buffer:
            self.output_text.insert(tk.END, msg + "\n", tag)

        self.count_label.config(text=str(len(self.log_buffer)))

        # 窗口关闭时隐藏而不是销毁
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        """关闭窗口时隐藏"""
        self.window.withdraw()

    def log(self, message, level='info'):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"

        # 确定标签和调试级别
        tag = 'info'
        debug_level = 'INFO'
        if '⚠️' in message or '警告' in message:
            tag = 'warning'
            debug_level = 'WARNING'
        elif '❌' in message or '错误' in message or '失败' in message:
            tag = 'error'
            debug_level = 'ERROR'
        elif '✅' in message or '成功' in message or '完成' in message:
            tag = 'success'
            debug_level = 'INFO'

        # 发送到调试控制台
        if self.debug_console:
            self.debug_console.log(message, debug_level, "OutputWindow")

        # 缓存日志
        self.log_buffer.append((formatted_msg, tag))

        # 限制缓存大小
        if len(self.log_buffer) > 1000:
            self.log_buffer = self.log_buffer[-500:]

        # 如果窗口存在，写入
        if self.output_text and self.window and self.window.winfo_exists():
            self.output_text.insert(tk.END, formatted_msg + "\n", tag)
            if self.auto_scroll_var.get():
                self.output_text.see(tk.END)
            self.count_label.config(text=str(len(self.log_buffer)))

        # 同时输出到控制台
        console_log(message)

    def clear(self):
        """清空日志"""
        self.log_buffer = []
        if self.output_text:
            self.output_text.delete(1.0, tk.END)
            self.count_label.config(text="0")

    def save_log(self):
        """保存日志到文件"""
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("日志文件", "*.log"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile=f"sysmon_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for msg, _ in self.log_buffer:
                        f.write(msg + "\n")
                messagebox.showinfo("成功", f"日志已保存到:\n{file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {e}")


class SysmonGUI:
    """主窗口类"""

    # 开发模式开关
    DEBUG_MODE = True

    def __init__(self, root):
        self.root = root

        # 应用 ttkbootstrap 主题（朴素浅色风格）
        self.style = ttk.Style(theme='litera')

        self.root.title("Sysinternals 工具集 - 系统监控")
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")

        # 设置网格权重
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # 创建调试控制台（开发模式下自动显示）
        self.debug_console = DebugConsole(self.root, "调试控制台 - 开发模式", auto_show=self.DEBUG_MODE)
        self.debug_console.separator("应用程序启动")
        self.debug_console.info("正在初始化 SysmonGUI...", "Main")

        # 创建独立的输出窗口
        self.output_window = OutputWindow(self.root, self.debug_console)

        # 先初始化基本管理器（轻量级）
        self.debug_console.debug("初始化管理器...", "Main")
        self.process_manager = ProcessManager()
        self.debug_console.debug("ProcessManager 已初始化", "Main")
        self.network_manager = NetworkManager()
        self.debug_console.debug("NetworkManager 已初始化", "Main")
        self.dll_manager = DLLManager()
        self.handle_manager = HandleManager()
        self.dump_manager = DumpManager()
        self.monitor_manager = MonitorManager()
        self.security_manager = SecurityManager()
        self.hash_manager = HashManager()
        self.file_locker = FileLocker()
        self.process_history_manager = ProcessHistoryManager()
        self.eventlog_manager = EventLogManager()
        self.persistence_detector = PersistenceDetector()
        self.user_audit_manager = UserAuditManager()
        self.sandbox_manager = SandboxManager()
        self.debug_console.debug("所有轻量级管理器已初始化", "Main")

        # 延迟初始化重量级管理器（涉及 ctypes DLL 加载）
        self.memory_scanner = None
        self.yara_scanner = None

        self.debug_console.debug("设置 UI...", "Main")
        self.setup_ui()
        self.debug_console.info("UI 设置完成", "Main")

        self.check_tools()
        self.check_admin()

        # 延迟初始化重量级组件
        self.debug_console.debug("延迟初始化重量级组件...", "Main")
        self.root.after(200, self._init_heavy_managers)

    def setup_ui(self):
        """设置UI"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding=5)
        main_frame.grid(row=0, column=0, sticky="nsew")

        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)

        # 顶部标题栏
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        header_frame.grid_columnconfigure(0, weight=1)

        # 标题
        title_label = ttk.Label(
            header_frame,
            text="Sysinternals 工具集成界面",
            font=("微软雅黑", 14, "bold")
        )
        title_label.grid(row=0, column=0)

        # 查看日志按钮
        log_btn = ttk.Button(header_frame, text="查看日志", command=self.output_window.show, width=10)
        log_btn.grid(row=0, column=1, padx=5)

        # 调试控制台按钮（开发模式）
        if self.DEBUG_MODE:
            debug_btn = ttk.Button(header_frame, text="调试控制台", command=self.debug_console.show, width=10)
            debug_btn.grid(row=0, column=2, padx=5)

        # 选项卡视图（现在占据主要空间）
        self.tabview = ttk.Notebook(main_frame)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=2, pady=2)

        # 底部状态栏
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, sticky="ew", pady=(3, 0))

        self.status_label = ttk.Label(status_frame, text="就绪", anchor='w')
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.admin_label = ttk.Label(status_frame, text="", foreground='gray')
        self.admin_label.pack(side=tk.RIGHT, padx=5)

        self.setup_tabs()
    
    def setup_tabs(self):
        """设置选项卡"""
        self.debug_console.debug("创建选项卡 Frames...", "Tabs")
        # 创建各个 tab frame
        self.tab_process = ttk.Frame(self.tabview)
        self.tab_tree = ttk.Frame(self.tabview)
        self.tab_network = ttk.Frame(self.tabview)
        self.tab_dll = ttk.Frame(self.tabview)
        self.tab_handle = ttk.Frame(self.tabview)
        self.tab_dump = ttk.Frame(self.tabview)
        self.tab_procmon = ttk.Frame(self.tabview)
        self.tab_security = ttk.Frame(self.tabview)
        self.tab_hash = ttk.Frame(self.tabview)
        self.tab_locker = ttk.Frame(self.tabview)
        self.tab_memscan = ttk.Frame(self.tabview)
        self.tab_yara = ttk.Frame(self.tabview)
        self.tab_trace = ttk.Frame(self.tabview)
        self.tab_eventlog = ttk.Frame(self.tabview)
        self.tab_persistence = ttk.Frame(self.tabview)
        self.tab_user_audit = ttk.Frame(self.tabview)
        self.tab_sandbox = ttk.Frame(self.tabview)
        self.tab_file_monitor = ttk.Frame(self.tabview)

        self.tabview.add(self.tab_process, text="进程列表")
        self.tabview.add(self.tab_tree, text="进程树")
        self.tabview.add(self.tab_network, text="网络连接")
        self.tabview.add(self.tab_dll, text="DLL检测")
        self.tabview.add(self.tab_handle, text="句柄查询")
        self.tabview.add(self.tab_dump, text="进程转储")
        self.tabview.add(self.tab_procmon, text="Procmon监控")
        self.tabview.add(self.tab_security, text="安全分析")
        self.tabview.add(self.tab_hash, text="Hash计算")
        self.tabview.add(self.tab_locker, text="文件解锁")
        self.tabview.add(self.tab_memscan, text="内存扫描")
        self.tabview.add(self.tab_yara, text="Yara扫描")
        self.tabview.add(self.tab_trace, text="进程溯源")
        self.tabview.add(self.tab_eventlog, text="事件日志")
        self.tabview.add(self.tab_persistence, text="持久化检测")
        self.tabview.add(self.tab_user_audit, text="用户审计")
        self.tabview.add(self.tab_sandbox, text="行为沙箱")
        self.tabview.add(self.tab_file_monitor, text="文件监控")

        # 初始化各个 Tab 类（传递 output_window 作为日志输出）
        self.debug_console.debug("初始化 Tab 类...", "Tabs")

        self.process_tab = ProcessTab(self.tab_process, self.process_manager, self.output_window)
        self.debug_console.debug("ProcessTab 已创建", "Tabs")

        self.process_tree_tab = ProcessTreeTab(self.tab_tree, self.process_manager, self.output_window)
        self.debug_console.debug("ProcessTreeTab 已创建", "Tabs")

        self.network_tab = NetworkTab(self.tab_network, self.network_manager, self.output_window)
        self.debug_console.debug("NetworkTab 已创建", "Tabs")

        self.dll_tab = DllTab(self.tab_dll, self.dll_manager, self.output_window)
        self.handle_tab = HandleTab(self.tab_handle, self.handle_manager, self.output_window)
        self.dump_tab = DumpTab(self.tab_dump, self.dump_manager, self.output_window)
        self.procmon_tab = ProcmonTab(self.tab_procmon, self.monitor_manager, self.output_window)
        self.security_tab = SecurityTab(self.tab_security, self.security_manager, self.output_window)
        self.hash_tab = HashTab(self.tab_hash, self.hash_manager, self.output_window)
        self.file_locker_tab = FileLockerTab(self.tab_locker, self.file_locker, self.output_window)
        self.process_trace_tab = ProcessTraceTab(self.tab_trace, self.process_history_manager, self.output_window)
        self.eventlog_tab = EventLogTab(self.tab_eventlog, self.eventlog_manager, self.output_window)
        self.persistence_tab = PersistenceTab(self.tab_persistence, self.persistence_detector, self.output_window)
        self.user_audit_tab = UserAuditTab(self.tab_user_audit, self.user_audit_manager, self.output_window)
        self.sandbox_tab = SandboxTab(self.tab_sandbox, self.sandbox_manager, self.output_window)
        self.file_monitor_tab = FileMonitorTab(self.tab_file_monitor, None, self.output_window)

        self.debug_console.info("所有 Tab 初始化完成 (共18个)", "Tabs")
        # 延迟初始化的 Tab（使用占位符管理器）
        self.memory_scanner_tab = None
        self.yara_tab = None

    def _init_heavy_managers(self):
        """延迟初始化重量级管理器"""
        self.debug_console.debug("开始初始化重量级管理器...", "Main")

        # 初始化内存扫描器
        try:
            self.memory_scanner = MemoryScanner()
            if self.memory_scanner_tab is None:
                self.memory_scanner_tab = MemoryScannerTab(self.tab_memscan, self.memory_scanner, self.output_window)
            self.debug_console.debug("MemoryScanner 已初始化", "Main")
        except Exception as e:
            self.debug_console.error(f"MemoryScanner 初始化失败: {e}", "Main")

        # 初始化 Yara 扫描器
        try:
            self.yara_scanner = YaraScanner()
            if self.yara_tab is None:
                self.yara_tab = YaraTab(self.tab_yara, self.yara_scanner, self.output_window)
            self.debug_console.debug("YaraScanner 已初始化", "Main")
        except Exception as e:
            self.debug_console.error(f"YaraScanner 初始化失败: {e}", "Main")

        self.debug_console.separator("应用程序就绪")
        self.debug_console.info("所有组件初始化完成，应用程序就绪", "Main")

    def log(self, message):
        """输出日志到独立窗口"""
        self.output_window.log(message)

    def set_status(self, message):
        """设置状态栏消息"""
        self.status_label.config(text=message)

    def check_tools(self):
        """检查工具"""
        self.log("检查 Sysinternals 工具...")
        found_count = 0
        for name, path in TOOLS.items():
            exists = os.path.exists(path)
            if exists:
                found_count += 1
            status = "[已找到]" if exists else "[未找到]"
            self.log(f"  {name}: {status}")
        self.set_status(f"工具检查完成: {found_count}/{len(TOOLS)} 个工具可用")

    def check_admin(self):
        """检查管理员权限"""
        if not is_admin():
            self.log("⚠️ 警告: 未以管理员身份运行")
            self.log("⚠️ 部分功能可能无法正常使用")
            self.admin_label.config(text="⚠️ 非管理员", foreground='orange')
            messagebox.showwarning("权限警告", "建议以管理员身份运行以获得完整功能!")
        else:
            self.log("✅ 已以管理员身份运行")
            self.admin_label.config(text="✅ 管理员", foreground='green')

def main():
    root = tk.Tk()
    app = SysmonGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
