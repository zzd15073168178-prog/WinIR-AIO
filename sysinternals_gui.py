#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sysinternals Tools GUI
一个用于方便调用 Sysinternals 工具的图形界面程序
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import os
from datetime import datetime
import re
import csv


class SysinternalsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sysinternals 工具集 GUI")
        self.root.geometry("1100x750")
        
        # 设置主题样式
        style = ttk.Style()
        style.theme_use('clam')
        
        # 创建主框架
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)
        
        # 创建笔记本（选项卡）
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # 创建进程列表选项卡
        self.create_process_tab()
        
        # 创建三个工具的选项卡
        self.create_handle_tab()
        self.create_listdlls_tab()
        self.create_procdump_tab()
        
        # 创建输出区域
        self.create_output_area()
        
        # 当前执行的进程
        self.current_process = None
        
        # 选中的进程信息
        self.selected_process_name = ""
        self.selected_process_pid = ""

    def create_process_tab(self):
        """创建进程列表选项卡"""
        process_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(process_frame, text="进程列表", state='normal')
        
        # 说明和操作栏
        top_frame = ttk.Frame(process_frame)
        top_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        desc = ttk.Label(top_frame, text="浏览系统进程 - 双击选择进程", 
                        font=('Arial', 10, 'bold'))
        desc.pack(side=tk.LEFT)
        
        ttk.Button(top_frame, text="🔄 刷新", command=self.refresh_process_list, 
                  width=10).pack(side=tk.RIGHT, padx=5)
        
        # 搜索框
        search_frame = ttk.Frame(process_frame)
        search_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        ttk.Label(search_frame, text="搜索:").pack(side=tk.LEFT, padx=(0, 5))
        self.process_search = ttk.Entry(search_frame, width=40)
        self.process_search.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.process_search.bind('<KeyRelease>', self.filter_process_list)
        
        # 创建进程树
        tree_frame = ttk.Frame(process_frame)
        tree_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 创建滚动条
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        # 创建Treeview
        self.process_tree = ttk.Treeview(tree_frame, 
                                         columns=('pid', 'name', 'memory', 'cpu'),
                                         show='headings',
                                         yscrollcommand=vsb.set,
                                         xscrollcommand=hsb.set)
        
        vsb.config(command=self.process_tree.yview)
        hsb.config(command=self.process_tree.xview)
        
        # 配置列
        self.process_tree.heading('pid', text='PID')
        self.process_tree.heading('name', text='进程名称')
        self.process_tree.heading('memory', text='内存使用')
        self.process_tree.heading('cpu', text='CPU时间')
        
        self.process_tree.column('pid', width=80, anchor='center')
        self.process_tree.column('name', width=250, anchor='w')
        self.process_tree.column('memory', width=120, anchor='e')
        self.process_tree.column('cpu', width=120, anchor='e')
        
        # 网格布局
        self.process_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # 绑定双击事件
        self.process_tree.bind('<Double-Button-1>', self.on_process_select)
        
        # 创建右键菜单
        self.process_menu = tk.Menu(self.process_tree, tearoff=0)
        self.process_menu.add_command(label="应用到 Handle", command=lambda: self.apply_to_tool('handle'))
        self.process_menu.add_command(label="应用到 ListDLLs", command=lambda: self.apply_to_tool('listdlls'))
        self.process_menu.add_command(label="应用到 ProcDump", command=lambda: self.apply_to_tool('procdump'))
        self.process_menu.add_separator()
        self.process_menu.add_command(label="复制 PID", command=self.copy_pid)
        self.process_menu.add_command(label="复制进程名", command=self.copy_process_name)
        
        self.process_tree.bind('<Button-3>', self.show_process_menu)
        
        # 信息标签
        info_frame = ttk.Frame(process_frame)
        info_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        self.process_info_label = ttk.Label(info_frame, text="准备就绪")
        self.process_info_label.pack(side=tk.LEFT)
        
        self.selected_info_label = ttk.Label(info_frame, text="", foreground='blue')
        self.selected_info_label.pack(side=tk.RIGHT)
        
        # 配置网格权重
        process_frame.columnconfigure(0, weight=1)
        process_frame.rowconfigure(2, weight=1)
        
        # 初始加载进程列表
        self.refresh_process_list()
    
    def refresh_process_list(self):
        """刷新进程列表"""
        # 清空当前列表
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        self.process_info_label.config(text="正在加载进程列表...")
        
        def load_processes():
            try:
                # 使用tasklist命令获取进程列表（包含更多信息）
                result = subprocess.run(
                    ['tasklist', '/FO', 'CSV', '/NH'],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='replace'
                )
                
                if result.returncode == 0:
                    processes = []
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            # 解析CSV格式
                            parts = [p.strip('"') for p in re.findall(r'"([^"]*)"', line)]
                            if len(parts) >= 5:
                                name = parts[0]
                                pid = parts[1]
                                memory = parts[4]
                                
                                # 获取CPU时间
                                cpu_time = self.get_process_cpu_time(pid)
                                
                                processes.append((pid, name, memory, cpu_time))
                    
                    # 按PID排序
                    processes.sort(key=lambda x: int(x[0]))
                    
                    # 插入到树中
                    for pid, name, memory, cpu_time in processes:
                        self.process_tree.insert('', 'end', values=(pid, name, memory, cpu_time))
                    
                    self.process_info_label.config(text=f"共 {len(processes)} 个进程")
                else:
                    self.process_info_label.config(text="加载失败")
                    messagebox.showerror("错误", "无法获取进程列表")
            
            except Exception as e:
                self.process_info_label.config(text="加载失败")
                messagebox.showerror("错误", f"获取进程列表失败:\n{str(e)}")
        
        # 在新线程中加载
        thread = threading.Thread(target=load_processes, daemon=True)
        thread.start()
    
    def get_process_cpu_time(self, pid):
        """获取进程CPU时间"""
        try:
            result = subprocess.run(
                ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'KernelModeTime,UserModeTime', '/FORMAT:CSV'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='replace',
                timeout=1
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split(',')
                    if len(parts) >= 2:
                        try:
                            kernel = int(parts[0]) if parts[0] else 0
                            user = int(parts[1]) if parts[1] else 0
                            total_ms = (kernel + user) // 10000
                            return f"{total_ms}ms"
                        except:
                            pass
        except:
            pass
        
        return "N/A"
    
    def filter_process_list(self, event=None):
        """过滤进程列表"""
        search_term = self.process_search.get().lower()
        
        for item in self.process_tree.get_children():
            values = self.process_tree.item(item, 'values')
            pid, name = values[0], values[1]
            
            if search_term in name.lower() or search_term in pid:
                self.process_tree.reattach(item, '', 'end')
            else:
                self.process_tree.detach(item)
    
    def on_process_select(self, event):
        """双击选择进程"""
        selection = self.process_tree.selection()
        if selection:
            item = selection[0]
            values = self.process_tree.item(item, 'values')
            self.selected_process_pid = values[0]
            self.selected_process_name = values[1]
            
            self.selected_info_label.config(
                text=f"已选择: {self.selected_process_name} (PID: {self.selected_process_pid})"
            )
            
            # 询问应用到哪个工具
            result = messagebox.askquestion(
                "应用选择",
                f"已选择进程:\n{self.selected_process_name} (PID: {self.selected_process_pid})\n\n是否应用到所有工具?",
                icon='question'
            )
            
            if result == 'yes':
                self.apply_to_all_tools()
            else:
                # 显示选择对话框
                dialog = tk.Toplevel(self.root)
                dialog.title("选择工具")
                dialog.geometry("300x150")
                dialog.transient(self.root)
                dialog.grab_set()
                
                ttk.Label(dialog, text="应用到哪个工具？", 
                         font=('Arial', 10, 'bold')).pack(pady=10)
                
                btn_frame = ttk.Frame(dialog)
                btn_frame.pack(pady=10)
                
                ttk.Button(btn_frame, text="Handle", 
                          command=lambda: [self.apply_to_tool('handle'), dialog.destroy()],
                          width=15).pack(pady=5)
                ttk.Button(btn_frame, text="ListDLLs", 
                          command=lambda: [self.apply_to_tool('listdlls'), dialog.destroy()],
                          width=15).pack(pady=5)
                ttk.Button(btn_frame, text="ProcDump", 
                          command=lambda: [self.apply_to_tool('procdump'), dialog.destroy()],
                          width=15).pack(pady=5)
    
    def show_process_menu(self, event):
        """显示右键菜单"""
        # 选中右键点击的项
        item = self.process_tree.identify_row(event.y)
        if item:
            self.process_tree.selection_set(item)
            values = self.process_tree.item(item, 'values')
            self.selected_process_pid = values[0]
            self.selected_process_name = values[1]
            
            self.process_menu.post(event.x_root, event.y_root)
    
    def apply_to_tool(self, tool):
        """应用选择的进程到指定工具"""
        if not self.selected_process_pid:
            messagebox.showwarning("警告", "请先选择一个进程")
            return
        
        if tool == 'handle':
            self.handle_process.delete(0, tk.END)
            self.handle_process.insert(0, self.selected_process_name)
            self.notebook.select(1)  # 切换到Handle选项卡
            messagebox.showinfo("成功", f"已将进程应用到 Handle\n进程: {self.selected_process_name}")
        elif tool == 'listdlls':
            self.listdlls_process.delete(0, tk.END)
            self.listdlls_process.insert(0, self.selected_process_name)
            self.notebook.select(2)  # 切换到ListDLLs选项卡
            messagebox.showinfo("成功", f"已将进程应用到 ListDLLs\n进程: {self.selected_process_name}")
        elif tool == 'procdump':
            # ProcDump使用PID更可靠，特别是对于系统进程
            self.procdump_process.delete(0, tk.END)
            self.procdump_process.insert(0, self.selected_process_pid)
            self.notebook.select(3)  # 切换到ProcDump选项卡
            messagebox.showinfo(
                "成功", 
                f"已将进程应用到 ProcDump\n"
                f"进程: {self.selected_process_name}\n"
                f"PID: {self.selected_process_pid}\n\n"
                f"注意: 使用PID更可靠！"
            )
    
    def apply_to_all_tools(self):
        """应用到所有工具"""
        if not self.selected_process_pid:
            return
        
        self.handle_process.delete(0, tk.END)
        self.handle_process.insert(0, self.selected_process_name)
        
        self.listdlls_process.delete(0, tk.END)
        self.listdlls_process.insert(0, self.selected_process_name)
        
        # ProcDump使用PID更可靠
        self.procdump_process.delete(0, tk.END)
        self.procdump_process.insert(0, self.selected_process_pid)
        
        messagebox.showinfo(
            "成功", 
            f"已将进程应用到所有工具\n\n"
            f"进程名: {self.selected_process_name}\n"
            f"PID: {self.selected_process_pid}\n\n"
            f"注意: ProcDump使用PID（更可靠）"
        )
    
    def copy_pid(self):
        """复制PID到剪贴板"""
        if self.selected_process_pid:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.selected_process_pid)
            messagebox.showinfo("成功", f"PID {self.selected_process_pid} 已复制到剪贴板")
    
    def copy_process_name(self):
        """复制进程名到剪贴板"""
        if self.selected_process_name:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.selected_process_name)
            messagebox.showinfo("成功", f"进程名 {self.selected_process_name} 已复制到剪贴板")
    
    def filter_results(self, event=None):
        """筛选结果"""
        search_term = self.result_search.get().lower()
        
        # 显示所有项
        for item in self.result_tree.get_children():
            self.result_tree.reattach(item, '', 'end')
        
        if not search_term:
            return
        
        # 隐藏不匹配的项
        for item in self.result_tree.get_children():
            values = self.result_tree.item(item, 'values')
            match = False
            for value in values:
                if search_term in str(value).lower():
                    match = True
                    break
            
            if not match:
                self.result_tree.detach(item)
    
    def clear_filter(self):
        """清除筛选"""
        self.result_search.delete(0, tk.END)
        self.filter_results()
    
    def copy_selected_row(self):
        """复制选中的行"""
        selection = self.result_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一行")
            return
        
        item = selection[0]
        values = self.result_tree.item(item, 'values')
        columns = self.result_tree['columns']
        
        # 创建格式化的文本
        text = '\n'.join([f"{col}: {val}" for col, val in zip(columns, values)])
        
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("成功", "选中行已复制到剪贴板")
    
    def export_csv(self):
        """导出为CSV"""
        if not self.parsed_data:
            messagebox.showwarning("警告", "没有可导出的数据")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
            initialfile=f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
                    if self.parsed_data:
                        writer = csv.DictWriter(f, fieldnames=self.parsed_data[0].keys())
                        writer.writeheader()
                        writer.writerows(self.parsed_data)
                
                messagebox.showinfo("成功", f"数据已导出到:\n{filename}")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败:\n{str(e)}")
    
    def parse_listdlls_output(self, output):
        """解析ListDLLs输出"""
        data = []
        lines = output.split('\n')
        
        current_dll = {}
        dll_path = None
        
        for line in lines:
            line_stripped = line.strip()
            
            # 跳过空行和分隔线
            if not line_stripped or line_stripped.startswith('---') or 'ListDLLs' in line_stripped:
                continue
            
            # 检测DLL路径行（通常以盘符开始或包含路径分隔符）
            if (':\\' in line_stripped or '/' in line_stripped) and not ':' in line_stripped[:20]:
                # 保存之前的DLL记录
                if current_dll and dll_path:
                    current_dll['DLL路径'] = dll_path
                    data.append(current_dll.copy())
                
                # 开始新的DLL记录
                dll_path = line_stripped
                current_dll = {}
            
            # 解析属性行
            elif ':' in line_stripped:
                parts = line_stripped.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    
                    # 只保留有值的非n/a项
                    if value and value.lower() != 'n/a':
                        # 映射英文键名到中文
                        key_mapping = {
                            'Version': '版本',
                            'File version': '文件版本',
                            'Create time': '创建时间',
                            'Publisher': '发布者',
                            'Description': '描述',
                            'Product': '产品',
                            'Base': '基地址',
                            'Size': '大小'
                        }
                        display_key = key_mapping.get(key, key)
                        current_dll[display_key] = value
        
        # 添加最后一个DLL
        if current_dll and dll_path:
            current_dll['DLL路径'] = dll_path
            data.append(current_dll.copy())
        
        # 如果没有解析到数据，尝试简单模式
        if not data:
            current_item = {}
            for line in lines:
                line_stripped = line.strip()
                if ':' in line_stripped and not line_stripped.startswith('==='):
                    parts = line_stripped.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        if value and value.lower() != 'n/a':
                            current_item[key] = value
                            if len(current_item) >= 3:
                                data.append(current_item.copy())
                                current_item = {}
        
        return data
    
    def parse_handle_output(self, output):
        """解析Handle输出"""
        data = []
        lines = output.split('\n')
        
        current_process = None
        current_pid = None
        
        for line in lines:
            line_stripped = line.strip()
            
            # 跳过空行、分隔线和标题
            if not line_stripped or line_stripped.startswith('---') or 'Handle v' in line_stripped:
                continue
            
            # 检测进程头行 (例如: "explorer.exe pid: 1234 NT AUTHORITY\SYSTEM")
            if 'pid:' in line_stripped.lower():
                parts = line_stripped.split('pid:', 1)
                if len(parts) == 2:
                    current_process = parts[0].strip()
                    pid_rest = parts[1].strip().split(None, 1)
                    current_pid = pid_rest[0] if pid_rest else ''
            
            # 检测句柄行 (通常包含句柄ID和类型)
            elif line_stripped and current_process:
                # 句柄行格式: "  0x4: File          C:\Windows\..."
                # 或者: "  0x10: Event         \BaseNamedObjects\..."
                parts = line_stripped.split(':', 1)
                if len(parts) == 2 and parts[0].strip().startswith('0x'):
                    handle_id = parts[0].strip()
                    rest = parts[1].strip()
                    
                    # 分离类型和路径
                    rest_parts = rest.split(None, 1)
                    handle_type = rest_parts[0] if rest_parts else ''
                    handle_path = rest_parts[1] if len(rest_parts) > 1 else ''
                    
                    data.append({
                        '进程': current_process,
                        'PID': current_pid,
                        '句柄': handle_id,
                        '类型': handle_type,
                        '路径或名称': handle_path
                    })
        
        return data
    
    def update_structured_view(self):
        """更新结构化视图"""
        # 清空树
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        
        if not self.parsed_data:
            self.stats_label.config(text="暂无数据")
            return
        
        # 配置列
        if self.parsed_data:
            columns = list(self.parsed_data[0].keys())
            self.result_tree['columns'] = columns
            self.result_tree['show'] = 'headings'
            
            # 设置列标题和宽度
            for col in columns:
                self.result_tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
                # 根据列名设置宽度
                if col in ['基地址', 'PID', '大小']:
                    width = 100
                elif col in ['类型', '进程']:
                    width = 150
                else:
                    width = 400
                self.result_tree.column(col, width=width, anchor='w')
            
            # 插入数据
            for item in self.parsed_data:
                values = [item.get(col, '') for col in columns]
                self.result_tree.insert('', 'end', values=values)
            
            # 更新统计
            self.stats_label.config(text=f"共 {len(self.parsed_data)} 条记录")
    
    def sort_by_column(self, col):
        """按列排序"""
        items = [(self.result_tree.set(item, col), item) for item in self.result_tree.get_children('')]
        items.sort()
        
        for index, (val, item) in enumerate(items):
            self.result_tree.move(item, '', index)

    def create_handle_tab(self):
        """创建 Handle.exe 的选项卡"""
        handle_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(handle_frame, text="Handle")
        
        # 说明
        desc = ttk.Label(handle_frame, text="查看系统中打开的句柄信息", 
                        font=('Arial', 10, 'bold'))
        desc.grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky=tk.W)
        
        # 选项
        row = 1
        
        # 进程名称或PID
        ttk.Label(handle_frame, text="进程名称或PID:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.handle_process = ttk.Entry(handle_frame, width=30)
        self.handle_process.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Label(handle_frame, text="(可选，如 notepad.exe 或 1234)").grid(row=row, column=2, sticky=tk.W)
        
        row += 1
        
        # 对象名称
        ttk.Label(handle_frame, text="对象名称:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.handle_object = ttk.Entry(handle_frame, width=30)
        self.handle_object.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Label(handle_frame, text="(可选，搜索特定对象)").grid(row=row, column=2, sticky=tk.W)
        
        row += 1
        
        # 选项
        self.handle_show_unnamed = tk.BooleanVar()
        ttk.Checkbutton(handle_frame, text="显示未命名句柄 (-u)", 
                       variable=self.handle_show_unnamed).grid(row=row, column=1, sticky=tk.W, pady=5)
        
        row += 1
        
        self.handle_show_all = tk.BooleanVar()
        ttk.Checkbutton(handle_frame, text="显示所有句柄类型 (-a)", 
                       variable=self.handle_show_all).grid(row=row, column=1, sticky=tk.W, pady=5)
        
        row += 1
        
        # 执行按钮
        btn_frame = ttk.Frame(handle_frame)
        btn_frame.grid(row=row, column=0, columnspan=3, pady=20)
        
        ttk.Button(btn_frame, text="执行", command=self.run_handle, 
                  width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空输出", command=self.clear_output, 
                  width=15).pack(side=tk.LEFT, padx=5)
        
        # 配置列权重
        handle_frame.columnconfigure(1, weight=1)

    def create_listdlls_tab(self):
        """创建 Listdlls.exe 的选项卡"""
        listdlls_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(listdlls_frame, text="ListDLLs")
        
        # 说明
        desc = ttk.Label(listdlls_frame, text="列出进程加载的DLL文件信息", 
                        font=('Arial', 10, 'bold'))
        desc.grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky=tk.W)
        
        # 选项
        row = 1
        
        # 进程名称或PID
        ttk.Label(listdlls_frame, text="进程名称或PID:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.listdlls_process = ttk.Entry(listdlls_frame, width=30)
        self.listdlls_process.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Label(listdlls_frame, text="(可选，如 chrome.exe 或 5678)").grid(row=row, column=2, sticky=tk.W)
        
        row += 1
        
        # 选项
        self.listdlls_show_unsigned = tk.BooleanVar()
        ttk.Checkbutton(listdlls_frame, text="仅显示未签名的DLL (-u)", 
                       variable=self.listdlls_show_unsigned).grid(row=row, column=1, sticky=tk.W, pady=5)
        
        row += 1
        
        self.listdlls_show_version = tk.BooleanVar(value=True)
        ttk.Checkbutton(listdlls_frame, text="显示版本信息 (-v)", 
                       variable=self.listdlls_show_version).grid(row=row, column=1, sticky=tk.W, pady=5)
        
        row += 1
        
        # 执行按钮
        btn_frame = ttk.Frame(listdlls_frame)
        btn_frame.grid(row=row, column=0, columnspan=3, pady=20)
        
        ttk.Button(btn_frame, text="执行", command=self.run_listdlls, 
                  width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空输出", command=self.clear_output, 
                  width=15).pack(side=tk.LEFT, padx=5)
        
        # 配置列权重
        listdlls_frame.columnconfigure(1, weight=1)

    def create_procdump_tab(self):
        """创建 Procdump.exe 的选项卡"""
        procdump_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(procdump_frame, text="ProcDump")
        
        # 说明
        desc = ttk.Label(procdump_frame, text="创建进程内存转储文件", 
                        font=('Arial', 10, 'bold'))
        desc.grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky=tk.W)
        
        # 选项
        row = 1
        
        # 进程名称或PID
        ttk.Label(procdump_frame, text="进程名称或PID:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.procdump_process = ttk.Entry(procdump_frame, width=30)
        self.procdump_process.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        hint_label = ttk.Label(procdump_frame, text="(推荐使用PID，如1234)", foreground='blue')
        hint_label.grid(row=row, column=2, sticky=tk.W)
        
        row += 1
        
        # 添加帮助信息
        help_frame = ttk.Frame(procdump_frame)
        help_frame.grid(row=row, column=1, sticky=tk.W, pady=(0, 5))
        ttk.Label(help_frame, text="💡 提示: 从进程列表选择更准确", 
                 font=('Arial', 8), foreground='green').pack(side=tk.LEFT)
        
        row += 1
        
        # 输出目录
        ttk.Label(procdump_frame, text="输出目录:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.procdump_output = ttk.Entry(procdump_frame, width=30)
        self.procdump_output.insert(0, os.getcwd())
        self.procdump_output.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Button(procdump_frame, text="浏览...", 
                  command=self.browse_output_dir).grid(row=row, column=2, sticky=tk.W, padx=5)
        
        row += 1
        
        # 转储选项
        ttk.Label(procdump_frame, text="转储选项:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.procdump_type = ttk.Combobox(procdump_frame, width=28, state='readonly')
        self.procdump_type['values'] = (
            '完整转储 (-ma)',
            '迷你转储 (-mm)',
            '异常时转储 (-e)',
            '挂起时转储 (-h)'
        )
        self.procdump_type.current(0)
        self.procdump_type.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        row += 1
        
        # 转储次数
        ttk.Label(procdump_frame, text="转储次数:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.procdump_count = ttk.Spinbox(procdump_frame, from_=1, to=10, width=28)
        self.procdump_count.set(1)
        self.procdump_count.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        row += 1
        
        # 选项
        self.procdump_compress = tk.BooleanVar()
        ttk.Checkbutton(procdump_frame, text="压缩转储文件 (-z)", 
                       variable=self.procdump_compress).grid(row=row, column=1, sticky=tk.W, pady=5)
        
        row += 1
        
        # 执行按钮
        btn_frame = ttk.Frame(procdump_frame)
        btn_frame.grid(row=row, column=0, columnspan=3, pady=20)
        
        ttk.Button(btn_frame, text="📋 选择进程", 
                  command=lambda: self.notebook.select(0),
                  width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="执行", command=self.run_procdump, 
                  width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空输出", command=self.clear_output, 
                  width=15).pack(side=tk.LEFT, padx=5)
        
        # 配置列权重
        procdump_frame.columnconfigure(1, weight=1)

    def create_output_area(self):
        """创建输出区域"""
        output_frame = ttk.LabelFrame(self.main_frame, text="输出结果", padding="5")
        output_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 创建选项卡用于不同的视图
        self.output_notebook = ttk.Notebook(output_frame)
        self.output_notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 文本视图
        text_frame = ttk.Frame(self.output_notebook)
        self.output_notebook.add(text_frame, text="原始输出")
        
        self.output_text = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, 
                                                     height=15, font=('Consolas', 9))
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # 结构化视图
        structured_frame = ttk.Frame(self.output_notebook)
        self.output_notebook.add(structured_frame, text="结构化视图")
        
        # 统计信息区域
        stats_frame = ttk.Frame(structured_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.stats_label = ttk.Label(stats_frame, text="等待执行命令...", 
                                     font=('Arial', 9, 'bold'), foreground='blue')
        self.stats_label.pack(side=tk.LEFT, padx=5)
        
        # 搜索框
        search_frame = ttk.Frame(structured_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(search_frame, text="筛选:").pack(side=tk.LEFT, padx=(5, 2))
        self.result_search = ttk.Entry(search_frame, width=30)
        self.result_search.pack(side=tk.LEFT, padx=2)
        self.result_search.bind('<KeyRelease>', self.filter_results)
        ttk.Button(search_frame, text="清除", command=self.clear_filter, 
                  width=8).pack(side=tk.LEFT, padx=2)
        
        # 创建结果树
        tree_container = ttk.Frame(structured_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)
        
        vsb = ttk.Scrollbar(tree_container, orient="vertical")
        hsb = ttk.Scrollbar(tree_container, orient="horizontal")
        
        self.result_tree = ttk.Treeview(tree_container,
                                       yscrollcommand=vsb.set,
                                       xscrollcommand=hsb.set)
        
        vsb.config(command=self.result_tree.yview)
        hsb.config(command=self.result_tree.xview)
        
        self.result_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        tree_container.columnconfigure(0, weight=1)
        tree_container.rowconfigure(0, weight=1)
        
        # 按钮框架
        btn_frame = ttk.Frame(output_frame)
        btn_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        ttk.Button(btn_frame, text="保存输出", command=self.save_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制到剪贴板", command=self.copy_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制选中行", command=self.copy_selected_row).pack(side=tk.LEFT, padx=5)
        
        # 配置权重
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        # 存储当前工具类型
        self.current_tool = None
        self.parsed_data = []

    def browse_output_dir(self):
        """浏览输出目录"""
        directory = filedialog.askdirectory(initialdir=self.procdump_output.get())
        if directory:
            self.procdump_output.delete(0, tk.END)
            self.procdump_output.insert(0, directory)

    def append_output(self, text):
        """添加输出文本"""
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.update()

    def clear_output(self):
        """清空输出"""
        self.output_text.delete(1.0, tk.END)

    def save_output(self):
        """保存输出到文件"""
        content = self.output_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showwarning("警告", "没有可保存的内容")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile=f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("成功", f"输出已保存到:\n{filename}")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败:\n{str(e)}")

    def copy_output(self):
        """复制输出到剪贴板"""
        content = self.output_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showwarning("警告", "没有可复制的内容")
            return
        
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("成功", "输出已复制到剪贴板")

    def get_error_explanation(self, exit_code, tool_path):
        """获取错误代码的解释"""
        # 将负数退出代码转换为无符号
        if exit_code < 0:
            exit_code = exit_code + 2**32
        
        tool_name = os.path.basename(tool_path).lower()
        
        # 通用错误
        common_errors = {
            5: "访问被拒绝 - 请尝试以管理员身份运行程序",
            2: "文件或进程未找到 - 请检查进程名称或PID是否正确",
            87: "参数错误 - 请检查命令参数",
        }
        
        # ProcDump特定错误
        if 'procdump' in tool_name:
            if exit_code == 4294967294 or exit_code == 0xFFFFFFFE:
                return ("无法打开进程。\n"
                       "   - 如果使用进程名，请尝试使用PID\n"
                       "   - 系统进程需要管理员权限\n"
                       "   - 建议: 从进程列表中选择进程（会自动使用PID）")
        
        return common_errors.get(exit_code, "未知错误 - 请检查输出信息")
    
    def run_command(self, cmd):
        """在新线程中执行命令"""
        def execute():
            try:
                self.append_output(f"=== 执行命令 ===\n{' '.join(cmd)}\n\n")
                self.append_output(f"=== 开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
                
                # 接受EULA
                env = os.environ.copy()
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    env=env
                )
                
                self.current_process = process
                
                # 收集输出
                output_lines = []
                for line in process.stdout:
                    self.append_output(line)
                    output_lines.append(line)
                
                process.wait()
                
                self.append_output(f"\n=== 结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
                self.append_output(f"=== 退出代码: {process.returncode} ===\n\n")
                
                if process.returncode == 0:
                    self.append_output("✓ 执行成功!\n\n")
                    
                    # 解析输出并更新结构化视图
                    full_output = ''.join(output_lines)
                    self.parse_and_display(full_output, cmd[0])
                else:
                    # 提供错误提示
                    error_msg = self.get_error_explanation(process.returncode, cmd[0])
                    self.append_output(f"✗ 执行失败\n\n")
                    if error_msg:
                        self.append_output(f"💡 可能的原因: {error_msg}\n\n")
                
            except Exception as e:
                self.append_output(f"\n✗ 错误: {str(e)}\n\n")
            finally:
                self.current_process = None
        
        thread = threading.Thread(target=execute, daemon=True)
        thread.start()
    
    def parse_and_display(self, output, tool_path):
        """解析输出并在结构化视图中显示"""
        tool_name = os.path.basename(tool_path).lower()
        
        try:
            if 'listdlls' in tool_name:
                self.parsed_data = self.parse_listdlls_output(output)
                self.current_tool = 'listdlls'
            elif 'handle' in tool_name:
                self.parsed_data = self.parse_handle_output(output)
                self.current_tool = 'handle'
            else:
                # ProcDump不需要结构化视图
                self.parsed_data = []
                self.current_tool = 'procdump'
            
            # 更新视图
            self.update_structured_view()
            
            # 如果有数据，切换到结构化视图
            if self.parsed_data:
                self.output_notebook.select(1)
        except Exception as e:
            print(f"解析错误: {e}")  # 调试用

    def run_handle(self):
        """执行 Handle.exe"""
        cmd = [os.path.join(os.getcwd(), "handle.exe"), "-accepteula"]
        
        # 添加进程参数
        process = self.handle_process.get().strip()
        if process:
            cmd.extend(["-p", process])
        
        # 添加对象名称
        obj = self.handle_object.get().strip()
        if obj:
            cmd.append(obj)
        
        # 添加选项
        if self.handle_show_unnamed.get():
            cmd.append("-u")
        
        if self.handle_show_all.get():
            cmd.append("-a")
        
        self.run_command(cmd)

    def run_listdlls(self):
        """执行 Listdlls.exe"""
        cmd = [os.path.join(os.getcwd(), "Listdlls.exe"), "-accepteula"]
        
        # 添加选项
        if self.listdlls_show_unsigned.get():
            cmd.append("-u")
        
        if self.listdlls_show_version.get():
            cmd.append("-v")
        
        # 添加进程参数
        process = self.listdlls_process.get().strip()
        if process:
            cmd.append(process)
        
        self.run_command(cmd)

    def run_procdump(self):
        """执行 Procdump.exe"""
        process = self.procdump_process.get().strip()
        
        if not process:
            messagebox.showerror("错误", "请指定进程名称或PID")
            return
        
        output_dir = self.procdump_output.get().strip()
        if not os.path.isdir(output_dir):
            messagebox.showerror("错误", "输出目录不存在")
            return
        
        # 检查是否为系统关键进程
        system_processes = ['services.exe', 'csrss.exe', 'smss.exe', 'wininit.exe', 
                          'winlogon.exe', 'lsass.exe', 'System']
        process_lower = process.lower()
        is_system_process = any(sp.lower() in process_lower for sp in system_processes)
        
        # 如果是进程名而不是PID，且是系统进程，给出警告
        if not process.isdigit() and is_system_process:
            result = messagebox.askyesno(
                "系统进程警告",
                f"'{process}' 是系统关键进程！\n\n"
                f"建议使用PID而不是进程名称。\n"
                f"是否从进程列表中重新选择？\n\n"
                f"点击'是'返回进程列表\n"
                f"点击'否'继续尝试执行（可能失败）",
                icon='warning'
            )
            
            if result:
                self.notebook.select(0)  # 切换到进程列表
                messagebox.showinfo(
                    "提示",
                    f"请在进程列表中找到 {process}，\n"
                    f"右键点击选择'应用到 ProcDump'，\n"
                    f"程序会自动使用PID（更可靠）"
                )
                return
        
        cmd = [os.path.join(os.getcwd(), "procdump.exe"), "-accepteula"]
        
        # 添加转储类型
        dump_type = self.procdump_type.get()
        if "完整转储" in dump_type:
            cmd.append("-ma")
        elif "迷你转储" in dump_type:
            cmd.append("-mm")
        elif "异常时转储" in dump_type:
            cmd.append("-e")
        elif "挂起时转储" in dump_type:
            cmd.append("-h")
        
        # 添加压缩选项
        if self.procdump_compress.get():
            cmd.append("-z")
        
        # 添加转储次数
        count = self.procdump_count.get()
        if count and int(count) > 1:
            cmd.extend(["-n", str(count)])
        
        # 添加进程和输出目录
        cmd.append(process)
        cmd.append(output_dir)
        
        self.run_command(cmd)


def main():
    root = tk.Tk()
    app = SysinternalsGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

