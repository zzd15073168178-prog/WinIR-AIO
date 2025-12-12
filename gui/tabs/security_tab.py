#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安全分析选项卡 - 集成 Autoruns"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import os
import webbrowser

from .base_tab import BaseTab


class SecurityTab(BaseTab):
    """安全分析选项卡 - 基于 Autoruns"""
    
    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.current_category = 'all'
        self.show_suspicious_only = False
        super().__init__(parent, manager, "🔒 安全分析")
    
    def setup_ui(self):
        """设置UI"""
        # 顶部工具栏
        toolbar = ttk.Frame(self.frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        # 扫描模式选择
        ttk.Label(toolbar, text="扫描:").pack(side=tk.LEFT, padx=(0, 3))
        self.scan_preset_var = tk.StringVar(value='quick')
        scan_presets = [
            ('⚡ 快速', 'quick'),
            ('📊 标准', 'standard'),
            ('🔍 完整', 'full'),
        ]
        for text, value in scan_presets:
            ttk.Radiobutton(toolbar, text=text, variable=self.scan_preset_var,
                           value=value).pack(side=tk.LEFT, padx=2)

        ttk.Button(toolbar, text="开始扫描", command=self.scan_with_preset).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🔄 刷新", command=self.refresh_display).pack(side=tk.LEFT, padx=3)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        # 过滤按钮
        ttk.Button(toolbar, text="⚠️ 仅可疑", command=self.filter_suspicious).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="📝 未签名", command=self.filter_unsigned).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="📋 显示全部", command=self.show_all).pack(side=tk.LEFT, padx=3)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        # 工具按钮
        ttk.Button(toolbar, text="📥 下载工具", command=self.download_tool).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="🚀 打开 Autoruns", command=self.open_autoruns_gui).pack(side=tk.LEFT, padx=3)

        # 分类选择
        cat_frame = ttk.Frame(self.frame)
        cat_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(cat_frame, text="分类:").pack(side=tk.LEFT, padx=5)
        self.category_var = tk.StringVar(value='all')
        self.category_combo = ttk.Combobox(cat_frame, textvariable=self.category_var,
                                           state='readonly', width=20)
        self.category_combo['values'] = ['全部']
        self.category_combo.pack(side=tk.LEFT, padx=5)
        self.category_combo.bind('<<ComboboxSelected>>', self.on_category_change)

        # 搜索框
        ttk.Label(cat_frame, text="搜索:").pack(side=tk.LEFT, padx=(20, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(cat_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        self.search_var.trace('w', lambda *a: self.refresh_display())
        
        # 列表区域
        list_frame = ttk.Frame(self.frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 创建Treeview
        columns = ('name', 'category', 'company', 'path', 'signer', 'timestamp', 'status')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=18)

        self.tree.heading('name', text='名称')
        self.tree.heading('category', text='分类')
        self.tree.heading('company', text='公司')
        self.tree.heading('path', text='路径')
        self.tree.heading('signer', text='签名')
        self.tree.heading('timestamp', text='时间')
        self.tree.heading('status', text='状态')

        self.tree.column('name', width=180)
        self.tree.column('category', width=80)
        self.tree.column('company', width=150)
        self.tree.column('path', width=280)
        self.tree.column('signer', width=150)
        self.tree.column('timestamp', width=90)
        self.tree.column('status', width=80)
        
        # 颜色标签
        self.tree.tag_configure('suspicious', background='#ffcccc', foreground='#8B0000')
        self.tree.tag_configure('unsigned', background='#fff3cd', foreground='#856404')
        self.tree.tag_configure('verified', background='#d4edda', foreground='#155724')
        self.tree.tag_configure('disabled', background='#e9ecef', foreground='#6c757d')
        self.tree.tag_configure('normal', background='white', foreground='black')
        
        scrollbar_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 绑定事件
        self.tree.bind('<Double-1>', lambda e: self._show_detail())
        self._setup_context_menu()
        
        # 状态栏
        self.status_label = ttk.Label(self.frame, text="状态: 等待扫描... (需要 autorunsc.exe)")
        self.status_label.pack(pady=5)
        
        # 检查工具
        self.check_tool()
    
    def _setup_context_menu(self):
        """设置右键菜单"""
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="📋 查看详情", command=self._show_detail)
        self.context_menu.add_command(label="📄 复制路径", command=self._copy_path)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📁 打开文件位置", command=self._open_location)
        self.context_menu.add_command(label="🔍 在线搜索", command=self._search_online)
        self.context_menu.add_command(label="🛡️ VirusTotal查询", command=self._check_virustotal)
        
        self.tree.bind('<Button-3>', self._show_context_menu)
    
    def _show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def check_tool(self):
        """检查工具是否可用"""
        if self.manager.is_tool_available():
            self.status_label.configure(text=f"状态: 已找到 autorunsc.exe，点击'扫描全部'开始")
            self.log(f"✅ 找到 Autoruns: {self.manager.tool_path}", self.output_widget)
        else:
            self.status_label.configure(text="状态: 未找到 autorunsc.exe，请点击'下载工具'")
            self.log("⚠️ 未找到 autorunsc.exe，请点击'下载工具'按钮", self.output_widget)
    
    def download_tool(self):
        """下载 Autoruns 工具"""
        if self.manager.is_tool_available():
            messagebox.showinfo("提示", "autorunsc.exe 已存在")
            return
        
        self.status_label.configure(text="状态: 正在下载...")
        self.log("📥 正在下载 autorunsc.exe...", self.output_widget)
        
        def download():
            def callback(msg):
                self.frame.after(0, lambda m=msg: self.log(f"  {m}", self.output_widget))
            
            success = self.manager.download_tool(callback)
            
            if success:
                self.frame.after(0, lambda: self.status_label.configure(
                    text="状态: 下载完成，可以开始扫描"))
                self.frame.after(0, lambda: messagebox.showinfo("完成", "下载成功!"))
            else:
                self.frame.after(0, lambda: self.status_label.configure(
                    text="状态: 下载失败"))
        
        threading.Thread(target=download, daemon=True).start()
    
    def open_autoruns_gui(self):
        """打开 Autoruns GUI 版本"""
        gui_path = os.path.join(os.path.dirname(self.manager.tool_path or ''), "Autoruns.exe")
        if os.path.exists(gui_path):
            os.startfile(gui_path)
        else:
            # 尝试下载或提示
            webbrowser.open("https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns")
            messagebox.showinfo("提示", "请从微软官网下载 Autoruns GUI 版本")
    
    def scan_with_preset(self):
        """使用预设模式扫描"""
        preset = self.scan_preset_var.get()
        self._do_scan(preset=preset)

    def scan_all(self):
        """扫描全部（完整扫描）"""
        self._do_scan(preset='full')

    def _do_scan(self, preset=None, scan_options=None):
        """执行扫描"""
        if not self.manager.is_tool_available():
            messagebox.showwarning("提示", "请先下载 autorunsc.exe")
            return

        # 获取预设信息
        preset_info = self.manager.SCAN_PRESETS.get(preset, {})
        preset_name = preset_info.get('name', '扫描')

        self.status_label.configure(text=f"状态: 正在{preset_name}...")
        self.log(f"🔍 开始 {preset_name}...", self.output_widget)

        def scan():
            try:
                def callback(msg):
                    try:
                        self.frame.after(0, lambda m=msg: self.log(f"  {m}", self.output_widget))
                    except:
                        pass

                self.manager.scan(progress_callback=callback, preset=preset, scan_options=scan_options)

                try:
                    self.frame.after(0, self._scan_complete)
                except:
                    pass
            except Exception as e:
                try:
                    self.frame.after(0, lambda err=str(e): self.log(f"❌ 扫描失败: {err}", self.output_widget))
                except:
                    pass

        threading.Thread(target=scan, daemon=True).start()
    
    def _scan_complete(self):
        """扫描完成"""
        summary = self.manager.get_summary()
        
        self.log(f"🔒 Autoruns 扫描完成!", self.output_widget)
        self.log(f"  📊 总计: {summary['total']} 项", self.output_widget)
        self.log(f"  ⚠️ 可疑: {summary['suspicious']} 项", self.output_widget)
        self.log(f"  📝 未签名: {summary['unsigned']} 项", self.output_widget)
        
        # 更新分类下拉框
        categories = self.manager.get_categories()
        cat_list = ['全部'] + [f"{v['name_cn']} ({v['count']})" for k, v in categories.items()]
        self.category_combo['values'] = cat_list
        
        # 刷新显示
        self.refresh_display()
        
        # 警告
        if summary['suspicious'] > 0:
            messagebox.showwarning("安全警告", 
                f"发现 {summary['suspicious']} 个可疑项!\n\n"
                f"请点击'仅可疑'按钮查看详情。")
    
    def refresh_display(self):
        """刷新显示"""
        # 清除现有项
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        data = self.manager.autoruns_data
        search = self.search_var.get().strip().lower()
        
        # 分类过滤
        if self.current_category != 'all':
            data = [item for item in data if item['category'] == self.current_category]
        
        # 可疑过滤
        if self.show_suspicious_only == 'suspicious':
            data = [item for item in data if item['is_suspicious']]
        elif self.show_suspicious_only == 'unsigned':
            data = [item for item in data if not item['is_verified'] and item['path']]
        
        count = 0
        suspicious_count = 0
        
        for item in data:
            # 搜索过滤
            if search:
                searchable = f"{item['name']} {item['path']} {item['company']} {item['description']}".lower()
                if search not in searchable:
                    continue
            
            # 确定标签
            if item['is_suspicious']:
                tag = 'suspicious'
                suspicious_count += 1
            elif not item['is_verified'] and item['path']:
                tag = 'unsigned'
            elif item['is_verified']:
                tag = 'verified'
            elif not item['enabled']:
                tag = 'disabled'
            else:
                tag = 'normal'
            
            # 状态文本
            status = "⚠️ 可疑" if item['is_suspicious'] else ("✓ 已验证" if item['is_verified'] else "未验证")
            if not item['enabled']:
                status = "已禁用"
            
            # 插入数据 (包含时间戳)
            values = (
                item['name'],
                item['category_cn'],
                item['company'],
                item['path'],
                item['signer'][:30] if item['signer'] else '',
                item.get('timestamp', ''),  # 时间戳列
                status
            )
            self.tree.insert('', tk.END, values=values, tags=(tag,))
            count += 1
        
        # 更新状态
        status = f"状态: 显示 {count} 项"
        if suspicious_count > 0:
            status += f" (⚠️ {suspicious_count} 可疑)"
        self.status_label.configure(text=status)
    
    def on_category_change(self, event=None):
        """分类改变"""
        selected = self.category_var.get()
        if selected == '全部':
            self.current_category = 'all'
        else:
            # 从显示文本提取分类名
            categories = self.manager.get_categories()
            for cat_key, cat_val in categories.items():
                if cat_val['name_cn'] in selected:
                    self.current_category = cat_key
                    break
        
        self.refresh_display()
    
    def filter_suspicious(self):
        """只显示可疑项"""
        self.show_suspicious_only = 'suspicious'
        self.refresh_display()
    
    def filter_unsigned(self):
        """只显示未签名项"""
        self.show_suspicious_only = 'unsigned'
        self.refresh_display()
    
    def show_all(self):
        """显示全部"""
        self.show_suspicious_only = False
        self.refresh_display()
    
    def _get_selected_item(self):
        """获取选中项"""
        selection = self.tree.selection()
        if not selection:
            return None
        
        values = self.tree.item(selection[0])['values']
        if not values:
            return None
        
        # 根据名称查找完整数据
        name = values[0]
        for item in self.manager.autoruns_data:
            if item['name'] == name:
                return item
        return None
    
    def _show_detail(self):
        """显示详情"""
        item = self._get_selected_item()
        if not item:
            return
        
        detail = {
            '名称': item['name'],
            '分类': item['category_cn'],
            '描述': item['description'],
            '创建时间': item.get('timestamp', '') or '未知',
            '---1': '',
            '路径': item['path'],
            '启动命令': item['launch_string'],
            '公司': item['company'],
            '版本': item['version'],
            '---2': '',
            '签名': item['signer'],
            '已验证': '是' if item['is_verified'] else '否',
            '---3': '',
            'MD5': item['md5'],
            'SHA-1': item['sha1'],
            'SHA-256': item['sha256'],
        }
        
        self.show_detail_dialog(f"详情 - {item['name']}", detail)
    
    def _copy_path(self):
        """复制路径"""
        item = self._get_selected_item()
        if item and item['path']:
            self.tree.clipboard_clear()
            self.tree.clipboard_append(item['path'])
            self.log(f"📋 已复制: {item['path']}", self.output_widget)
    
    def _open_location(self):
        """打开文件位置"""
        item = self._get_selected_item()
        if item and item['path'] and os.path.exists(item['path']):
            folder = os.path.dirname(item['path'])
            os.startfile(folder)
    
    def _search_online(self):
        """在线搜索"""
        item = self._get_selected_item()
        if item:
            query = item['name']
            if item['md5']:
                query = item['md5']
            webbrowser.open(f"https://www.google.com/search?q={query}+malware+or+legitimate")
    
    def _check_virustotal(self):
        """VirusTotal 查询"""
        item = self._get_selected_item()
        if item and item['sha256']:
            webbrowser.open(f"https://www.virustotal.com/gui/file/{item['sha256']}")
        elif item and item['md5']:
            webbrowser.open(f"https://www.virustotal.com/gui/file/{item['md5']}")
        else:
            messagebox.showinfo("提示", "没有哈希值，无法查询 VirusTotal")
    
    def _on_double_click(self, tree):
        """双击事件"""
        self._show_detail()
