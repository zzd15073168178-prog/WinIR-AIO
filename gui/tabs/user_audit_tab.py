#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用户账户审计选项卡"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
from datetime import datetime

from .base_tab import BaseTab


class UserAuditTab(BaseTab):
    """用户账户审计选项卡

    功能：
    - 本地用户枚举
    - 隐藏账户检测
    - 登录历史分析
    - RDP 会话监控
    - 本地组审计
    """

    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.current_view = 'users'  # users, hidden, login, rdp, groups
        super().__init__(parent, manager, "用户审计")

    def setup_ui(self):
        """设置UI"""
        # ============== 顶部工具栏 ==============
        toolbar = ttk.Frame(self.frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="完整审计",
                   command=self.run_full_audit).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        ttk.Button(toolbar, text="用户列表",
                   command=self.refresh_users).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="隐藏账户",
                   command=self.detect_hidden).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="登录历史",
                   command=self.get_login_history).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="RDP会话",
                   command=self.get_rdp_sessions).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="本地组",
                   command=self.get_groups).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        ttk.Button(toolbar, text="导出报告",
                   command=self.export_report).pack(side=tk.LEFT, padx=2)

        # 登录历史天数
        ttk.Label(toolbar, text="历史天数:").pack(side=tk.RIGHT, padx=(10, 2))
        self.days_var = tk.StringVar(value='7')
        days_entry = ttk.Entry(toolbar, textvariable=self.days_var, width=5)
        days_entry.pack(side=tk.RIGHT, padx=2)

        # ============== 视图切换标签 ==============
        view_frame = ttk.Frame(self.frame)
        view_frame.pack(fill=tk.X, padx=5, pady=2)

        self.view_var = tk.StringVar(value='users')
        views = [
            ('用户', 'users'),
            ('隐藏账户', 'hidden'),
            ('登录历史', 'login'),
            ('RDP会话', 'rdp'),
            ('本地组', 'groups')
        ]
        for text, value in views:
            rb = ttk.Radiobutton(view_frame, text=text, variable=self.view_var,
                                value=value, command=self.on_view_change)
            rb.pack(side=tk.LEFT, padx=5)

        # 搜索框
        ttk.Label(view_frame, text="搜索:").pack(side=tk.RIGHT, padx=(10, 2))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(view_frame, textvariable=self.search_var, width=20)
        search_entry.pack(side=tk.RIGHT, padx=2)
        self.search_var.trace('w', lambda *a: self.refresh_display())

        # ============== 主内容区域 ==============
        main_frame = ttk.Frame(self.frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 使用 PanedWindow
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # 左侧：摘要面板
        summary_frame = ttk.LabelFrame(paned, text="审计摘要", width=200)
        paned.add(summary_frame, weight=1)
        self._create_summary_panel(summary_frame)

        # 右侧：结果列表
        list_frame = ttk.Frame(paned)
        paned.add(list_frame, weight=4)
        self._create_results_tree(list_frame)

        # ============== 底部状态栏 ==============
        self.status_label = ttk.Label(self.frame, text="状态: 等待操作...")
        self.status_label.pack(pady=5)

    def _create_summary_panel(self, parent):
        """创建摘要面板"""
        self.summary_text = tk.Text(parent, wrap=tk.WORD, width=25, height=25,
                                    font=("Consolas", 9))
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.summary_text.config(state=tk.DISABLED)
        self._update_summary_display()

    def _create_results_tree(self, parent):
        """创建结果列表"""
        # 创建多个 Treeview 用于不同视图
        self.trees = {}
        self.tree_frames = {}

        # 用户视图
        self._create_users_tree(parent)

        # 隐藏账户视图
        self._create_hidden_tree(parent)

        # 登录历史视图
        self._create_login_tree(parent)

        # RDP 会话视图
        self._create_rdp_tree(parent)

        # 组视图
        self._create_groups_tree(parent)

        # 默认显示用户视图
        self.show_view('users')

    def _create_users_tree(self, parent):
        """创建用户列表树"""
        frame = ttk.Frame(parent)
        columns = ('name', 'status', 'admin', 'last_logon', 'groups', 'risk', 'sid')

        tree = ttk.Treeview(frame, columns=columns, show='headings', height=20)
        tree.heading('name', text='用户名')
        tree.heading('status', text='状态')
        tree.heading('admin', text='管理员')
        tree.heading('last_logon', text='上次登录')
        tree.heading('groups', text='所属组')
        tree.heading('risk', text='风险等级')
        tree.heading('sid', text='SID')

        tree.column('name', width=120)
        tree.column('status', width=60)
        tree.column('admin', width=60)
        tree.column('last_logon', width=150)
        tree.column('groups', width=200)
        tree.column('risk', width=80)
        tree.column('sid', width=300)

        self._setup_tree_tags(tree)
        self._add_scrollbars(frame, tree)

        tree.bind('<Double-1>', lambda e: self._show_user_detail())
        self._setup_user_context_menu(tree)

        self.trees['users'] = tree
        self.tree_frames['users'] = frame

    def _create_hidden_tree(self, parent):
        """创建隐藏账户树"""
        frame = ttk.Frame(parent)
        columns = ('name', 'method', 'severity', 'description')

        tree = ttk.Treeview(frame, columns=columns, show='headings', height=20)
        tree.heading('name', text='用户名')
        tree.heading('method', text='隐藏方法')
        tree.heading('severity', text='严重程度')
        tree.heading('description', text='描述')

        tree.column('name', width=150)
        tree.column('method', width=200)
        tree.column('severity', width=100)
        tree.column('description', width=400)

        self._setup_tree_tags(tree)
        self._add_scrollbars(frame, tree)

        self.trees['hidden'] = tree
        self.tree_frames['hidden'] = frame

    def _create_login_tree(self, parent):
        """创建登录历史树"""
        frame = ttk.Frame(parent)
        columns = ('time', 'user', 'type', 'logon_type', 'source_ip', 'workstation')

        tree = ttk.Treeview(frame, columns=columns, show='headings', height=20)
        tree.heading('time', text='时间')
        tree.heading('user', text='用户')
        tree.heading('type', text='事件类型')
        tree.heading('logon_type', text='登录类型')
        tree.heading('source_ip', text='来源 IP')
        tree.heading('workstation', text='工作站')

        tree.column('time', width=150)
        tree.column('user', width=120)
        tree.column('type', width=80)
        tree.column('logon_type', width=150)
        tree.column('source_ip', width=120)
        tree.column('workstation', width=150)

        self._setup_tree_tags(tree)
        self._add_scrollbars(frame, tree)

        self.trees['login'] = tree
        self.tree_frames['login'] = frame

    def _create_rdp_tree(self, parent):
        """创建 RDP 会话树"""
        frame = ttk.Frame(parent)
        columns = ('type', 'username', 'session', 'state', 'server', 'description')

        tree = ttk.Treeview(frame, columns=columns, show='headings', height=20)
        tree.heading('type', text='类型')
        tree.heading('username', text='用户')
        tree.heading('session', text='会话')
        tree.heading('state', text='状态')
        tree.heading('server', text='服务器')
        tree.heading('description', text='描述')

        tree.column('type', width=100)
        tree.column('username', width=120)
        tree.column('session', width=100)
        tree.column('state', width=80)
        tree.column('server', width=150)
        tree.column('description', width=300)

        self._setup_tree_tags(tree)
        self._add_scrollbars(frame, tree)

        self.trees['rdp'] = tree
        self.tree_frames['rdp'] = frame

    def _create_groups_tree(self, parent):
        """创建组列表树"""
        frame = ttk.Frame(parent)
        columns = ('name', 'privileged', 'member_count', 'members')

        tree = ttk.Treeview(frame, columns=columns, show='headings', height=20)
        tree.heading('name', text='组名')
        tree.heading('privileged', text='特权组')
        tree.heading('member_count', text='成员数')
        tree.heading('members', text='成员')

        tree.column('name', width=200)
        tree.column('privileged', width=80)
        tree.column('member_count', width=80)
        tree.column('members', width=500)

        self._setup_tree_tags(tree)
        self._add_scrollbars(frame, tree)

        self.trees['groups'] = tree
        self.tree_frames['groups'] = frame

    def _setup_tree_tags(self, tree):
        """设置树的颜色标签"""
        tree.tag_configure('critical', background='#ffcccc', foreground='#8B0000')
        tree.tag_configure('high', background='#ffddcc', foreground='#8B4500')
        tree.tag_configure('warning', background='#fff3cd', foreground='#856404')
        tree.tag_configure('info', background='#e2e3e5', foreground='#383d41')
        tree.tag_configure('normal', background='white', foreground='black')
        tree.tag_configure('success', background='#d4edda', foreground='#155724')

    def _add_scrollbars(self, frame, tree):
        """添加滚动条"""
        scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

    def _setup_user_context_menu(self, tree):
        """设置用户列表右键菜单"""
        menu = tk.Menu(tree, tearoff=0)
        menu.add_command(label="查看详情", command=self._show_user_detail)
        menu.add_command(label="复制用户名", command=lambda: self._copy_field(0))
        menu.add_command(label="复制 SID", command=lambda: self._copy_field(6))
        menu.add_separator()
        menu.add_command(label="复制全部信息", command=self._copy_all)

        def show_menu(event):
            item = tree.identify_row(event.y)
            if item:
                tree.selection_set(item)
                menu.post(event.x_root, event.y_root)

        tree.bind('<Button-3>', show_menu)

    def show_view(self, view_name):
        """显示指定视图"""
        # 隐藏所有视图
        for name, frame in self.tree_frames.items():
            frame.pack_forget()

        # 显示目标视图
        if view_name in self.tree_frames:
            self.tree_frames[view_name].pack(fill=tk.BOTH, expand=True)
            self.current_view = view_name

    def on_view_change(self):
        """视图切换"""
        view = self.view_var.get()
        self.show_view(view)

    # ==================== 核心功能 ====================

    def run_full_audit(self):
        """执行完整审计"""
        self.status_label.configure(text="状态: 正在执行完整审计...")
        self.log("开始完整用户审计...", self.output_widget)

        def do_audit():
            try:
                result = self.manager.run_full_audit()
                self.safe_after(self._on_audit_complete, result)
            except Exception as e:
                self.safe_after(lambda: self.log(f"审计失败: {e}", self.output_widget))
                self.safe_after(lambda: self.status_label.configure(text="状态: 审计失败"))

        threading.Thread(target=do_audit, daemon=True).start()

    def _on_audit_complete(self, result):
        """审计完成回调"""
        summary = result.get('summary', {})

        self.log("完整审计完成!", self.output_widget)
        self.log(f"  用户总数: {summary.get('total_users', 0)}", self.output_widget)
        self.log(f"  隐藏账户: {summary.get('hidden_users', 0)}", self.output_widget)
        self.log(f"  高风险用户: {summary.get('high_risk_users', 0)}", self.output_widget)
        self.log(f"  登录记录: {summary.get('recent_logins', 0)}", self.output_widget)

        self._update_summary_display()
        self._refresh_all_views()

        # 警告
        if summary.get('hidden_users', 0) > 0:
            messagebox.showwarning("安全警告",
                f"检测到 {summary['hidden_users']} 个隐藏账户!\n\n"
                "请切换到'隐藏账户'视图查看详情。")

        self.status_label.configure(text=f"状态: 审计完成 - {summary.get('total_users', 0)} 个用户")

    def refresh_users(self):
        """刷新用户列表"""
        self.status_label.configure(text="状态: 获取用户列表...")
        self.log("获取本地用户列表...", self.output_widget)

        def do_refresh():
            try:
                self.manager.get_local_users()
                self.safe_after(self._display_users)
            except Exception as e:
                self.safe_after(lambda: self.log(f"获取用户失败: {e}", self.output_widget))

        threading.Thread(target=do_refresh, daemon=True).start()

    def detect_hidden(self):
        """检测隐藏账户"""
        self.status_label.configure(text="状态: 检测隐藏账户...")
        self.log("检测隐藏账户...", self.output_widget)

        def do_detect():
            try:
                if not self.manager.users:
                    self.manager.get_local_users()
                self.manager.detect_hidden_users()
                self.safe_after(self._display_hidden)
            except Exception as e:
                self.safe_after(lambda: self.log(f"检测失败: {e}", self.output_widget))

        threading.Thread(target=do_detect, daemon=True).start()

    def get_login_history(self):
        """获取登录历史"""
        try:
            days = int(self.days_var.get())
        except:
            days = 7

        self.status_label.configure(text=f"状态: 获取 {days} 天登录历史...")
        self.log(f"获取 {days} 天登录历史...", self.output_widget)

        def do_get():
            try:
                self.manager.get_login_history(days=days)
                self.safe_after(self._display_login_history)
            except Exception as e:
                self.safe_after(lambda: self.log(f"获取登录历史失败: {e}", self.output_widget))

        threading.Thread(target=do_get, daemon=True).start()

    def get_rdp_sessions(self):
        """获取 RDP 会话"""
        self.status_label.configure(text="状态: 获取 RDP 会话...")
        self.log("获取 RDP 会话...", self.output_widget)

        def do_get():
            try:
                self.manager.get_rdp_sessions()
                self.safe_after(self._display_rdp_sessions)
            except Exception as e:
                self.safe_after(lambda: self.log(f"获取 RDP 会话失败: {e}", self.output_widget))

        threading.Thread(target=do_get, daemon=True).start()

    def get_groups(self):
        """获取本地组"""
        self.status_label.configure(text="状态: 获取本地组...")
        self.log("获取本地组...", self.output_widget)

        def do_get():
            try:
                self.manager.get_local_groups()
                self.safe_after(self._display_groups)
            except Exception as e:
                self.safe_after(lambda: self.log(f"获取组失败: {e}", self.output_widget))

        threading.Thread(target=do_get, daemon=True).start()

    # ==================== 显示功能 ====================

    def _refresh_all_views(self):
        """刷新所有视图"""
        self._display_users()
        self._display_hidden()
        self._display_login_history()
        self._display_rdp_sessions()
        self._display_groups()

    def _display_users(self):
        """显示用户列表"""
        tree = self.trees['users']
        for item in tree.get_children():
            tree.delete(item)

        search = self.search_var.get().strip().lower()

        count = 0
        for user in self.manager.users:
            # 搜索过滤
            if search:
                searchable = f"{user['name']} {user.get('full_name', '')} {user.get('sid', '')}".lower()
                if search not in searchable:
                    continue

            status = "启用" if user['active'] else "禁用"
            admin = "是" if user['is_admin'] else "否"
            groups = ', '.join(user.get('groups', [])[:3])
            if len(user.get('groups', [])) > 3:
                groups += '...'

            values = (
                user['name'],
                status,
                admin,
                user.get('last_logon', ''),
                groups,
                user['risk_level'],
                user.get('sid', '')
            )

            tag = user['risk_level'] if user['risk_level'] != 'normal' else 'normal'
            tree.insert('', tk.END, values=values, tags=(tag,))
            count += 1

        self.view_var.set('users')
        self.show_view('users')
        self.status_label.configure(text=f"状态: 显示 {count} 个用户")
        self._update_summary_display()

    def _display_hidden(self):
        """显示隐藏账户"""
        tree = self.trees['hidden']
        for item in tree.get_children():
            tree.delete(item)

        count = 0
        for hidden in self.manager.hidden_users:
            values = (
                hidden['name'],
                hidden['method'],
                hidden['severity'],
                f"检测到隐藏账户: {hidden['name']}"
            )

            tree.insert('', tk.END, values=values, tags=(hidden['severity'],))
            count += 1

        self.view_var.set('hidden')
        self.show_view('hidden')

        if count > 0:
            self.log(f"检测到 {count} 个隐藏账户!", self.output_widget)
        else:
            self.log("未检测到隐藏账户", self.output_widget)

        self.status_label.configure(text=f"状态: 显示 {count} 个隐藏账户")

    def _display_login_history(self):
        """显示登录历史"""
        tree = self.trees['login']
        for item in tree.get_children():
            tree.delete(item)

        search = self.search_var.get().strip().lower()

        count = 0
        for login in self.manager.login_history:
            # 搜索过滤
            if search:
                searchable = f"{login.get('user', '')} {login.get('source_ip', '')}".lower()
                if search not in searchable:
                    continue

            values = (
                login.get('time', ''),
                login.get('user', ''),
                login.get('type', ''),
                login.get('logon_type_desc', ''),
                login.get('source_ip', ''),
                login.get('workstation', '')
            )

            # 登录失败标红
            tag = 'warning' if login.get('event_id') == '4625' else 'normal'
            # RDP 登录高亮
            if login.get('logon_type') == '10':
                tag = 'info'

            tree.insert('', tk.END, values=values, tags=(tag,))
            count += 1

        self.view_var.set('login')
        self.show_view('login')
        self.log(f"获取到 {count} 条登录记录", self.output_widget)
        self.status_label.configure(text=f"状态: 显示 {count} 条登录记录")

    def _display_rdp_sessions(self):
        """显示 RDP 会话"""
        tree = self.trees['rdp']
        for item in tree.get_children():
            tree.delete(item)

        count = 0
        for session in self.manager.rdp_sessions:
            session_type = session.get('type', '')

            if session_type == 'active_session':
                values = (
                    '活动会话',
                    session.get('username', ''),
                    session.get('session_name', ''),
                    session.get('state', ''),
                    '',
                    'RDP' if session.get('is_rdp') else '本地'
                )
                tag = 'info' if session.get('is_rdp') else 'normal'
            else:
                values = (
                    'RDP历史',
                    session.get('username', ''),
                    '',
                    '',
                    session.get('server', ''),
                    session.get('description', '')
                )
                tag = 'normal'

            tree.insert('', tk.END, values=values, tags=(tag,))
            count += 1

        self.view_var.set('rdp')
        self.show_view('rdp')
        self.log(f"获取到 {count} 条 RDP 记录", self.output_widget)
        self.status_label.configure(text=f"状态: 显示 {count} 条 RDP 记录")

    def _display_groups(self):
        """显示本地组"""
        tree = self.trees['groups']
        for item in tree.get_children():
            tree.delete(item)

        search = self.search_var.get().strip().lower()

        count = 0
        for group in self.manager.groups:
            # 搜索过滤
            if search:
                searchable = f"{group['name']} {' '.join(group.get('members', []))}".lower()
                if search not in searchable:
                    continue

            members = ', '.join(group.get('members', [])[:5])
            if len(group.get('members', [])) > 5:
                members += f'... (+{len(group["members"]) - 5})'

            values = (
                group['name'],
                '是' if group['is_privileged'] else '否',
                group['member_count'],
                members
            )

            tag = 'warning' if group['is_privileged'] else 'normal'
            tree.insert('', tk.END, values=values, tags=(tag,))
            count += 1

        self.view_var.set('groups')
        self.show_view('groups')
        self.log(f"获取到 {count} 个本地组", self.output_widget)
        self.status_label.configure(text=f"状态: 显示 {count} 个本地组")

    def refresh_display(self):
        """刷新当前显示"""
        view = self.current_view
        if view == 'users':
            self._display_users()
        elif view == 'hidden':
            self._display_hidden()
        elif view == 'login':
            self._display_login_history()
        elif view == 'rdp':
            self._display_rdp_sessions()
        elif view == 'groups':
            self._display_groups()

    def _update_summary_display(self):
        """更新摘要面板"""
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)

        summary = self.manager.get_audit_summary()

        self.summary_text.insert(tk.END, "=" * 22 + "\n")
        self.summary_text.insert(tk.END, "  用户账户审计摘要\n")
        self.summary_text.insert(tk.END, "=" * 22 + "\n\n")

        self.summary_text.insert(tk.END, "【用户统计】\n")
        self.summary_text.insert(tk.END, f"  总用户数: {summary['total_users']}\n")
        self.summary_text.insert(tk.END, f"  活动用户: {summary['active_users']}\n")
        self.summary_text.insert(tk.END, f"  管理员: {summary['admin_users']}\n")
        self.summary_text.insert(tk.END, f"  高风险: {summary['high_risk_users']}\n")

        self.summary_text.insert(tk.END, "\n【安全告警】\n")
        hidden = summary['hidden_users']
        if hidden > 0:
            self.summary_text.insert(tk.END, f"  隐藏账户: {hidden} ⚠️\n")
        else:
            self.summary_text.insert(tk.END, f"  隐藏账户: 0 ✓\n")

        self.summary_text.insert(tk.END, "\n【登录活动】\n")
        self.summary_text.insert(tk.END, f"  近期登录: {summary['recent_logins']}\n")
        self.summary_text.insert(tk.END, f"  失败登录: {summary['failed_logins']}\n")
        self.summary_text.insert(tk.END, f"  RDP登录: {summary['rdp_logins']}\n")

        self.summary_text.insert(tk.END, "\n【会话/组】\n")
        self.summary_text.insert(tk.END, f"  活动会话: {summary['active_sessions']}\n")
        self.summary_text.insert(tk.END, f"  特权组: {summary['privileged_groups']}\n")

        self.summary_text.config(state=tk.DISABLED)

    # ==================== 辅助功能 ====================

    def _show_user_detail(self):
        """显示用户详情"""
        tree = self.trees['users']
        selection = tree.selection()
        if not selection:
            return

        values = tree.item(selection[0])['values']
        if not values:
            return

        username = values[0]

        # 查找用户详情
        user = None
        for u in self.manager.users:
            if u['name'] == username:
                user = u
                break

        if not user:
            return

        detail = {
            '用户名': user['name'],
            '全名': user.get('full_name', ''),
            '状态': '启用' if user['active'] else '禁用',
            '管理员': '是' if user['is_admin'] else '否',
            '---1': '',
            '上次登录': user.get('last_logon', ''),
            '密码过期': user.get('password_expires', ''),
            '账户过期': user.get('account_expires', ''),
            '需要密码': '是' if user.get('password_required', True) else '否',
            '---2': '',
            '所属组': ', '.join(user.get('groups', [])),
            '---3': '',
            'SID': user.get('sid', ''),
            '风险等级': user['risk_level'],
            '注释': user.get('comment', '')
        }

        self.show_detail_dialog(f"用户详情 - {username}", detail)

    def _copy_field(self, index):
        """复制指定字段"""
        tree = self.trees[self.current_view]
        selection = tree.selection()
        if selection:
            values = tree.item(selection[0])['values']
            if values and index < len(values):
                tree.clipboard_clear()
                tree.clipboard_append(str(values[index]))
                self.log(f"已复制: {values[index]}", self.output_widget)

    def _copy_all(self):
        """复制全部信息"""
        tree = self.trees[self.current_view]
        selection = tree.selection()
        if selection:
            values = tree.item(selection[0])['values']
            if values:
                text = '\n'.join([str(v) for v in values])
                tree.clipboard_clear()
                tree.clipboard_append(text)
                self.log("已复制完整信息", self.output_widget)

    def export_report(self):
        """导出报告"""
        if not self.manager.users:
            messagebox.showwarning("提示", "请先执行审计")
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_name = f"user_audit_{timestamp}.json"

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")],
            initialfile=default_name
        )

        if not filepath:
            return

        try:
            report = {
                'audit_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'summary': self.manager.get_audit_summary(),
                'users': self.manager.users,
                'hidden_users': self.manager.hidden_users,
                'login_history': self.manager.login_history[:100],  # 限制数量
                'rdp_sessions': self.manager.rdp_sessions,
                'groups': self.manager.groups
            }

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            self.log(f"报告已导出: {filepath}", self.output_widget)
            messagebox.showinfo("成功", f"报告已导出到:\n{filepath}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")

    def _on_double_click(self, tree):
        """双击事件"""
        if self.current_view == 'users':
            self._show_user_detail()
