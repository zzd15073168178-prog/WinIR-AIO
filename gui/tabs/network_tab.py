#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网络连接选项卡"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any
import threading
from .base_tab import BaseTab
from console_logger import log_action, console_log
from utils import is_local_ip


class NetworkTab(BaseTab):
    """网络连接选项卡"""
    
    def __init__(self, parent, manager, output_widget):
        self.output_widget = output_widget
        self.network_data = []
        self.network_filter_mode = 'all'
        self.network_sort_column = None
        self.network_sort_reverse = False
        self.network_search_var = None
        super().__init__(parent, manager, "🌐 网络连接")
    
    def setup_ui(self):
        """设置UI"""
        # 搜索框
        search_frame, self.network_search_var = self.create_search_frame(
            self.frame, "搜索:", "IP/端口/PID", width=30)
        self.network_search_var.trace('w', lambda *a: self.filter_network())
        
        # 按钮
        btn_frame = self.create_button_frame(self.frame)
        ttk.Button(btn_frame, text="刷新连接", command=self.refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="显示全部", command=lambda: self.set_filter('all')).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="可疑连接", command=lambda: self.set_filter('suspicious')).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="已建立", command=lambda: self.set_filter('established')).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="仅外联IP", command=lambda: self.set_filter('external')).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="统计", command=self._show_stats).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出外联IP", command=self._export_external_ips).pack(side=tk.LEFT, padx=5)
        
        # 连接列表
        list_frame = ttk.Frame(self.frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('协议', '本地地址', '远程地址', '状态', 'PID', '进程', '位置')
        self.connection_tree = self.create_tree(list_frame, columns, height=20)
        
        self.connection_tree.column('协议', width=45)
        self.connection_tree.column('本地地址', width=140)
        self.connection_tree.column('远程地址', width=140)
        self.connection_tree.column('状态', width=90)
        self.connection_tree.column('PID', width=50)
        self.connection_tree.column('进程', width=120)
        self.connection_tree.column('位置', width=450)
        
        # 排序
        for col in columns:
            self.connection_tree.heading(col, text=col, command=lambda c=col: self.sort_network(c))
        
        # 颜色标签
        self.connection_tree.tag_configure('suspicious', background='#ffcccc', foreground='#8B0000')
        self.connection_tree.tag_configure('established', background='#d4edda', foreground='#155724')
        self.connection_tree.tag_configure('listen', background='#cce5ff', foreground='#004085')
        self.connection_tree.tag_configure('external', background='#fff3cd', foreground='#856404')
        self.connection_tree.tag_configure('normal', background='white', foreground='black')
        
        scrollbar = self.add_scrollbar(list_frame, self.connection_tree)
        self.connection_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 右键菜单
        self._setup_context_menu()
        self.refresh()
    
    def _setup_context_menu(self):
        """设置右键菜单"""
        menu_items = [
            {'label': '📋 查看详情', 'command': self._show_detail},
            {'label': '📄 复制信息', 'command': self._copy_info},
            {'separator': True, 'label': '---'},
            {'label': '🌐 查询IP信息', 'command': self._lookup_ip},
            {'label': '🔍 查看进程', 'command': self._view_process},
            {'separator': True, 'label': '---'},
            {'label': '📋 复制本地地址', 'command': lambda: self._copy_column(1)},
            {'label': '📋 复制远程地址', 'command': lambda: self._copy_column(2)},
            {'label': '📋 复制远程IP', 'command': self._copy_remote_ip},
        ]
        self.setup_tree_context_menu(self.connection_tree, menu_items)
    
    def _on_double_click(self, tree):
        """双击查看详情"""
        self._show_detail()
    
    def refresh(self):
        """刷新连接"""
        connections = self.manager.get_all_connections()
        
        # 先设置默认位置，不阻塞UI
        for conn in connections:
            ip = conn.get('remote_ip')
            if ip and self._is_local(ip):
                conn['location'] = "本地"
            elif ip:
                conn['location'] = "查询中..."
            else:
                conn['location'] = "N/A"
        
        self.network_data = connections
        self.log(f"🌐 找到 {len(connections)} 个网络连接", self.output_widget)
        self.filter_network()
        
        # 后台线程查询IP位置
        def query_locations():
            external_ips = set()
            for conn in self.network_data:
                ip = conn.get('remote_ip')
                if ip and not self._is_local(ip):
                    external_ips.add(ip)
            
            for ip in external_ips:
                try:
                    location = self.manager.get_ip_location(ip)
                    # 更新所有该IP的连接
                    for conn in self.network_data:
                        if conn.get('remote_ip') == ip:
                            conn['location'] = location
                except:
                    pass
            
            # 刷新显示
            self.safe_after(self.filter_network)

        threading.Thread(target=query_locations, daemon=True).start()
    
    def _is_local(self, ip):
        """检查是否为本地/保留IP"""
        return is_local_ip(ip)
    
    def filter_network(self):
        """过滤连接"""
        for item in self.connection_tree.get_children():
            self.connection_tree.delete(item)

        search = self.network_search_var.get().strip().lower() if self.network_search_var else ""

        for conn in self.network_data:
            remote_ip = conn.get('remote_ip', '')
            is_external = remote_ip and not self._is_local(remote_ip)

            # 模式过滤
            if self.network_filter_mode == 'suspicious' and not conn['is_suspicious']:
                continue
            if self.network_filter_mode == 'established' and conn['status'] != 'ESTABLISHED':
                continue
            if self.network_filter_mode == 'external' and not is_external:
                continue

            # 搜索过滤
            if search:
                s = f"{conn['local_addr']} {conn['remote_addr']} {conn['pid']} {conn['process']}".lower()
                if search not in s:
                    continue

            # 确定标签
            if conn['is_suspicious']:
                tag = 'suspicious'
            elif is_external:
                tag = 'external'
            elif conn['status'] == 'ESTABLISHED':
                tag = 'established'
            elif conn['status'] == 'LISTEN':
                tag = 'listen'
            else:
                tag = 'normal'

            # 处理进程名显示 - 对于Unknown进程尝试推断
            process_name = conn['process']
            pid = conn['pid']
            if not process_name or process_name == 'Unknown' or pid == 0:
                # 尝试根据端口推断
                remote_port = conn.get('remote_port')
                local_port = None
                if ':' in conn.get('local_addr', ''):
                    try:
                        local_port = int(conn['local_addr'].split(':')[-1])
                    except:
                        pass
                inferred = self.manager.infer_process_from_port(local_port, remote_port, conn['status'])
                if inferred:
                    process_name = inferred
                elif pid == 0:
                    # 显示状态提示
                    state_info = self.manager.get_state_info(conn['status'])
                    process_name = f"[已退出] {state_info[0]}"
                else:
                    process_name = "Unknown"

            self.connection_tree.insert('', tk.END, values=(
                conn['protocol'], conn['local_addr'], conn['remote_addr'],
                conn['status'], conn['pid'], process_name, conn['location']
            ), tags=(tag,))
    
    def sort_network(self, col):
        """排序"""
        if self.network_sort_column == col:
            self.network_sort_reverse = not self.network_sort_reverse
        else:
            self.network_sort_column = col
            self.network_sort_reverse = False
        
        sort_map = {
            '协议': 'protocol', '本地地址': 'local_addr', '远程地址': 'remote_addr',
            '状态': 'status', 'PID': 'pid', '进程': 'process', '位置': 'location'
        }
        if col in sort_map:
            key = sort_map[col]
            self.network_data.sort(key=lambda x: x.get(key) or '', reverse=self.network_sort_reverse)
        
        self.filter_network()
        
        # 更新标题
        for c in ['协议', '本地地址', '远程地址', '状态', 'PID', '进程', '位置']:
            arrow = ' ▼' if c == col and self.network_sort_reverse else (' ▲' if c == col else '')
            self.connection_tree.heading(c, text=c + arrow)
    
    def set_filter(self, mode):
        """设置过滤模式"""
        self.network_filter_mode = mode
        self.filter_network()
    
    def _show_detail(self):
        """显示详情"""
        cols = ['协议', '本地地址', '远程地址', '状态', 'PID', '进程', '位置']
        data = self.get_selected_row_data(self.connection_tree, cols)
        if not data:
            return

        log_action("查看连接详情", data.get('远程地址', ''))

        # 获取更多信息
        pid = data.get('PID')
        status = data.get('状态', '')

        # 获取状态解释
        state_info = self.manager.get_state_info(status)

        detail_data = {
            '协议': data.get('协议'),
            '本地地址': data.get('本地地址'),
            '远程地址': data.get('远程地址'),
            '---1': '',
            '连接状态': f"{status} ({state_info[0]})",
            '状态说明': state_info[1],
            '---2': '',
            '进程PID': pid,
            '进程名': data.get('进程'),
            'IP位置': data.get('位置'),
        }

        # 从原始数据获取更多
        conn_found = None
        for conn in self.network_data:
            if str(conn['pid']) == str(pid) and conn['local_addr'] == data.get('本地地址'):
                conn_found = conn
                detail_data['---3'] = ''
                detail_data['远程IP'] = conn.get('remote_ip', 'N/A')
                detail_data['远程端口'] = conn.get('remote_port', 'N/A')

                # 端口服务识别
                remote_port = conn.get('remote_port')
                if remote_port:
                    port_info = self.manager.get_port_info(remote_port)
                    if port_info:
                        detail_data['远程服务'] = f"{port_info[0]} - {port_info[1]}"

                detail_data['是否外联'] = '🌐 是' if not self._is_local(conn.get('remote_ip', '')) else '🏠 否'
                detail_data['是否可疑'] = '⚠️ 是' if conn.get('is_suspicious') else '✅ 否'
                break

        # 进程分析
        pid_int = int(pid) if pid and str(pid).isdigit() else 0
        if pid_int == 0 or data.get('进程') in ('Unknown', '', '[已退出]'):
            detail_data['---4'] = ''
            detail_data['⚠️ 进程状态'] = '原进程已退出'
            detail_data['说明'] = f'此连接处于 {status} 状态，原进程可能已终止'

            # 显示推断信息
            if conn_found:
                remote_port = conn_found.get('remote_port')
                local_port = None
                if ':' in conn_found.get('local_addr', ''):
                    try:
                        local_port = int(conn_found['local_addr'].split(':')[-1])
                    except:
                        pass
                inferred = self.manager.infer_process_from_port(local_port, remote_port, status)
                if inferred:
                    detail_data['推断进程类型'] = inferred
        else:
            # 进程详情
            try:
                import psutil
                p = psutil.Process(pid_int)
                detail_data['---4'] = ''
                detail_data['进程路径'] = p.exe() if hasattr(p, 'exe') else 'N/A'
                detail_data['进程用户'] = p.username() if hasattr(p, 'username') else 'N/A'
                detail_data['进程命令行'] = ' '.join(p.cmdline())[:100] if p.cmdline() else 'N/A'
            except:
                pass

        self.show_detail_dialog("网络连接详情", detail_data)
    
    def _copy_info(self):
        """复制信息"""
        cols = ['协议', '本地地址', '远程地址', '状态', 'PID', '进程', '位置']
        self.copy_selected_to_clipboard(self.connection_tree, cols)
    
    def _copy_column(self, col_idx):
        """复制指定列"""
        selection = self.connection_tree.selection()
        if selection:
            item = self.connection_tree.item(selection[0])
            if item['values'] and len(item['values']) > col_idx:
                self.connection_tree.clipboard_clear()
                self.connection_tree.clipboard_append(str(item['values'][col_idx]))
                log_action("复制", str(item['values'][col_idx]))
    
    def _lookup_ip(self):
        """查询IP信息"""
        cols = ['协议', '本地地址', '远程地址', '状态', 'PID', '进程', '位置']
        data = self.get_selected_row_data(self.connection_tree, cols)
        if not data:
            return
        
        remote = data.get('远程地址', '')
        ip = remote.split(':')[0] if ':' in remote else remote
        
        if not ip or self._is_local(ip):
            self.log(f"ℹ️ {ip} 是本地/私有IP", self.output_widget)
            return
        
        self.log(f"🌐 正在查询 {ip} 的位置信息...", self.output_widget)
        
        def query():
            loc = self.manager.get_ip_location(ip, verbose=True)
            self.safe_after(lambda: self.log(f"🌐 IP: {ip} 位置: {loc}", self.output_widget))

        threading.Thread(target=query, daemon=True).start()
    
    def _view_process(self):
        """查看进程"""
        cols = ['协议', '本地地址', '远程地址', '状态', 'PID', '进程', '位置']
        data = self.get_selected_row_data(self.connection_tree, cols)
        if data:
            pid = data.get('PID')
            name = data.get('进程')
            self.log(f"🔍 进程信息 - PID: {pid}, 名称: {name}", self.output_widget)
            self.log(f"ℹ️ 请在进程列表选项卡中搜索 PID: {pid}", self.output_widget)
    
    def _show_stats(self):
        """显示统计"""
        total = len(self.network_data)
        by_status = {}
        by_protocol = {}
        suspicious = 0
        
        for conn in self.network_data:
            status = conn['status']
            proto = conn['protocol']
            by_status[status] = by_status.get(status, 0) + 1
            by_protocol[proto] = by_protocol.get(proto, 0) + 1
            if conn['is_suspicious']:
                suspicious += 1
        
        stats = {
            '连接总数': total,
            '可疑连接': f"{suspicious} ({'⚠️ 有可疑连接!' if suspicious > 0 else '✅ 无'})",
            '---1': '',
        }
        
        # 按状态统计
        for status, count in sorted(by_status.items()):
            stats[f'状态-{status}'] = count
        
        stats['---2'] = ''
        
        # 按协议统计
        for proto, count in sorted(by_protocol.items()):
            stats[f'协议-{proto}'] = count
        
        self.show_detail_dialog("网络连接统计", stats)
    
    def _copy_remote_ip(self):
        """复制远程IP"""
        cols = ['协议', '本地地址', '远程地址', '状态', 'PID', '进程', '位置']
        data = self.get_selected_row_data(self.connection_tree, cols)
        if not data:
            return
        
        remote = data.get('远程地址', '')
        ip = remote.split(':')[0] if ':' in remote else remote
        
        if ip:
            self.connection_tree.clipboard_clear()
            self.connection_tree.clipboard_append(ip)
            self.log(f"📋 已复制IP: {ip}", self.output_widget)
    
    def _export_external_ips(self):
        """导出所有外联IP"""
        # 收集所有外联IP
        external_ips = set()
        ip_details = {}  # IP -> 进程信息
        
        for conn in self.network_data:
            ip = conn.get('remote_ip', '')
            if ip and not self._is_local(ip):
                external_ips.add(ip)
                if ip not in ip_details:
                    ip_details[ip] = []
                ip_details[ip].append(conn.get('process', 'Unknown'))
        
        if not external_ips:
            messagebox.showinfo("提示", "没有发现外联IP")
            return
        
        # 输出到日志
        self.log(f"\n{'='*50}", self.output_widget)
        self.log(f"🌐 外联IP列表 (共 {len(external_ips)} 个)", self.output_widget)
        self.log(f"{'='*50}", self.output_widget)
        
        sorted_ips = sorted(external_ips)
        for ip in sorted_ips:
            procs = list(set(ip_details.get(ip, [])))
            proc_str = ', '.join(procs[:3])
            if len(procs) > 3:
                proc_str += f' (+{len(procs)-3})'
            self.log(f"  {ip}  ←  {proc_str}", self.output_widget)
        
        self.log(f"{'='*50}", self.output_widget)
        
        # 复制到剪贴板
        ip_text = '\n'.join(sorted_ips)
        self.connection_tree.clipboard_clear()
        self.connection_tree.clipboard_append(ip_text)
        
        self.log(f"✅ 已复制 {len(external_ips)} 个外联IP到剪贴板", self.output_widget)
        messagebox.showinfo("导出完成", f"已导出 {len(external_ips)} 个外联IP\n\nIP列表已复制到剪贴板，\n可以直接粘贴到威胁情报平台查询。")
