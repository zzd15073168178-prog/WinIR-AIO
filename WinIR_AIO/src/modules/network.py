"""
Network Module
Network connections monitoring using psutil
"""

import psutil
import socket
from datetime import datetime
from typing import List, Dict, Any

from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, 
    QTableWidgetItem, QPushButton, QHeaderView, QLineEdit,
    QCheckBox, QSplitter, QGroupBox, QTextEdit
)
from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QColor, QBrush

import logging

from .base_module import BaseModule
from ..ui.workers import global_task_manager

logger = logging.getLogger(__name__)

class NetworkModule(BaseModule):
    """Network connections module"""
    
    def __init__(self, parent=None):
        super().__init__(parent, "Network")
        self.connections: List[Dict[str, Any]] = []
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI"""
        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("刷新连接")
        self.refresh_btn.clicked.connect(self.refresh)
        
        self.resolve_dns_cb = QCheckBox("解析主机名")
        self.resolve_dns_cb.setChecked(False)
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("搜索 IP、端口或进程...")
        self.filter_edit.textChanged.connect(self.filter_data)
        
        toolbar_layout.addWidget(self.refresh_btn)
        toolbar_layout.addWidget(self.resolve_dns_cb)
        toolbar_layout.addWidget(self.filter_edit)
        toolbar_layout.addStretch()
        
        self.main_layout.addLayout(toolbar_layout)
        
        # Splitter
        splitter = QSplitter(Qt.Vertical)
        
        # Connection Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "协议", "本地地址", "本地端口", "远程地址", "远程端口", 
            "状态", "进程 (PID)"
        ])
        
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        
        splitter.addWidget(self.table)
        
        # Details
        details_group = QGroupBox("连接详情")
        details_layout = QVBoxLayout()
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(120)
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        
        splitter.addWidget(details_group)
        
        self.main_layout.addWidget(splitter)
        
        # Info Label
        self.info_label = QLabel("点击刷新以加载网络连接")
        self.main_layout.addWidget(self.info_label)
        
    def refresh(self):
        """Refresh network connections"""
        self.set_loading(True)
        self.refresh_btn.setEnabled(False)
        self.info_label.setText("正在扫描网络连接...")
        
        resolve_dns = self.resolve_dns_cb.isChecked()
        
        global_task_manager.start_task(
            self.collect_connections,
            on_result=self.on_collection_finished,
            on_error=self.on_collection_error,
            on_finished=self.on_finished,
            resolve_dns=resolve_dns
        )
        
    def collect_connections(self, resolve_dns: bool = False, **kwargs) -> List[Dict[str, Any]]:
        """Collect network connections (Worker function)"""
        conns = []
        
        if kwargs.get('status_callback'):
            kwargs['status_callback'].emit("获取进程映射...")
            
        # Create PID -> Name map first
        proc_map = {}
        for p in psutil.process_iter(['pid', 'name']):
            try:
                proc_map[p.info['pid']] = p.info['name']
            except:
                pass
                
        if kwargs.get('status_callback'):
            kwargs['status_callback'].emit("扫描连接...")
            
        # Get connections
        # kind='inet' for IPv4/IPv6 TCP/UDP
        for c in psutil.net_connections(kind='inet'):
            laddr = c.laddr
            raddr = c.raddr
            
            l_host = laddr.ip
            r_host = raddr.ip if raddr else ""
            
            # DNS resolution (slow, so optional)
            if resolve_dns:
                try:
                    if r_host and r_host not in ['127.0.0.1', '0.0.0.0', '::1']:
                        r_host = socket.gethostbyaddr(r_host)[0]
                except:
                    pass
            
            protocol = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            
            entry = {
                'proto': protocol,
                'laddr': l_host,
                'lport': laddr.port,
                'raddr': r_host,
                'rport': raddr.port if raddr else "",
                'status': c.status,
                'pid': c.pid,
                'process_name': proc_map.get(c.pid, f"Unknown ({c.pid})") if c.pid else "System",
                'family': 'IPv4' if c.family == socket.AF_INET else 'IPv6'
            }
            conns.append(entry)
            
        return conns
        
    @Slot(object)
    def on_collection_finished(self, data: List[Dict[str, Any]]):
        """Handle collection success"""
        self.connections = data
        self.filter_data()
        self.info_label.setText(f"加载完成: {len(data)} 个连接")
        
    @Slot(tuple)
    def on_collection_error(self, error_info):
        """Handle error"""
        _, error, _ = error_info
        self.handle_error(error, "获取网络连接失败")
        self.info_label.setText(f"错误: {str(error)}")
        
    @Slot()
    def on_finished(self):
        """Cleanup"""
        self.set_loading(False)
        self.refresh_btn.setEnabled(True)
        
    def filter_data(self):
        """Filter and display data"""
        filter_text = self.filter_edit.text().lower()
        
        filtered_rows = []
        for c in self.connections:
            if filter_text:
                search_fields = [
                    c['laddr'], str(c['lport']), 
                    c['raddr'], str(c['rport']),
                    c['process_name'].lower(), str(c['pid'])
                ]
                if not any(filter_text in str(f) for f in search_fields):
                    continue
            filtered_rows.append(c)
            
        self.update_table(filtered_rows)
        
    def update_table(self, rows: List[Dict[str, Any]]):
        """Update table widget"""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        
        for i, c in enumerate(rows):
            # Protocol
            self.table.setItem(i, 0, QTableWidgetItem(c['proto']))
            
            # Local Addr
            self.table.setItem(i, 1, QTableWidgetItem(c['laddr']))
            
            # Local Port (Numeric sort)
            port_item = QTableWidgetItem()
            port_item.setData(Qt.DisplayRole, c['lport'])
            self.table.setItem(i, 2, port_item)
            
            # Remote Addr
            self.table.setItem(i, 3, QTableWidgetItem(c['raddr']))
            
            # Remote Port
            if c['rport']:
                rport_item = QTableWidgetItem()
                rport_item.setData(Qt.DisplayRole, c['rport'])
                self.table.setItem(i, 4, rport_item)
            else:
                self.table.setItem(i, 4, QTableWidgetItem(""))
                
            # Status
            status_item = QTableWidgetItem(c['status'])
            if c['status'] == 'ESTABLISHED':
                status_item.setForeground(QBrush(QColor("#27ae60")))
            elif c['status'] == 'LISTEN':
                status_item.setForeground(QBrush(QColor("#2980b9")))
            self.table.setItem(i, 5, status_item)
            
            # Process
            proc_str = f"{c['process_name']} ({c['pid']})" if c['pid'] else "System"
            self.table.setItem(i, 6, QTableWidgetItem(proc_str))
            
        self.table.setSortingEnabled(True)
        
    def on_selection_changed(self):
        """Update details"""
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            self.details_text.clear()
            return
            
        row = rows[0].row()
        # Since table is sorted/filtered, we need to find original data
        # But for now just reading from table is easier for simple display
        
        # Or better: store index in UserRole?
        # For simple display, just constructing text is fine
        
        proto = self.table.item(row, 0).text()
        laddr = self.table.item(row, 1).text()
        lport = self.table.item(row, 2).text()
        raddr = self.table.item(row, 3).text()
        rport = self.table.item(row, 4).text()
        status = self.table.item(row, 5).text()
        proc = self.table.item(row, 6).text()
        
        details = f"进程: {proc}\n"
        details += f"连接: {laddr}:{lport} -> {raddr}:{rport}\n"
        details += f"协议: {proto}\n"
        details += f"状态: {status}\n"
        
        self.details_text.setText(details)
        
    def export_data(self, filename: str, format: str = "CSV"):
        """Export network data"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                headers = ["Protocol", "Local IP", "Local Port", "Remote IP", "Remote Port", "Status", "Process", "PID"]
                f.write(",".join(headers) + "\n")
                
                for c in self.connections:
                    row = [
                        c['proto'],
                        c['laddr'],
                        str(c['lport']),
                        c['raddr'],
                        str(c['rport']),
                        c['status'],
                        c['process_name'],
                        str(c['pid'])
                    ]
                    f.write(",".join(row) + "\n")
            self.emit_status(f"已导出到 {filename}")
        except Exception as e:
            self.handle_error(e, "导出失败")
