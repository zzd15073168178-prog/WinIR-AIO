"""
Process Module
Process analysis and verification using psutil and sigcheck
"""

import psutil
import time
import os
from datetime import datetime
from typing import List, Dict, Any, Set

from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, 
    QTableWidgetItem, QPushButton, QHeaderView, QLineEdit,
    QMenu, QMessageBox, QCheckBox, QSplitter, QGroupBox, QTextEdit
)
from PySide6.QtCore import Qt, Slot, QTimer
from PySide6.QtGui import QColor, QBrush, QAction, QCursor

import logging

from .base_module import BaseModule
from ..core.signatures import SignatureVerifier
from ..ui.workers import global_task_manager

logger = logging.getLogger(__name__)

class ProcessModule(BaseModule):
    """Process analysis module"""
    
    def __init__(self, parent=None):
        super().__init__(parent, "Process")
        self.verifier = SignatureVerifier()
        self.processes: List[Dict[str, Any]] = []
        self.process_map: Dict[int, Dict[str, Any]] = {} # PID -> Info
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI"""
        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("刷新列表")
        self.refresh_btn.clicked.connect(self.refresh)
        
        self.verify_btn = QPushButton("验证签名")
        self.verify_btn.clicked.connect(self.verify_signatures)
        self.verify_btn.setToolTip("批量验证所有可见进程的数字签名（可能较慢）")
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("搜索进程名、PID或用户...")
        self.filter_edit.textChanged.connect(self.filter_data)
        
        self.hide_system_cb = QCheckBox("隐藏系统进程")
        self.hide_system_cb.setChecked(False)
        self.hide_system_cb.stateChanged.connect(self.filter_data)
        
        toolbar_layout.addWidget(self.refresh_btn)
        toolbar_layout.addWidget(self.verify_btn)
        toolbar_layout.addWidget(self.filter_edit)
        toolbar_layout.addWidget(self.hide_system_cb)
        toolbar_layout.addStretch()
        
        self.main_layout.addLayout(toolbar_layout)
        
        # Splitter for Table and Details
        splitter = QSplitter(Qt.Vertical)
        
        # Process Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "PID", "名称", "用户", "CPU%", "内存 (MB)", 
            "路径", "签名状态", "描述"
        ])
        
        # Setup header resizing
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.Interactive) # Name
        header.setSectionResizeMode(5, QHeaderView.Interactive) # Path
        header.setStretchLastSection(True)
        
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        
        splitter.addWidget(self.table)
        
        # Process Details
        details_group = QGroupBox("进程详情")
        details_layout = QVBoxLayout()
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        
        splitter.addWidget(details_group)
        
        self.main_layout.addWidget(splitter)
        
        # Info Label
        self.info_label = QLabel("点击刷新以加载进程列表")
        self.main_layout.addWidget(self.info_label)
        
        # Initial load
        # self.refresh() 
        
    def refresh(self):
        """Refresh process list"""
        self.set_loading(True)
        self.refresh_btn.setEnabled(False)
        self.verify_btn.setEnabled(False)
        self.info_label.setText("正在收集进程信息...")
        
        global_task_manager.start_task(
            self.collect_processes,
            on_result=self.on_collection_finished,
            on_error=self.on_collection_error,
            on_finished=self.on_finished
        )
        
    def collect_processes(self, **kwargs) -> List[Dict[str, Any]]:
        """Collect process info (Worker function)"""
        procs = []
        
        if kwargs.get('status_callback'):
            kwargs['status_callback'].emit("扫描系统进程...")
            
        # Iterate over all running processes
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'create_time', 'cpu_percent', 'memory_info']):
            try:
                info = proc.info
                
                # Calculate memory in MB
                mem_mb = info['memory_info'].rss / (1024 * 1024)
                
                # Process create time
                create_time = datetime.fromtimestamp(info['create_time']).strftime("%Y-%m-%d %H:%M:%S")
                
                entry = {
                    'pid': info['pid'],
                    'name': info['name'],
                    'username': info['username'] or "",
                    'exe': info['exe'] or "",
                    'cmdline': " ".join(info['cmdline']) if info['cmdline'] else "",
                    'create_time': create_time,
                    'cpu_percent': info['cpu_percent'],
                    'memory_mb': round(mem_mb, 2),
                    'verified': None, # None=Unknown, True=Signed, False=Unsigned
                    'signer': "",
                    'description': "",
                    'display_row': True # For filtering
                }
                procs.append(entry)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        return procs
        
    @Slot(object)
    def on_collection_finished(self, data: List[Dict[str, Any]]):
        """Handle collection success"""
        self.processes = data
        # Update map for quick access
        self.process_map = {p['pid']: p for p in data}
        
        self.filter_data()
        self.info_label.setText(f"加载完成: {len(data)} 个进程")
        self.verify_btn.setEnabled(True)
        
    @Slot(tuple)
    def on_collection_error(self, error_info):
        """Handle error"""
        _, error, _ = error_info
        self.handle_error(error, "获取进程列表失败")
        self.info_label.setText(f"错误: {str(error)}")
        
    @Slot()
    def on_finished(self):
        """Cleanup"""
        self.set_loading(False)
        self.refresh_btn.setEnabled(True)
        
    def filter_data(self):
        """Filter and display processes"""
        filter_text = self.filter_edit.text().lower()
        hide_system = self.hide_system_cb.isChecked()
        
        filtered_rows = []
        
        for p in self.processes:
            # Filter logic
            if hide_system:
                # Simple heuristic for system processes
                if p['username'] in ['NT AUTHORITY\\SYSTEM', 'SYSTEM', 'NT AUTHORITY\\LOCAL SERVICE', 'NT AUTHORITY\\NETWORK SERVICE']:
                    continue
            
            if filter_text:
                search_fields = [str(p['pid']), p['name'].lower(), p['username'].lower() if p['username'] else ""]
                if not any(filter_text in field for field in search_fields):
                    continue
            
            filtered_rows.append(p)
            
        self.update_table(filtered_rows)
        
    def update_table(self, rows: List[Dict[str, Any]]):
        """Update table widget"""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        
        for i, p in enumerate(rows):
            # PID (Sortable as number)
            pid_item = QTableWidgetItem()
            pid_item.setData(Qt.DisplayRole, p['pid'])
            self.table.setItem(i, 0, pid_item)
            
            # Name
            self.table.setItem(i, 1, QTableWidgetItem(p['name']))
            
            # User
            self.table.setItem(i, 2, QTableWidgetItem(p['username']))
            
            # CPU (Sortable as number)
            cpu_item = QTableWidgetItem()
            cpu_item.setData(Qt.DisplayRole, p['cpu_percent'])
            self.table.setItem(i, 3, cpu_item)
            
            # Memory (Sortable as number)
            mem_item = QTableWidgetItem()
            mem_item.setData(Qt.DisplayRole, p['memory_mb'])
            self.table.setItem(i, 4, mem_item)
            
            # Path
            self.table.setItem(i, 5, QTableWidgetItem(p['exe']))
            
            # Signature Status
            sig_status = "未验证"
            bg_color = None
            fg_color = None
            
            if p['verified'] is True:
                sig_status = "✅ 已签名"
                fg_color = QColor("#27ae60") # Green
            elif p['verified'] is False:
                sig_status = "❌ 未签名"
                fg_color = QColor("#e74c3c") # Red
                
            sig_item = QTableWidgetItem(sig_status)
            if fg_color:
                sig_item.setForeground(QBrush(fg_color))
            self.table.setItem(i, 6, sig_item)
            
            # Description/Signer
            desc = p['description'] or p['signer'] or ""
            self.table.setItem(i, 7, QTableWidgetItem(desc))
            
            # Store PID in row for easy access
            self.table.item(i, 0).setData(Qt.UserRole, p['pid'])
            
        self.table.setSortingEnabled(True)
        
    def on_selection_changed(self):
        """Update details view"""
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            self.details_text.clear()
            return
            
        row = rows[0].row()
        pid_item = self.table.item(row, 0)
        if not pid_item:
            return
            
        pid = pid_item.data(Qt.UserRole)
        proc = self.process_map.get(pid)
        
        if proc:
            details = f"PID: {proc['pid']}\n"
            details += f"名称: {proc['name']}\n"
            details += f"路径: {proc['exe']}\n"
            details += f"命令行: {proc['cmdline']}\n"
            details += f"用户: {proc['username']}\n"
            details += f"启动时间: {proc['create_time']}\n"
            details += f"内存: {proc['memory_mb']} MB\n"
            
            if proc['verified'] is not None:
                status = "已签名" if proc['verified'] else "未签名"
                details += f"签名状态: {status}\n"
                details += f"签名者: {proc['signer']}\n"
                
            self.details_text.setText(details)
            
    def verify_signatures(self):
        """Batch verify signatures for visible processes"""
        self.set_loading(True)
        self.verify_btn.setEnabled(False)
        self.refresh_btn.setEnabled(False)
        
        # Collect paths to verify
        paths_to_verify = []
        pids_to_update = []
        
        # Only verify filtered (visible) processes to save time
        # Get all items from table model (after filtering)
        row_count = self.table.rowCount()
        for i in range(row_count):
            pid_item = self.table.item(i, 0)
            pid = pid_item.data(Qt.DisplayRole)
            proc = self.process_map.get(pid)
            
            if proc and proc['exe'] and os.path.exists(proc['exe']):
                # Only verify if not already verified
                if proc['verified'] is None:
                    paths_to_verify.append(proc['exe'])
                    pids_to_update.append(pid)
                    
        if not paths_to_verify:
            self.info_label.setText("没有需要验证的新进程")
            self.on_finished()
            self.verify_btn.setEnabled(True)
            return
            
        # De-duplicate paths
        unique_paths = list(set(paths_to_verify))
        self.info_label.setText(f"正在验证 {len(unique_paths)} 个文件的签名...")
        
        global_task_manager.start_task(
            self.run_verification,
            on_result=self.on_verification_result,
            on_error=self.on_verification_error,
            on_finished=self.on_finished,
            file_paths=unique_paths
        )
        
    def run_verification(self, file_paths: List[str], **kwargs) -> Dict[str, Dict[str, Any]]:
        """Run sigcheck batch verification (Worker function)"""
        if kwargs.get('status_callback'):
            kwargs['status_callback'].emit(f"正在验证 {len(file_paths)} 个文件...")
            
        # Use wildcard optimization if possible
        return self.verifier.verify_batch(file_paths, use_wildcard=True)
        
    @Slot(object)
    def on_verification_result(self, results: Dict[str, Dict[str, Any]]):
        """Handle verification results"""
        count = 0
        for proc in self.processes:
            exe_path = proc.get('exe')
            if exe_path and exe_path in results:
                res = results[exe_path]
                proc['verified'] = res.get('verified')
                proc['signer'] = res.get('signer', '') or res.get('publisher', '')
                proc['description'] = res.get('description', '')
                count += 1
                
        # Refresh display
        self.filter_data()
        self.info_label.setText(f"验证完成: 更新了 {count} 个进程")
        
    @Slot(tuple)
    def on_verification_error(self, error_info):
        """Handle verification error"""
        _, error, _ = error_info
        self.handle_error(error, "签名验证失败")
        
    def show_context_menu(self, position):
        """Show context menu for table"""
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
            
        menu = QMenu()
        
        pid = self.table.item(rows[0].row(), 0).data(Qt.UserRole)
        proc = self.process_map.get(pid)
        
        open_folder_action = QAction("打开文件所在位置", self)
        open_folder_action.triggered.connect(lambda: self.open_folder(proc['exe']))
        if not proc or not proc['exe']:
            open_folder_action.setEnabled(False)
        menu.addAction(open_folder_action)
        
        menu.addSeparator()
        
        kill_action = QAction("结束进程", self)
        kill_action.triggered.connect(lambda: self.kill_process(pid))
        menu.addAction(kill_action)
        
        menu.exec(self.table.viewport().mapToGlobal(position))
        
    def open_folder(self, path):
        """Open folder containing file"""
        if path and os.path.exists(path):
            folder = os.path.dirname(path)
            os.startfile(folder)
            
    def kill_process(self, pid):
        """Kill a process"""
        proc = self.process_map.get(pid)
        name = proc['name'] if proc else str(pid)
        
        reply = QMessageBox.question(
            self, "确认结束进程", 
            f"确定要强制结束进程 {name} (PID: {pid}) 吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                ps_proc = psutil.Process(pid)
                ps_proc.terminate()
                self.emit_status(f"进程 {pid} 已结束")
                self.refresh() # Refresh list
            except Exception as e:
                QMessageBox.critical(self, "错误", f"无法结束进程: {str(e)}")
                
    def export_data(self, filename: str, format: str = "CSV"):
        """Export process list"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Header
                headers = ["PID", "Name", "User", "CPU", "Memory(MB)", "Path", "Verified", "Signer"]
                f.write(",".join(headers) + "\n")
                
                for p in self.processes:
                    row = [
                        str(p['pid']),
                        p['name'],
                        p['username'],
                        str(p['cpu_percent']),
                        str(p['memory_mb']),
                        p['exe'],
                        str(p['verified']) if p['verified'] is not None else "Unknown",
                        p['signer'].replace(',', ' ') # Simple CSV escape
                    ]
                    f.write(",".join(row) + "\n")
                    
            self.emit_status(f"已导出到 {filename}")
        except Exception as e:
            self.handle_error(e, "导出失败")
