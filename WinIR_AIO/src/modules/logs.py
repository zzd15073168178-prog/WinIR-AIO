"""
Logs Module
System logs analysis using Get-WinEvent
"""

from typing import List, Dict, Any
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, 
    QTableWidgetItem, QPushButton, QHeaderView, QComboBox,
    QSpinBox, QGroupBox, QSplitter, QTextEdit
)
from PySide6.QtCore import Qt, Slot
import logging
import json

from .base_module import BaseModule
from ..core.executor import CommandRunner

logger = logging.getLogger(__name__)

class LogsModule(BaseModule):
    """Logs analysis module"""
    
    def __init__(self, parent=None):
        super().__init__(parent, "Logs")
        self.runner = CommandRunner()
        self.logs_data: List[Dict[str, Any]] = []
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI"""
        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        toolbar_layout.addWidget(QLabel("事件类型:"))
        self.event_type_combo = QComboBox()
        self.event_type_combo.addItems([
            "登录失败 (4625)", 
            "登录成功 (4624)", 
            "进程创建 (4688)",
            "服务安装 (7045)",
            "账户创建 (4720)",
            "所有关键安全事件"
        ])
        toolbar_layout.addWidget(self.event_type_combo)
        
        toolbar_layout.addWidget(QLabel("最近记录数:"))
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(10, 1000)
        self.limit_spin.setValue(100)
        toolbar_layout.addWidget(self.limit_spin)
        
        self.refresh_btn = QPushButton("查询日志")
        self.refresh_btn.clicked.connect(self.refresh)
        toolbar_layout.addWidget(self.refresh_btn)
        
        toolbar_layout.addStretch()
        self.main_layout.addLayout(toolbar_layout)
        
        # Splitter for Table and Details
        splitter = QSplitter(Qt.Vertical)
        
        # Log Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "时间 (Time)", "事件ID (ID)", "级别 (Level)", 
            "来源 (Provider)", "消息摘要 (Message)"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        
        splitter.addWidget(self.table)
        
        # Details View
        details_group = QGroupBox("事件详情")
        details_layout = QVBoxLayout()
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        
        splitter.addWidget(details_group)
        
        self.main_layout.addWidget(splitter)
        
        # Info Label
        self.info_label = QLabel("选择事件类型并点击查询")
        self.main_layout.addWidget(self.info_label)
        
    def refresh(self):
        """Refresh logs data"""
        # Import here to avoid circular import
        from ..ui.workers import global_task_manager
        
        self.set_loading(True)
        self.refresh_btn.setEnabled(False)
        self.table.setRowCount(0)
        self.details_text.clear()
        
        event_type_idx = self.event_type_combo.currentIndex()
        limit = self.limit_spin.value()
        
        # Map combo index to event IDs
        event_ids = []
        if event_type_idx == 0: event_ids = [4625]
        elif event_type_idx == 1: event_ids = [4624]
        elif event_type_idx == 2: event_ids = [4688]
        elif event_type_idx == 3: event_ids = [7045]
        elif event_type_idx == 4: event_ids = [4720]
        else: event_ids = [4624, 4625, 4688, 7045, 4720, 4728, 4776]
        
        self.info_label.setText(f"正在查询事件 {event_ids} (限制 {limit} 条)...")
        
        global_task_manager.start_task(
            self.run_query,
            on_result=self.on_query_finished,
            on_error=self.on_query_error,
            on_finished=self.on_finished,
            event_ids=event_ids,
            limit=limit
        )
        
    def run_query(self, event_ids: List[int], limit: int, **kwargs) -> List[Dict[str, Any]]:
        """Run Get-WinEvent query (Worker function)"""
        
        ids_str = ','.join(map(str, event_ids))
        
        # PowerShell command to get events as JSON
        # We select specific properties to keep it lightweight
        # Disable progress to avoid CLIXML output to stderr
        ps_command = (
            "$ProgressPreference = 'SilentlyContinue'; "
            f"Get-WinEvent -FilterHashTable @{{LogName='Security'; Id={ids_str}}} -MaxEvents {limit} -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | "
            "ConvertTo-Json -Depth 1"
        )
        
        if kwargs.get('status_callback'):
            kwargs['status_callback'].emit("Executing PowerShell query...")
            
        result = self.runner.run_powershell(ps_command)
        
        # Check stderr for real errors (ignore CLIXML progress and "No events" messages)
        has_real_error = False
        if result.stderr:
            stderr_lower = result.stderr.lower()
            # Ignore CLIXML progress info and expected messages
            if not ('<clixml' in stderr_lower or 'no events were found' in stderr_lower or '正在准备' in stderr_lower):
                has_real_error = True
        
        if not result.success and has_real_error:
            raise Exception(f"Query failed: {result.stderr}")
        
        # If no stdout (empty result or error), return empty list
        if not result.stdout or not result.stdout.strip():
            return []
            
        try:
            data = json.loads(result.stdout)
            if isinstance(data, dict):  # Single result
                return [data]
            return data
        except json.JSONDecodeError:
            logger.error(f"JSON Decode Error. Raw output: {result.stdout[:100]}...")
            raise Exception("Failed to parse log data")
            
    @Slot(object)
    def on_query_finished(self, data: List[Dict[str, Any]]):
        """Handle query results"""
        self.logs_data = data
        self.update_table(data)
        self.info_label.setText(f"查询完成: 找到 {len(data)} 条事件")
        
    @Slot(tuple)
    def on_query_error(self, error_info):
        """Handle error"""
        _, error, _ = error_info
        self.handle_error(error, "日志查询失败")
        self.info_label.setText(f"错误: {str(error)}")
        
    @Slot()
    def on_finished(self):
        """Cleanup"""
        self.set_loading(False)
        self.refresh_btn.setEnabled(True)
        
    def update_table(self, rows: List[Dict[str, Any]]):
        """Update table widget"""
        self.table.setRowCount(len(rows))
        
        for i, entry in enumerate(rows):
            # Time
            time_str = entry.get('TimeCreated', '')
            if isinstance(time_str, dict) and 'DateTime' in time_str:
                time_str = time_str['DateTime']
            
            self.table.setItem(i, 0, QTableWidgetItem(str(time_str)))
            self.table.setItem(i, 1, QTableWidgetItem(str(entry.get('Id', ''))))
            self.table.setItem(i, 2, QTableWidgetItem(str(entry.get('LevelDisplayName', ''))))
            self.table.setItem(i, 3, QTableWidgetItem(str(entry.get('ProviderName', ''))))
            
            # Truncate message for table
            msg = str(entry.get('Message', ''))
            short_msg = (msg[:100] + '...') if len(msg) > 100 else msg
            self.table.setItem(i, 4, QTableWidgetItem(short_msg))
            
    def on_selection_changed(self):
        """Show details for selected log"""
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
            
        row_idx = rows[0].row()
        if row_idx < len(self.logs_data):
            entry = self.logs_data[row_idx]
            
            # Format details
            details = f"Event ID: {entry.get('Id')}\n"
            details += f"Time: {entry.get('TimeCreated')}\n"
            details += f"Level: {entry.get('LevelDisplayName')}\n"
            details += f"Provider: {entry.get('ProviderName')}\n"
            details += "-" * 40 + "\n"
            details += f"Message:\n{entry.get('Message')}\n"
            
            self.details_text.setText(details)
            
    def export_data(self, filename: str, format: str = "CSV"):
        """Export logs data"""
        # TODO: Implement proper export
        self.emit_status(f"Exporting to {filename}...")
