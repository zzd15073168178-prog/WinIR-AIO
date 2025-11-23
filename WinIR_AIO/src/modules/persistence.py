"""
Persistence Module
Persistence mechanisms detection using Autoruns
"""

from typing import List, Dict, Any
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, 
    QTableWidgetItem, QPushButton, QHeaderView, QCheckBox,
    QMessageBox, QLineEdit, QGroupBox, QMenu
)
from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QAction, QColor
import logging
from pathlib import Path

from .base_module import BaseModule
from ..core.executor import CommandRunner
from ..core.parsers import AutorunsParser
from ..core.timestamp_analyzer import TimestampAnalyzer
from ..ui.workers import global_task_manager
from ..ui.command_log_dialog import command_logger

logger = logging.getLogger(__name__)

class PersistenceModule(BaseModule):
    """Persistence detection module"""
    
    def __init__(self, parent=None):
        super().__init__(parent, "Persistence")
        self.runner = CommandRunner()
        self.timestamp_analyzer = TimestampAnalyzer(command_callback=self._on_command_log)
        self.autoruns_data: List[Dict[str, Any]] = []
        self.check_timestamps = False  # Flag to enable timestamp checking
        self.setup_ui()
        
    def _on_command_log(self, log_data: Dict[str, Any]):
        """Handle command log data from timestamp analyzer"""
        if log_data['type'] == 'command':
            if log_data['command']:
                command_logger.log_command(log_data['command'], log_data.get('description'))
            if log_data.get('output'):
                command_logger.log_output(log_data['output'], not log_data.get('success', True))
            if 'success' in log_data:
                command_logger.log_result(log_data['success'])
        
    def setup_ui(self):
        """Setup the UI"""
        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("刷新数据")
        self.refresh_btn.clicked.connect(self.refresh)
        
        self.hide_microsoft_cb = QCheckBox("隐藏微软签名项")
        self.hide_microsoft_cb.setChecked(True)
        self.hide_microsoft_cb.stateChanged.connect(self.filter_data)
        
        self.timestamp_check_cb = QCheckBox("检测时间戳异常")
        self.timestamp_check_cb.setToolTip("检测可能的时间戳篡改（会增加扫描时间）")
        self.timestamp_check_cb.stateChanged.connect(self.on_timestamp_check_changed)
        
        self.show_cmd_log_btn = QPushButton("📜 命令日志")
        self.show_cmd_log_btn.setToolTip("显示时间戳分析执行的命令")
        self.show_cmd_log_btn.clicked.connect(self.show_command_log)
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("搜索...")
        self.filter_edit.textChanged.connect(self.filter_data)
        
        toolbar_layout.addWidget(self.refresh_btn)
        toolbar_layout.addWidget(self.hide_microsoft_cb)
        toolbar_layout.addWidget(self.timestamp_check_cb)
        toolbar_layout.addWidget(self.show_cmd_log_btn)
        toolbar_layout.addWidget(self.filter_edit)
        toolbar_layout.addStretch()
        
        self.main_layout.addLayout(toolbar_layout)
        
        # Data Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "位置 (Location)", "条目 (Entry)", "启用 (Enabled)", 
            "映像路径 (Image Path)", "发布者 (Publisher)", "时间戳状态"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        
        # Enable context menu
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        self.main_layout.addWidget(self.table)
        
        # Info Label
        self.info_label = QLabel("点击刷新以加载 Autoruns 数据 (这可能需要几分钟)")
        self.main_layout.addWidget(self.info_label)
        
    def refresh(self):
        """Refresh persistence data"""
        self.set_loading(True)
        self.refresh_btn.setEnabled(False)
        self.table.setRowCount(0)
        self.info_label.setText("正在运行 Autoruns... 请稍候")
        
        global_task_manager.start_task(
            self.run_autoruns,
            on_result=self.on_autoruns_finished,
            on_error=self.on_autoruns_error,
            on_finished=self.on_finished
        )
        
    def run_autoruns(self, **kwargs) -> List[Dict[str, Any]]:
        """Run autorunsc tool (Worker function)"""
        # autorunsc -a * -c -nobanner -accepteula -t (timestamp)
        # -a *: All entries
        # -c: CSV output
        # -t: Include timestamp information
        # -h: Hash (optional, makes it slower)
        
        if kwargs.get('status_callback'):
            kwargs['status_callback'].emit("Executing autorunsc...")
            
        # Log the command
        args = ['-a', '*', '-c', '-nobanner', '-t']
        command_logger.log_command(
            f"autorunsc.exe {' '.join(args)}",
            "扫描所有启动项和持久化机制"
        )
        
        # Include -t flag to get timestamp info
        result = self.runner.run_sysinternals_tool(
            "autorunsc.exe", 
            args
        )
        
        if result.success:
            command_logger.log_result(True, f"成功获取 {len(result.stdout.splitlines())} 行数据")
        else:
            command_logger.log_result(False, result.stderr[:200])
        
        if not result.success:
            raise Exception(f"Autorunsc failed: {result.stderr}")
            
        if kwargs.get('status_callback'):
            kwargs['status_callback'].emit("Parsing results...")
            
        autoruns_data = AutorunsParser.parse(result.stdout)
        
        # If timestamp checking is enabled, analyze each file
        if self.check_timestamps:
            if kwargs.get('status_callback'):
                kwargs['status_callback'].emit("Analyzing timestamps...")
                
            command_logger.log_info(f"开始分析 {len(autoruns_data)} 个条目的时间戳")
            suspicious_count = 0
                
            for idx, entry in enumerate(autoruns_data):
                if idx % 10 == 0 and kwargs.get('progress_callback'):
                    kwargs['progress_callback'].emit(int((idx / len(autoruns_data)) * 100))
                    
                # AutorunsParser converts keys to lowercase
                image_path = entry.get('image path', '')
                if image_path and Path(image_path).exists():
                    try:
                        is_suspicious, anomalies = self.timestamp_analyzer.check_file_timestamps(image_path)
                        entry['timestamp_suspicious'] = is_suspicious
                        entry['timestamp_anomalies'] = anomalies
                        
                        if is_suspicious:
                            suspicious_count += 1
                            command_logger.log_info(f"⚠️ 发现可疑文件: {Path(image_path).name} ({len(anomalies)} 个异常)")
                            
                    except Exception as e:
                        logger.debug(f"Failed to analyze timestamp for {image_path}: {e}")
                        entry['timestamp_suspicious'] = False
                        entry['timestamp_anomalies'] = []
                else:
                    entry['timestamp_suspicious'] = False
                    entry['timestamp_anomalies'] = []
                    
            command_logger.log_result(True, f"时间戳分析完成: 发现 {suspicious_count} 个可疑文件")
            command_logger.log_separator()
                    
        return autoruns_data
        
    @Slot(object)
    def on_autoruns_finished(self, data: List[Dict[str, Any]]):
        """Handle successful autoruns execution"""
        self.autoruns_data = data
        self.filter_data()
        self.info_label.setText(f"加载完成: {len(data)} 个条目")
        
    @Slot(tuple)
    def on_autoruns_error(self, error_info):
        """Handle error"""
        _, error, _ = error_info
        self.handle_error(error, "Autoruns 执行失败")
        self.info_label.setText(f"错误: {str(error)}")
        
    @Slot()
    def on_finished(self):
        """Cleanup after task"""
        self.set_loading(False)
        self.refresh_btn.setEnabled(True)
        
    def filter_data(self):
        """Filter and display data"""
        filter_text = self.filter_edit.text().lower()
        hide_microsoft = self.hide_microsoft_cb.isChecked()
        
        filtered_rows = []
        
        for entry in self.autoruns_data:
            # Skip if hiding microsoft and publisher contains Microsoft
            publisher = entry.get('publisher', '').lower()
            if hide_microsoft and 'microsoft' in publisher and 'corporation' in publisher:
                continue
                
            # Text filter
            values = list(entry.values())
            if filter_text and not any(filter_text in str(v).lower() for v in values):
                continue
                
            filtered_rows.append(entry)
            
        self.update_table(filtered_rows)
        
    def update_table(self, rows: List[Dict[str, Any]]):
        """Update table widget"""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        
        for i, entry in enumerate(rows):
            # AutorunsParser converts all keys to lowercase
            self.table.setItem(i, 0, QTableWidgetItem(entry.get('entry location', '')))
            self.table.setItem(i, 1, QTableWidgetItem(entry.get('entry', '')))
            self.table.setItem(i, 2, QTableWidgetItem(entry.get('enabled', '')))
            
            # Image path with full data stored in item
            image_item = QTableWidgetItem(entry.get('image path', ''))
            image_item.setData(Qt.UserRole, entry.get('image path', ''))
            self.table.setItem(i, 3, image_item)
            
            self.table.setItem(i, 4, QTableWidgetItem(entry.get('publisher', '')))
            
            # Timestamp status column
            timestamp_item = QTableWidgetItem()
            if self.check_timestamps and 'timestamp_suspicious' in entry:
                if entry['timestamp_suspicious']:
                    timestamp_item.setText("⚠️ 可疑")
                    timestamp_item.setForeground(QColor(255, 200, 0))  # Orange
                    anomaly_count = len(entry.get('timestamp_anomalies', []))
                    timestamp_item.setToolTip(f"发现 {anomaly_count} 个异常\n点击右键查看详情")
                else:
                    timestamp_item.setText("✅ 正常")
                    timestamp_item.setForeground(QColor(0, 200, 0))  # Green
                    timestamp_item.setToolTip("未发现时间戳异常")
            else:
                timestamp_item.setText("-")
                timestamp_item.setToolTip("未启用时间戳检查")
            
            # Store the full entry data for context menu
            timestamp_item.setData(Qt.UserRole, entry)
            self.table.setItem(i, 5, timestamp_item)
            
        self.table.setSortingEnabled(True)
        
    def export_data(self, filename: str, format: str = "CSV"):
        """Export data"""
        # TODO: Implement proper export
        self.emit_status(f"Exporting to {filename}...")
        
    def on_timestamp_check_changed(self, state):
        """Handle timestamp check checkbox state change"""
        self.check_timestamps = (state == Qt.Checked)
        if self.check_timestamps:
            self.info_label.setText("时间戳检查已启用 - 下次刷新时生效")
        else:
            self.info_label.setText("时间戳检查已禁用")
            
    def show_context_menu(self, position):
        """Show context menu for table items"""
        item = self.table.itemAt(position)
        if not item:
            return
            
        row = item.row()
        col = item.column()
        
        menu = QMenu(self)
        
        # Get image path from row
        image_item = self.table.item(row, 3)
        if image_item:
            image_path = image_item.data(Qt.UserRole)
            
            if image_path and Path(image_path).exists():
                # Add timestamp analysis action
                analyze_action = QAction("🔍 分析时间戳", self)
                analyze_action.triggered.connect(lambda: self.show_timestamp_analysis(image_path))
                menu.addAction(analyze_action)
                
                # Add quick check action
                check_action = QAction("⚡ 快速检查时间戳", self)
                check_action.triggered.connect(lambda: self.quick_timestamp_check(image_path))
                menu.addAction(check_action)
                
                menu.addSeparator()
                
                # Add show command log action
                show_log_action = QAction("📜 显示命令日志", self)
                show_log_action.triggered.connect(self.show_command_log)
                menu.addAction(show_log_action)
                
                menu.addSeparator()
                
        # Add copy actions
        copy_action = QAction("📋 复制单元格", self)
        copy_action.triggered.connect(lambda: self.copy_cell(row, col))
        menu.addAction(copy_action)
        
        copy_row_action = QAction("📋 复制整行", self)
        copy_row_action.triggered.connect(lambda: self.copy_row(row))
        menu.addAction(copy_row_action)
        
        if col == 5 and self.check_timestamps:  # Timestamp column
            timestamp_item = self.table.item(row, 5)
            entry = timestamp_item.data(Qt.UserRole) if timestamp_item else None
            
            if entry and entry.get('timestamp_anomalies'):
                menu.addSeparator()
                details_action = QAction("📝 查看异常详情", self)
                details_action.triggered.connect(lambda: self.show_anomaly_details(entry))
                menu.addAction(details_action)
                
        menu.exec_(self.table.viewport().mapToGlobal(position))
        
    def show_command_log(self):
        """Show command log dialog"""
        command_logger.show_dialog(self)
        command_logger.log_info("命令日志窗口已打开 - 分析时间戳时执行的所有命令将显示在此")
        command_logger.log_separator()
        
    def show_timestamp_analysis(self, file_path: str):
        """Show detailed timestamp analysis in a message box"""
        try:
            self.info_label.setText(f"正在分析: {file_path}")
            
            # Show command log if not visible
            if self.timestamp_check_cb.isChecked():
                command_logger.show_dialog(self)
                command_logger.log_info(f"开始分析文件: {file_path}")
                command_logger.log_separator()
            
            summary = self.timestamp_analyzer.get_summary(file_path)
            
            QMessageBox.information(
                self, 
                f"时间戳分析 - {Path(file_path).name}",
                summary
            )
        except Exception as e:
            QMessageBox.warning(
                self,
                "分析失败",
                f"无法分析文件时间戳:\n{str(e)}"
            )
        finally:
            self.info_label.setText("")
            
    def quick_timestamp_check(self, file_path: str):
        """Quick timestamp anomaly check"""
        try:
            # Show command log if enabled
            if self.timestamp_check_cb.isChecked():
                command_logger.show_dialog(self)
                command_logger.log_info(f"快速检查文件: {file_path}")
                command_logger.log_separator()
            
            is_suspicious, anomalies = self.timestamp_analyzer.check_file_timestamps(file_path)
            
            if is_suspicious:
                msg = f"⚠️ 发现 {len(anomalies)} 个时间戳异常:\n\n"
                msg += "\n".join(f"• {a}" for a in anomalies)
                QMessageBox.warning(self, "时间戳异常", msg)
            else:
                QMessageBox.information(self, "时间戳正常", "✅ 未发现时间戳异常")
        except Exception as e:
            QMessageBox.warning(self, "检查失败", f"无法检查时间戳:\n{str(e)}")
            
    def show_anomaly_details(self, entry: Dict[str, Any]):
        """Show detailed anomaly information"""
        anomalies = entry.get('timestamp_anomalies', [])
        image_path = entry.get('image path', 'Unknown')
        
        msg = f"文件: {image_path}\n\n"
        msg += f"发现 {len(anomalies)} 个时间戳异常:\n\n"
        msg += "\n".join(f"• {a}" for a in anomalies)
        
        QMessageBox.information(self, "时间戳异常详情", msg)
        
    def copy_cell(self, row: int, col: int):
        """Copy cell content to clipboard"""
        item = self.table.item(row, col)
        if item:
            clipboard = self.table.clipboard()
            clipboard.setText(item.text())
            self.info_label.setText("已复制到剪贴板")
            
    def copy_row(self, row: int):
        """Copy entire row to clipboard"""
        row_data = []
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            row_data.append(item.text() if item else "")
            
        clipboard = self.table.clipboard()
        clipboard.setText("\t".join(row_data))
        self.info_label.setText("已复制整行到剪贴板")
