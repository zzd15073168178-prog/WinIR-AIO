"""
Log Viewer Dialog - View and export application logs
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
    QLabel, QComboBox, QFileDialog, QMessageBox, QCheckBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QTextCursor
import datetime
import os
from pathlib import Path
from typing import Optional
import zipfile
import json

class LogViewerDialog(QDialog):
    """Dialog for viewing and managing application logs"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("日志查看器")
        self.resize(900, 600)
        self.log_file_path = None
        self.auto_refresh_timer = QTimer()
        self.auto_refresh_timer.timeout.connect(self.refresh_log)
        
        self.setup_ui()
        self.load_log_file()
        
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout()
        
        # Header controls
        header_layout = QHBoxLayout()
        
        header_layout.addWidget(QLabel("日志级别过滤:"))
        self.level_filter = QComboBox()
        self.level_filter.addItems(["全部", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.level_filter.currentTextChanged.connect(self.apply_filter)
        header_layout.addWidget(self.level_filter)
        
        self.auto_refresh_cb = QCheckBox("自动刷新")
        self.auto_refresh_cb.stateChanged.connect(self.toggle_auto_refresh)
        header_layout.addWidget(self.auto_refresh_cb)
        
        header_layout.addStretch()
        
        self.status_label = QLabel("")
        header_layout.addWidget(self.status_label)
        
        layout.addLayout(header_layout)
        
        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Consolas", 9))
        self.log_display.setStyleSheet("""
            QTextEdit {
                background-color: #2c3e50;
                color: #ecf0f1;
                border: 1px solid #34495e;
                padding: 5px;
            }
        """)
        layout.addWidget(self.log_display)
        
        # Button bar
        button_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.clicked.connect(self.refresh_log)
        button_layout.addWidget(self.refresh_btn)
        
        self.clear_btn = QPushButton("清空日志")
        self.clear_btn.clicked.connect(self.clear_log)
        button_layout.addWidget(self.clear_btn)
        
        self.export_btn = QPushButton("导出日志")
        self.export_btn.clicked.connect(self.export_log)
        button_layout.addWidget(self.export_btn)
        
        self.diagnostic_btn = QPushButton("生成诊断包")
        self.diagnostic_btn.clicked.connect(self.create_diagnostic_package)
        self.diagnostic_btn.setToolTip("生成包含日志、系统信息和配置的诊断包")
        button_layout.addWidget(self.diagnostic_btn)
        
        button_layout.addStretch()
        
        self.close_btn = QPushButton("关闭")
        self.close_btn.clicked.connect(self.close)
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def load_log_file(self):
        """Load the current log file"""
        try:
            # Import config
            import sys
            from pathlib import Path
            sys.path.append(str(Path(__file__).parent.parent.parent))
            from src.config import LOGS_DIR
            
            # Find the most recent log file
            log_files = list(LOGS_DIR.glob("winir*.log"))
            if not log_files:
                self.log_display.setText("未找到日志文件")
                return
                
            # Get the most recent file
            self.log_file_path = max(log_files, key=lambda p: p.stat().st_mtime)
            self.refresh_log()
            
        except Exception as e:
            self.log_display.setText(f"加载日志失败: {str(e)}")
            
    def refresh_log(self):
        """Refresh log content"""
        if not self.log_file_path or not self.log_file_path.exists():
            return
            
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                
            # Apply filter if needed
            if self.level_filter.currentText() != "全部":
                filtered_lines = []
                level = self.level_filter.currentText()
                for line in content.splitlines():
                    if level in line or not any(lvl in line for lvl in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]):
                        filtered_lines.append(line)
                content = '\n'.join(filtered_lines)
                
            # Update display
            current_scroll = self.log_display.verticalScrollBar().value()
            self.log_display.setPlainText(content)
            
            # Restore scroll position or go to bottom
            if self.auto_refresh_cb.isChecked():
                self.log_display.verticalScrollBar().setValue(
                    self.log_display.verticalScrollBar().maximum()
                )
            else:
                self.log_display.verticalScrollBar().setValue(current_scroll)
                
            # Update status
            file_size = self.log_file_path.stat().st_size / 1024  # KB
            self.status_label.setText(f"日志文件: {self.log_file_path.name} ({file_size:.1f} KB)")
            
        except Exception as e:
            self.log_display.append(f"\n[ERROR] 读取日志失败: {str(e)}")
            
    def apply_filter(self):
        """Apply log level filter"""
        self.refresh_log()
        
    def toggle_auto_refresh(self, state):
        """Toggle auto refresh"""
        if state == Qt.Checked:
            self.auto_refresh_timer.start(1000)  # Refresh every second
        else:
            self.auto_refresh_timer.stop()
            
    def clear_log(self):
        """Clear the log file"""
        reply = QMessageBox.question(
            self, 
            "确认清空", 
            "确定要清空日志文件吗？此操作不可恢复。",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                if self.log_file_path and self.log_file_path.exists():
                    # Create backup before clearing
                    backup_path = self.log_file_path.with_suffix('.backup')
                    self.log_file_path.rename(backup_path)
                    
                    # Create new empty log file
                    self.log_file_path.touch()
                    
                    self.refresh_log()
                    QMessageBox.information(self, "成功", f"日志已清空，备份保存在:\n{backup_path}")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"清空日志失败:\n{str(e)}")
                
    def export_log(self):
        """Export log to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "导出日志",
            f"winir_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*.*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_display.toPlainText())
                QMessageBox.information(self, "成功", f"日志已导出到:\n{filename}")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"导出失败:\n{str(e)}")
                
    def create_diagnostic_package(self):
        """Create a diagnostic package with logs and system info"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "保存诊断包",
            f"winir_diagnostic_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
            "ZIP Files (*.zip);;All Files (*.*)"
        )
        
        if not filename:
            return
            
        try:
            import platform
            import psutil
            from src.core.executor import get_system_info
            
            with zipfile.ZipFile(filename, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Add log files
                from src.config import LOGS_DIR
                for log_file in LOGS_DIR.glob("*.log"):
                    zf.write(log_file, f"logs/{log_file.name}")
                    
                # Add system information
                sys_info = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "platform": platform.platform(),
                    "python_version": platform.python_version(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "cpu_count": psutil.cpu_count(),
                    "memory_total": psutil.virtual_memory().total,
                    "memory_available": psutil.virtual_memory().available,
                    "disk_usage": {
                        str(disk.mountpoint): psutil.disk_usage(disk.mountpoint)._asdict()
                        for disk in psutil.disk_partitions() if disk.fstype
                    },
                    "windows_info": get_system_info()
                }
                
                zf.writestr("system_info.json", json.dumps(sys_info, indent=2, default=str))
                
                # Add README
                readme_content = f"""
WinIR-AIO Diagnostic Package
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Contents:
- logs/: Application log files
- system_info.json: System information and configuration

This package can be used for troubleshooting and support purposes.
"""
                zf.writestr("README.txt", readme_content)
                
            QMessageBox.information(self, "成功", f"诊断包已创建:\n{filename}")
            
        except Exception as e:
            QMessageBox.warning(self, "错误", f"创建诊断包失败:\n{str(e)}")
            
    def closeEvent(self, event):
        """Handle close event"""
        self.auto_refresh_timer.stop()
        event.accept()
