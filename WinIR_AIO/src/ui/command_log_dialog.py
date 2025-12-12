"""
Command Log Dialog - 显示命令执行日志
Shows all commands executed during analysis
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTextEdit, QPushButton,
    QHBoxLayout, QCheckBox, QLabel
)
from PySide6.QtCore import Qt, Signal, Slot, QTimer
from PySide6.QtGui import QTextCursor, QFont, QColor, QTextCharFormat
import datetime
from typing import Optional

class CommandLogDialog(QDialog):
    """显示命令执行日志的对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("命令执行日志")
        self.setModal(False)  # Non-modal so user can interact with main window
        self.resize(900, 600)
        
        self.setup_ui()
        self.commands_count = 0
        
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("🖥️ 命令执行日志"))
        
        self.auto_scroll_cb = QCheckBox("自动滚动")
        self.auto_scroll_cb.setChecked(True)
        header_layout.addWidget(self.auto_scroll_cb)
        
        header_layout.addStretch()
        
        self.status_label = QLabel("就绪")
        header_layout.addWidget(self.status_label)
        
        layout.addLayout(header_layout)
        
        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Consolas", 9))
        self.log_display.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
                padding: 5px;
            }
        """)
        layout.addWidget(self.log_display)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.clear_btn = QPushButton("清空日志")
        self.clear_btn.clicked.connect(self.clear_log)
        button_layout.addWidget(self.clear_btn)
        
        self.save_btn = QPushButton("保存日志")
        self.save_btn.clicked.connect(self.save_log)
        button_layout.addWidget(self.save_btn)
        
        button_layout.addStretch()
        
        self.close_btn = QPushButton("关闭")
        self.close_btn.clicked.connect(self.close)
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Add initial message
        self.add_info("命令日志已启动 - 所有执行的命令将在此显示")
        self.add_separator()
        
    def add_command(self, command: str, description: Optional[str] = None):
        """添加命令到日志"""
        self.commands_count += 1
        
        # Add timestamp
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Format the command entry
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        # Timestamp
        fmt = QTextCharFormat()
        fmt.setForeground(QColor("#608b4e"))  # Green
        cursor.insertText(f"[{timestamp}] ", fmt)
        
        # Command number
        fmt.setForeground(QColor("#4ec9b0"))  # Cyan
        cursor.insertText(f"CMD #{self.commands_count:03d}: ", fmt)
        
        # Description
        if description:
            fmt.setForeground(QColor("#808080"))  # Gray
            cursor.insertText(f"{description}\n", fmt)
        
        # Command
        fmt.setForeground(QColor("#ce9178"))  # Orange
        cursor.insertText(f"$ {command}\n", fmt)
        
        # Auto scroll
        if self.auto_scroll_cb.isChecked():
            self.log_display.verticalScrollBar().setValue(
                self.log_display.verticalScrollBar().maximum()
            )
            
        self.status_label.setText(f"已执行 {self.commands_count} 个命令")
        
    def add_output(self, output: str, is_error: bool = False):
        """添加命令输出到日志"""
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        fmt = QTextCharFormat()
        if is_error:
            fmt.setForeground(QColor("#f48771"))  # Red
        else:
            fmt.setForeground(QColor("#d4d4d4"))  # Light gray
            
        # Indent output
        lines = output.strip().split('\n')
        for line in lines:
            cursor.insertText(f"  {line}\n", fmt)
            
        # Auto scroll
        if self.auto_scroll_cb.isChecked():
            self.log_display.verticalScrollBar().setValue(
                self.log_display.verticalScrollBar().maximum()
            )
            
    def add_result(self, success: bool, message: Optional[str] = None):
        """添加命令执行结果"""
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        fmt = QTextCharFormat()
        if success:
            fmt.setForeground(QColor("#608b4e"))  # Green
            status = "✓ 成功"
        else:
            fmt.setForeground(QColor("#f48771"))  # Red
            status = "✗ 失败"
            
        if message:
            cursor.insertText(f"  {status}: {message}\n", fmt)
        else:
            cursor.insertText(f"  {status}\n", fmt)
            
    def add_info(self, text: str):
        """添加信息文本"""
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        fmt = QTextCharFormat()
        fmt.setForeground(QColor("#3794ff"))  # Blue
        cursor.insertText(f"ℹ️ {text}\n", fmt)
        
    def add_separator(self):
        """添加分隔线"""
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        fmt = QTextCharFormat()
        fmt.setForeground(QColor("#3c3c3c"))  # Dark gray
        cursor.insertText("─" * 80 + "\n", fmt)
        
    def clear_log(self):
        """清空日志"""
        self.log_display.clear()
        self.commands_count = 0
        self.status_label.setText("日志已清空")
        self.add_info("命令日志已清空")
        self.add_separator()
        
    def save_log(self):
        """保存日志到文件"""
        from PySide6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "保存命令日志",
            f"command_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*.*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_display.toPlainText())
                self.add_info(f"日志已保存到: {filename}")
            except Exception as e:
                self.add_info(f"保存失败: {str(e)}")


class CommandLogger:
    """单例命令记录器"""
    
    _instance = None
    _dialog = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
        
    def show_dialog(self, parent=None):
        """显示日志对话框"""
        if not self._dialog:
            self._dialog = CommandLogDialog(parent)
        self._dialog.show()
        self._dialog.raise_()
        self._dialog.activateWindow()
        return self._dialog
        
    def log_command(self, command: str, description: Optional[str] = None):
        """记录命令"""
        if self._dialog and self._dialog.isVisible():
            self._dialog.add_command(command, description)
            
    def log_output(self, output: str, is_error: bool = False):
        """记录输出"""
        if self._dialog and self._dialog.isVisible():
            self._dialog.add_output(output, is_error)
            
    def log_result(self, success: bool, message: Optional[str] = None):
        """记录结果"""
        if self._dialog and self._dialog.isVisible():
            self._dialog.add_result(success, message)
            
    def log_info(self, text: str):
        """记录信息"""
        if self._dialog and self._dialog.isVisible():
            self._dialog.add_info(text)
            
    def log_separator(self):
        """添加分隔线"""
        if self._dialog and self._dialog.isVisible():
            self._dialog.add_separator()


# Global instance
command_logger = CommandLogger()
