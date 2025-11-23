"""
Startup Dialog Module
Shows initialization progress and handles tool downloads
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QProgressBar, QPushButton, QTextEdit, QGroupBox
)
from PySide6.QtCore import Qt, Signal, QTimer, Slot
from PySide6.QtGui import QFont
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.core.downloader import ToolDownloader, get_missing_tools
from src.config import APP_NAME, APP_VERSION
from src.ui.workers import global_task_manager


class StartupDialog(QDialog):
    """
    Startup dialog that checks for required tools and downloads them if necessary
    Uses TaskManager for async operations instead of QThread
    """
    
    # Signal emitted when initialization is complete
    initialization_complete = Signal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.downloader = ToolDownloader()
        self.download_results = {}
        self.task_running = False
        self.init_ui()
        self.check_tools()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"{APP_NAME} - 初始化")
        self.setFixedSize(600, 400)
        self.setWindowFlags(Qt.WindowTitleHint | Qt.CustomizeWindowHint)
        
        # Main layout
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title section
        title_layout = QVBoxLayout()
        
        # App title
        title_label = QLabel(f"{APP_NAME}")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        
        # Version
        version_label = QLabel(f"版本 {APP_VERSION}")
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setStyleSheet("color: #7f8c8d;")
        
        title_layout.addWidget(title_label)
        title_layout.addWidget(version_label)
        
        # Status section
        status_group = QGroupBox("初始化状态")
        status_layout = QVBoxLayout()
        
        # Current status label
        self.status_label = QLabel("正在检查系统环境...")
        self.status_label.setWordWrap(True)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%")
        
        # Current tool being downloaded
        self.current_tool_label = QLabel("")
        self.current_tool_label.setStyleSheet("color: #3498db;")
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_bar)
        status_layout.addWidget(self.current_tool_label)
        status_group.setLayout(status_layout)
        
        # Log section
        log_group = QGroupBox("详细信息")
        log_layout = QVBoxLayout()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(120)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #2c3e50;
                color: #ecf0f1;
                font-family: Consolas, Monaco, monospace;
                font-size: 10pt;
                border: none;
                padding: 5px;
            }
        """)
        
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        
        # Button section
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.skip_button = QPushButton("跳过")
        self.skip_button.clicked.connect(self.skip_download)
        self.skip_button.setEnabled(False)
        
        self.continue_button = QPushButton("继续")
        self.continue_button.clicked.connect(self.continue_to_main)
        self.continue_button.setEnabled(False)
        self.continue_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 8px 20px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        
        button_layout.addWidget(self.skip_button)
        button_layout.addWidget(self.continue_button)
        
        # Add all to main layout
        layout.addLayout(title_layout)
        layout.addWidget(status_group)
        layout.addWidget(log_group)
        layout.addStretch()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Apply dark theme
        self.apply_theme()
        
    def apply_theme(self):
        """Apply dark theme to the dialog"""
        self.setStyleSheet("""
            QDialog {
                background-color: #34495e;
            }
            QLabel {
                color: #ecf0f1;
            }
            QGroupBox {
                color: #ecf0f1;
                border: 1px solid #7f8c8d;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QProgressBar {
                border: 1px solid #7f8c8d;
                border-radius: 4px;
                background-color: #2c3e50;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 3px;
            }
            QPushButton {
                background-color: #7f8c8d;
                color: white;
                padding: 6px 15px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #95a5a6;
            }
        """)
        
    def check_tools(self):
        """Check for missing tools and start download if necessary"""
        self.append_log("正在检查必需的工具...")
        
        missing_tools = get_missing_tools()
        
        if not missing_tools:
            self.append_log("[OK] 所有必需工具已就绪")
            self.status_label.setText("初始化完成！")
            self.progress_bar.setValue(100)
            self.continue_button.setEnabled(True)
            
            # Auto-continue after 1 second
            QTimer.singleShot(1000, self.continue_to_main)
        else:
            self.append_log(f"需要下载以下工具: {', '.join(missing_tools)}")
            self.start_download()
            
    def start_download(self):
        """Start the download task using TaskManager"""
        self.status_label.setText("正在下载必需的工具...")
        self.skip_button.setEnabled(True)
        self.task_running = True
        
        # Start download task
        global_task_manager.start_task(
            self.run_download_task,
            on_result=self.on_download_finished,
            on_error=self.on_download_error,
            on_finished=self.on_task_finished,
            on_progress=self.on_download_progress,
            on_status=self.on_status_update
        )
        
    def run_download_task(self, progress_callback=None, status_callback=None, **kwargs):
        """
        Download task function (runs in worker thread)
        
        Args:
            progress_callback: Signal to emit progress updates
            status_callback: Signal to emit status messages
            
        Returns:
            Dict mapping tool names to success status
        """
        if status_callback:
            status_callback.emit("正在检查必需的工具...")
        
        # Simple progress callback - just emit overall progress
        def progress_wrapper(tool_name, current, total):
            """Wrapper to format progress updates for UI"""
            if status_callback:
                # Send tool-specific status message
                status_callback.emit(f"正在下载 {tool_name}: {current // 1024} KB / {total // 1024} KB")
                
            if progress_callback and total > 0:
                # Calculate percentage based on single tool
                percentage = int((current / total) * 100)
                progress_callback.emit(percentage)
        
        return self.downloader.check_and_download_all(progress_wrapper)
        
    @Slot(int)
    def on_download_progress(self, percentage):
        """Handle progress updates"""
        self.progress_bar.setValue(percentage)
        
    @Slot(str)
    def on_status_update(self, message):
        """Handle status updates"""
        self.status_label.setText(message)
        self.append_log(message)
        
    @Slot(object)
    def on_download_finished(self, results):
        """Handle download completion"""
        self.download_results = results
        
        # Check if all downloads were successful
        all_success = all(results.values())
        
        if all_success:
            self.append_log("[OK] 所有工具下载成功")
            self.status_label.setText("初始化完成！")
            self.progress_bar.setValue(100)
            self.continue_button.setEnabled(True)
            
            # Auto-continue after 1 second
            QTimer.singleShot(1000, self.continue_to_main)
        else:
            failed = [name for name, success in results.items() if not success]
            self.append_log(f"[FAIL] 以下工具下载失败: {', '.join(failed)}")
            self.status_label.setText("部分工具下载失败")
            self.skip_button.setText("忽略并继续")
            self.skip_button.setEnabled(True)
            self.continue_button.setText("重试")
            self.continue_button.setEnabled(True)
            
    @Slot(tuple)
    def on_download_error(self, error_info):
        """Handle download errors"""
        _, error, traceback_str = error_info
        error_message = str(error)
        self.append_log(f"[ERROR] 错误: {error_message}")
        self.status_label.setText("下载失败")
        self.skip_button.setEnabled(True)
        self.continue_button.setText("重试")
        self.continue_button.setEnabled(True)
        
    @Slot()
    def on_task_finished(self):
        """Called when task completes (success or error)"""
        self.task_running = False
        
    def append_log(self, message):
        """Append message to the log"""
        self.log_text.append(message)
        
    def skip_download(self):
        """Skip the download and continue"""
        # Note: TaskManager doesn't expose direct task cancellation yet
        # This is a TODO for Worker enhancement
        self.append_log("[SKIP] 跳过工具下载")
        self.initialization_complete.emit()
        self.accept()
        
    def continue_to_main(self):
        """Continue to the main application"""
        if self.continue_button.text() == "重试":
            # Retry download
            self.continue_button.setEnabled(False)
            self.continue_button.setText("继续")
            self.check_tools()
        else:
            # Continue to main window
            self.initialization_complete.emit()
            self.accept()
            
    def closeEvent(self, event):
        """Handle close event"""
        # TaskManager will handle cleanup when app closes
        # No need to manually stop threads
        event.accept()
