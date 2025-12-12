"""
Main Window Module
The main application window with navigation and module loading
"""

import sys
import logging
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QStackedWidget, QMenuBar, QMenu, QStatusBar,
    QToolBar, QSplitter, QListWidget, QListWidgetItem,
    QLabel, QPushButton, QMessageBox, QFileDialog,
    QProgressBar, QFrame
)
from PySide6.QtCore import Qt, Signal, QTimer, QSize
from PySide6.QtGui import QAction, QIcon, QFont

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.config import (
    WINDOW_TITLE, WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT,
    SIDEBAR_WIDTH, MODULE_ICONS, APP_VERSION, is_admin,
    EXPORT_FORMATS, THEME
)

# Import modules (we'll create placeholder classes for now)
from src.modules.dashboard import DashboardModule
from src.modules.process import ProcessModule
from src.modules.network import NetworkModule
from src.modules.persistence import PersistenceModule
from src.modules.logs import LogsModule
from src.ui.sidebar import ModuleNavigator

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.modules: Dict[str, QWidget] = {}
        self.current_module: Optional[str] = None
        self.init_ui()
        self.load_modules()
        self.setup_timers()
        
    def init_ui(self):
        """Initialize the user interface"""
        # Set window properties
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        
        # Set window state
        if is_admin():
            self.setWindowTitle(f"{WINDOW_TITLE} [管理员]")
        else:
            self.setWindowTitle(f"{WINDOW_TITLE} [受限模式]")
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create central widget
        self.create_central_widget()
        
        # Create status bar
        self.create_status_bar()
        
        # Apply theme
        self.apply_theme()
        
    def create_menu_bar(self):
        """Create the menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("文件(&F)")
        
        export_action = QAction("导出报告(&E)", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("退出(&X)", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("工具(&T)")
        
        refresh_action = QAction("刷新(&R)", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_current_module)
        tools_menu.addAction(refresh_action)
        
        tools_menu.addSeparator()
        
        log_viewer_action = QAction("日志查看器(&L)", self)
        log_viewer_action.setShortcut("Ctrl+L")
        log_viewer_action.triggered.connect(self.show_log_viewer)
        tools_menu.addAction(log_viewer_action)
        
        settings_action = QAction("设置(&S)", self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # View menu
        view_menu = menubar.addMenu("视图(&V)")
        
        fullscreen_action = QAction("全屏(&F)", self)
        fullscreen_action.setShortcut("F11")
        fullscreen_action.setCheckable(True)
        fullscreen_action.triggered.connect(self.toggle_fullscreen)
        view_menu.addAction(fullscreen_action)
        
        # Help menu
        help_menu = menubar.addMenu("帮助(&H)")
        
        about_action = QAction("关于(&A)", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_toolbar(self):
        """Create the toolbar"""
        toolbar = self.addToolBar("主工具栏")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        
        # Add actions
        refresh_action = QAction("🔄 刷新", self)
        refresh_action.triggered.connect(self.refresh_current_module)
        toolbar.addAction(refresh_action)
        
        toolbar.addSeparator()
        
        export_action = QAction("💾 导出", self)
        export_action.triggered.connect(self.export_report)
        toolbar.addAction(export_action)
        
        toolbar.addSeparator()
        
        # Add admin status label
        admin_label = QLabel()
        if is_admin():
            admin_label.setText(" ✅ 管理员权限 ")
            admin_label.setStyleSheet("color: #27ae60; font-weight: bold;")
        else:
            admin_label.setText(" ⚠️ 受限权限 ")
            admin_label.setStyleSheet("color: #f39c12; font-weight: bold;")
        toolbar.addWidget(admin_label)
        
    def create_central_widget(self):
        """Create the central widget with navigation and content"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Create navigator
        self.navigator = ModuleNavigator()
        self.navigator.module_selected.connect(self.switch_module)
        
        # Create content stack
        self.content_stack = QStackedWidget()
        self.content_stack.setStyleSheet("""
            QStackedWidget {
                background-color: #34495e;
                border: none;
            }
        """)
        
        # Add to splitter
        splitter.addWidget(self.navigator)
        splitter.addWidget(self.content_stack)
        splitter.setSizes([SIDEBAR_WIDTH, WINDOW_MIN_WIDTH - SIDEBAR_WIDTH])
        
        # Add splitter to layout
        main_layout.addWidget(splitter)
        
    def create_status_bar(self):
        """Create the status bar"""
        self.status_bar = self.statusBar()
        
        # Create status widgets
        self.status_label = QLabel("就绪")
        self.status_bar.addWidget(self.status_label)
        
        # Add permanent widgets
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        self.time_label = QLabel()
        self.update_time()
        self.status_bar.addPermanentWidget(self.time_label)
        
    def load_modules(self):
        """Load all modules"""
        try:
            # Create module instances
            self.modules = {
                "dashboard": DashboardModule(self),
                "process": ProcessModule(self),
                "network": NetworkModule(self),
                "persistence": PersistenceModule(self),
                "logs": LogsModule(self)
            }
            
            # Add modules to stack
            for module_id, module_widget in self.modules.items():
                self.content_stack.addWidget(module_widget)
                
            # Switch to dashboard by default
            self.switch_module("dashboard")
            
        except Exception as e:
            logger.error(f"Failed to load modules: {e}")
            QMessageBox.critical(self, "错误", f"无法加载模块: {str(e)}")
            
    def switch_module(self, module_id: str):
        """Switch to a different module"""
        if module_id not in self.modules:
            logger.error(f"Unknown module: {module_id}")
            return
            
        self.current_module = module_id
        module_widget = self.modules[module_id]
        self.content_stack.setCurrentWidget(module_widget)
        
        # Update status
        self.status_label.setText(f"当前模块: {module_id}")
        
        # Trigger refresh if module supports it
        if hasattr(module_widget, 'refresh'):
            module_widget.refresh()
            
    def refresh_current_module(self):
        """Refresh the current module"""
        if self.current_module and self.current_module in self.modules:
            module_widget = self.modules[self.current_module]
            if hasattr(module_widget, 'refresh'):
                self.show_progress(True)
                self.status_label.setText("正在刷新...")
                module_widget.refresh()
                QTimer.singleShot(1000, lambda: self.show_progress(False))
                
    def export_report(self):
        """Export current module data"""
        if not self.current_module:
            return
            
        module_widget = self.modules.get(self.current_module)
        if not module_widget or not hasattr(module_widget, 'export_data'):
            QMessageBox.information(self, "信息", "当前模块不支持导出")
            return
            
        # Get export format
        file_filter = ";;".join([
            f"{fmt} Files (*.{fmt.lower()})" for fmt in EXPORT_FORMATS
        ])
        
        filename, selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出报告",
            f"winir_report_{self.current_module}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            file_filter
        )
        
        if filename:
            try:
                # Get format from filter
                format_name = selected_filter.split()[0]
                module_widget.export_data(filename, format_name)
                QMessageBox.information(self, "成功", f"报告已导出到:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
                
    def show_settings(self):
        """Show settings dialog"""
        QMessageBox.information(self, "设置", "设置功能正在开发中...")
        
    def show_log_viewer(self):
        """Show log viewer dialog"""
        try:
            from src.ui.log_viewer import LogViewerDialog
            dialog = LogViewerDialog(self)
            dialog.exec()
        except Exception as e:
            logger.error(f"Failed to open log viewer: {e}")
            QMessageBox.warning(self, "错误", f"无法打开日志查看器:\n{str(e)}")
        
    def show_about(self):
        """Show about dialog"""
        about_text = f"""
        <h2>{WINDOW_TITLE}</h2>
        <p>版本: {APP_VERSION}</p>
        <p>一个综合性的Windows事件响应工具</p>
        <br>
        <p><b>功能特性:</b></p>
        <ul>
            <li>系统指纹识别</li>
            <li>进程分析与验证</li>
            <li>网络连接监控</li>
            <li>持久化机制检测</li>
            <li>系统日志分析</li>
        </ul>
        <br>
        <p>© 2025 Cybersecurity Team</p>
        """
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("关于")
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(about_text)
        msg_box.exec()
        
    def toggle_fullscreen(self, checked: bool):
        """Toggle fullscreen mode"""
        if checked:
            self.showFullScreen()
        else:
            self.showNormal()
            
    def show_progress(self, visible: bool, value: int = 0):
        """Show or hide progress bar"""
        self.progress_bar.setVisible(visible)
        if visible and value > 0:
            self.progress_bar.setValue(value)
        elif visible:
            self.progress_bar.setRange(0, 0)  # Indeterminate
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            
    def update_time(self):
        """Update time display"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.setText(f" {current_time} ")
        
    def setup_timers(self):
        """Setup periodic timers"""
        # Time update timer
        self.time_timer = QTimer(self)
        self.time_timer.timeout.connect(self.update_time)
        self.time_timer.start(1000)  # Update every second
        
    def apply_theme(self):
        """Apply custom theme"""
        # Additional styling is handled by the QApplication
        pass
        
    def closeEvent(self, event):
        """Handle close event"""
        reply = QMessageBox.question(
            self,
            "确认退出",
            "确定要退出WinIR-AIO吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Cleanup
            if hasattr(self, 'time_timer'):
                self.time_timer.stop()
                
            # Stop any running module tasks
            for module in self.modules.values():
                if hasattr(module, 'cleanup'):
                    module.cleanup()
                    
            event.accept()
        else:
            event.ignore()
