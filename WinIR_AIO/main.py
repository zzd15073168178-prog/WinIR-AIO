#!/usr/bin/env python3
"""
WinIR-AIO - Windows Incident Response All-in-One Tool
Main entry point for the application
"""

import sys
import os
import logging
import traceback
from pathlib import Path
from datetime import datetime

# Set up path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging early
from src.config import LOGS_DIR, APP_NAME, APP_VERSION
from logging.handlers import RotatingFileHandler

# Setup logging with rotation
log_file = LOGS_DIR / "winir.log"
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create rotating file handler (10MB max, keep 5 backups)
file_handler = RotatingFileHandler(
    log_file, 
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5,
    encoding='utf-8'
)
file_handler.setFormatter(log_formatter)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, console_handler]
)

logger = logging.getLogger(__name__)

# PySide6 imports
try:
    from PySide6.QtWidgets import QApplication, QMessageBox, QStyleFactory
    from PySide6.QtCore import Qt, QCoreApplication
    from PySide6.QtGui import QPalette, QColor, QIcon
except ImportError as e:
    print(f"错误: 无法导入 PySide6。请确保已安装: pip install PySide6")
    print(f"详细错误: {e}")
    sys.exit(1)

# Local imports
from src.ui.startup_dialog import StartupDialog
from src.ui.main_window import MainWindow
from src.core.executor import check_admin_privileges
from src.core.downloader import get_missing_tools
from src.config import WINDOW_TITLE, is_admin


class WinIRApplication(QApplication):
    """Custom QApplication class for WinIR-AIO"""
    
    def __init__(self, argv):
        super().__init__(argv)
        self.main_window = None
        
        # Set application metadata
        self.setApplicationName(APP_NAME)
        self.setApplicationDisplayName(WINDOW_TITLE)
        self.setOrganizationName("CyberSecurity Team")
        
        # Apply application style
        self.setup_style()
        
    def setup_style(self):
        """Configure application style and theme"""
        # Set Fusion style for modern look
        self.setStyle(QStyleFactory.create("Fusion"))
        
        # Create dark palette
        dark_palette = QPalette()
        
        # Window colors
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        
        # Base colors
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        
        # Text colors
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        
        # Button colors
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        
        # Bright text
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        
        # Link colors
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        
        # Highlight colors
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        # Apply palette
        self.setPalette(dark_palette)
        
        # Additional stylesheet
        self.setStyleSheet("""
            QToolTip {
                color: #ffffff;
                background-color: #2a2a2a;
                border: 1px solid #3a3a3a;
                padding: 4px;
            }
            QMenuBar {
                background-color: #2a2a2a;
                color: white;
            }
            QMenuBar::item:selected {
                background-color: #3a3a3a;
            }
            QMenu {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #3a3a3a;
            }
            QMenu::item:selected {
                background-color: #3a3a3a;
            }
            QTabWidget::pane {
                border: 1px solid #3a3a3a;
                background-color: #2a2a2a;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: white;
                padding: 8px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #3498db;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)


def check_requirements():
    """Check if all requirements are met"""
    errors = []
    warnings = []
    
    # Check Python version
    if sys.version_info < (3, 10):
        errors.append(f"需要 Python 3.10 或更高版本 (当前: {sys.version})")
    
    # Check for required modules
    required_modules = {
        'psutil': 'psutil',
        'wmi': 'WMI',
        'win32com': 'pywin32',
        'requests': 'requests'
    }
    
    for module, package in required_modules.items():
        try:
            __import__(module)
        except ImportError:
            warnings.append(f"缺少模块 {module}。请安装: pip install {package}")
    
    # Check for admin privileges (warning only)
    if not is_admin():
        warnings.append("建议以管理员权限运行以获得完整功能")
    
    return errors, warnings


def show_error_dialog(title: str, message: str, details: str = None):
    """Show an error dialog"""
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Critical)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    
    if details:
        msg_box.setDetailedText(details)
    
    msg_box.setStandardButtons(QMessageBox.Ok)
    msg_box.exec()


def show_warning_dialog(title: str, message: str, details: str = None):
    """Show a warning dialog"""
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Warning)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    
    if details:
        msg_box.setDetailedText(details)
    
    msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
    return msg_box.exec() == QMessageBox.Ok


def main():
    """Main entry point"""
    try:
        logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Admin privileges: {is_admin()}")
        
        # Create Qt application
        app = WinIRApplication(sys.argv)
        
        # Check requirements
        errors, warnings = check_requirements()
        
        if errors:
            error_msg = "无法启动应用程序:\n\n" + "\n".join(errors)
            show_error_dialog("启动错误", error_msg)
            return 1
        
        if warnings:
            warning_msg = "检测到以下警告:\n\n" + "\n".join(warnings)
            warning_msg += "\n\n是否继续运行？"
            if not show_warning_dialog("警告", warning_msg):
                return 0
        
        # Check for missing tools
        missing_tools = get_missing_tools()
        
        if missing_tools:
            logger.info(f"Missing tools detected: {missing_tools}")
            
            # Show startup dialog for downloading tools
            startup_dialog = StartupDialog()
            
            if startup_dialog.exec() != StartupDialog.Accepted:
                logger.info("User cancelled initialization")
                return 0
        else:
            logger.info("All required tools are available")
        
        # Create and show main window
        try:
            main_window = MainWindow()
            main_window.show()
            
            # Store reference in app
            app.main_window = main_window
            
        except Exception as e:
            logger.error(f"Failed to create main window: {e}")
            logger.error(traceback.format_exc())
            show_error_dialog(
                "窗口创建失败",
                "无法创建主窗口",
                traceback.format_exc()
            )
            return 1
        
        # Run the application
        logger.info("Application started successfully")
        return_code = app.exec()
        
        logger.info(f"Application exited with code: {return_code}")
        return return_code
        
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}")
        logger.critical(traceback.format_exc())
        
        try:
            show_error_dialog(
                "严重错误",
                f"应用程序遇到未处理的错误:\n{str(e)}",
                traceback.format_exc()
            )
        except:
            # If we can't even show a dialog, just print
            print(f"CRITICAL ERROR: {e}")
            print(traceback.format_exc())
        
        return 1


if __name__ == "__main__":
    sys.exit(main())
