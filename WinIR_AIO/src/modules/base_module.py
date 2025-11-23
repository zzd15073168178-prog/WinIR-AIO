"""
Base Module Class
Abstract base class for all WinIR-AIO modules
"""

from typing import Any, Dict, Optional
import logging
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from PySide6.QtCore import Signal

logger = logging.getLogger(__name__)


class BaseModule(QWidget):
    """
    Base class for all modules in WinIR-AIO
    
    Each module should inherit from this class and implement
    the abstract methods
    """
    
    # Signals
    status_update = Signal(str)  # Emit status updates
    progress_update = Signal(int)  # Emit progress percentage
    data_ready = Signal(dict)  # Emit when data is ready
    
    def __init__(self, parent=None, module_name: str = "BaseModule"):
        """
        Initialize base module
        
        Args:
            parent: Parent widget
            module_name: Name of the module for logging
        """
        super().__init__(parent)
        self.module_name = module_name
        self.data: Dict[str, Any] = {}
        self.is_loading = False
        
        # Setup UI
        self.init_ui()
        
    def init_ui(self):
        """Initialize the base UI layout"""
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        
    def refresh(self):
        """
        Refresh module data
        
        This method should be implemented by each module to
        reload/refresh its data
        """
        raise NotImplementedError("Subclasses must implement refresh()")
    
    def export_data(self, filename: str, format: str = "CSV"):
        """
        Export module data to file
        
        Args:
            filename: Path to export file
            format: Export format (CSV, JSON, HTML, TXT)
        """
        raise NotImplementedError("Subclasses must implement export_data()")
    
    def cleanup(self):
        """
        Cleanup resources when module is closed
        
        Override this method if the module needs to perform
        cleanup operations
        """
        logger.info(f"{self.module_name} cleanup completed")
    
    def set_loading(self, loading: bool):
        """
        Set loading state
        
        Args:
            loading: Whether the module is loading data
        """
        self.is_loading = loading
        if loading:
            self.status_update.emit(f"{self.module_name} 正在加载...")
        else:
            self.status_update.emit(f"{self.module_name} 就绪")
    
    def emit_progress(self, current: int, total: int):
        """
        Emit progress update
        
        Args:
            current: Current progress value
            total: Total value
        """
        if total > 0:
            percentage = int((current / total) * 100)
            self.progress_update.emit(percentage)
    
    def emit_status(self, message: str):
        """
        Emit status message
        
        Args:
            message: Status message to emit
        """
        self.status_update.emit(message)
        logger.info(f"{self.module_name}: {message}")
    
    def handle_error(self, error: Exception, message: str = None):
        """
        Handle and log errors
        
        Args:
            error: Exception that occurred
            message: Optional custom error message
        """
        error_msg = message or f"Error in {self.module_name}"
        logger.error(f"{error_msg}: {str(error)}")
        self.status_update.emit(f"错误: {error_msg}")
