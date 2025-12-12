"""
Sidebar Module
Navigation sidebar component
"""

from PySide6.QtWidgets import QListWidget, QListWidgetItem
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

# Import configuration
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.config import SIDEBAR_WIDTH, MODULE_ICONS


class ModuleNavigator(QListWidget):
    """Custom navigation sidebar for modules"""
    
    module_selected = Signal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(SIDEBAR_WIDTH)
        self.setup_ui()
        self.populate_modules()
        
    def setup_ui(self):
        """Setup the UI"""
        self.setStyleSheet("""
            QListWidget {
                background-color: #2c3e50;
                border: none;
                outline: none;
            }
            QListWidget::item {
                color: #ecf0f1;
                padding: 15px;
                border-left: 3px solid transparent;
            }
            QListWidget::item:hover {
                background-color: #34495e;
            }
            QListWidget::item:selected {
                background-color: #34495e;
                border-left: 3px solid #3498db;
            }
        """)
        
        # Set font
        font = QFont()
        font.setPointSize(11)
        self.setFont(font)
        
    def populate_modules(self):
        """Add module items to the navigator"""
        modules = [
            ("dashboard", "系统概览"),
            ("process", "进程分析"),
            ("network", "网络连接"),
            ("persistence", "持久化检测"),
            ("logs", "日志分析")
        ]
        
        for module_id, module_name in modules:
            item = QListWidgetItem(f"{MODULE_ICONS.get(module_id, '📁')} {module_name}")
            item.setData(Qt.UserRole, module_id)
            self.addItem(item)
        
        # Select first item by default
        self.setCurrentRow(0)
        
        # Connect selection change
        self.itemSelectionChanged.connect(self.on_selection_changed)
        
    def on_selection_changed(self):
        """Handle module selection"""
        current_item = self.currentItem()
        if current_item:
            module_id = current_item.data(Qt.UserRole)
            self.module_selected.emit(module_id)

