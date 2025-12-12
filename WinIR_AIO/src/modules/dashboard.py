"""
Dashboard Module
System overview and quick status display
Enhanced to use TaskManager instead of QThread
"""

import platform
import psutil
import socket
from datetime import datetime
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QTextEdit
)
from PySide6.QtCore import Qt, Slot
import logging

from .base_module import BaseModule
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.core.executor import get_system_info, CommandRunner
from src.config import is_admin

logger = logging.getLogger(__name__)


class DashboardModule(BaseModule):
    """Dashboard module for system overview"""
    
    def __init__(self, parent=None):
        super().__init__(parent, "Dashboard")
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the dashboard UI"""
        # System Info Group
        sys_info_group = QGroupBox("系统信息")
        sys_info_layout = QVBoxLayout()
        
        self.sys_info_table = QTableWidget()
        self.sys_info_table.setColumnCount(2)
        self.sys_info_table.setHorizontalHeaderLabels(["项目", "值"])
        self.sys_info_table.horizontalHeader().setStretchLastSection(True)
        self.sys_info_table.setAlternatingRowColors(True)
        
        sys_info_layout.addWidget(self.sys_info_table)
        sys_info_group.setLayout(sys_info_layout)
        
        # Quick Actions Group
        actions_group = QGroupBox("快速操作")
        actions_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("刷新系统信息")
        self.refresh_btn.clicked.connect(self.refresh)
        
        self.export_btn = QPushButton("导出系统信息")
        self.export_btn.clicked.connect(lambda: self.export_data("system_info.txt", "TXT"))
        
        actions_layout.addWidget(self.refresh_btn)
        actions_layout.addWidget(self.export_btn)
        actions_layout.addStretch()
        actions_group.setLayout(actions_layout)
        
        # Admin Status Group
        admin_group = QGroupBox("权限状态")
        admin_layout = QVBoxLayout()
        
        admin_status = "管理员权限" if is_admin() else "标准用户权限"
        admin_color = "#27ae60" if is_admin() else "#e74c3c"
        
        admin_label = QLabel(f"<h3 style='color: {admin_color}'>{admin_status}</h3>")
        admin_label.setAlignment(Qt.AlignCenter)
        
        if not is_admin():
            warning_label = QLabel(
                "⚠️ 某些功能可能受限。建议以管理员身份运行以获得完整功能。"
            )
            warning_label.setWordWrap(True)
            warning_label.setStyleSheet("color: #f39c12; padding: 10px;")
            admin_layout.addWidget(warning_label)
        
        admin_layout.addWidget(admin_label)
        admin_group.setLayout(admin_layout)
        
        # Hotfixes Group
        hotfix_group = QGroupBox("已安装的补丁")
        hotfix_layout = QVBoxLayout()
        
        self.hotfix_text = QTextEdit()
        self.hotfix_text.setReadOnly(True)
        self.hotfix_text.setMaximumHeight(150)
        
        hotfix_layout.addWidget(self.hotfix_text)
        hotfix_group.setLayout(hotfix_layout)
        
        # Add all groups to main layout
        self.main_layout.addWidget(sys_info_group)
        self.main_layout.addWidget(actions_group)
        self.main_layout.addWidget(admin_group)
        self.main_layout.addWidget(hotfix_group)
        self.main_layout.addStretch()
        
        # Initial load
        self.refresh()
        
    def refresh(self):
        """Refresh system information using TaskManager"""
        # Import here to avoid circular import
        from src.ui.workers import global_task_manager
        
        self.set_loading(True)
        self.refresh_btn.setEnabled(False)
        
        # Start system info collection task
        global_task_manager.start_task(
            self.collect_system_info,
            on_result=self.on_info_collected,
            on_error=self.on_collection_error,
            on_finished=self.on_collection_finished
        )
        
        # Load hotfixes separately
        self.load_hotfixes()
        
    def collect_system_info(self, **kwargs) -> dict:
        """
        Collect system information (runs in worker thread)
        
        Returns:
            Dict containing system information
        """
        info = {}
        
        try:
            # Basic system info
            info['hostname'] = socket.gethostname()
            info['platform'] = platform.platform()
            info['processor'] = platform.processor()
            info['architecture'] = platform.machine()
            info['python_version'] = platform.python_version()
            
            # Memory info
            mem = psutil.virtual_memory()
            info['total_memory'] = f"{mem.total // (1024**3)} GB"
            info['available_memory'] = f"{mem.available // (1024**3)} GB"
            info['memory_percent'] = f"{mem.percent}%"
            
            # CPU info
            info['cpu_count'] = psutil.cpu_count()
            info['cpu_percent'] = f"{psutil.cpu_percent(interval=1)}%"
            
            # Disk info
            disk = psutil.disk_usage('/')
            info['disk_total'] = f"{disk.total // (1024**3)} GB"
            info['disk_free'] = f"{disk.free // (1024**3)} GB"
            info['disk_percent'] = f"{disk.percent}%"
            
            # Network interfaces
            interfaces = []
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append(f"{iface}: {addr.address}")
            info['network_interfaces'] = interfaces
            
            # Boot time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            info['boot_time'] = boot_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Get additional Windows info
            cmd_info = get_system_info()
            info.update(cmd_info)
            
            return info
            
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            raise
        
    @Slot(object)
    def on_info_collected(self, data: dict):
        """Handle successful system info collection"""
        self.data = data
        self.update_display(data)
        
    @Slot(tuple)
    def on_collection_error(self, error_info):
        """Handle collection error"""
        _, error, _ = error_info
        self.handle_error(error, "获取系统信息失败")
        
    @Slot()
    def on_collection_finished(self):
        """Cleanup after collection"""
        self.set_loading(False)
        self.refresh_btn.setEnabled(True)
        
    def update_display(self, data: dict):
        """Update the display with system information"""
        self.sys_info_table.setRowCount(0)
        
        # Add items to table
        for key, value in data.items():
            if key == 'network_interfaces':
                # Handle network interfaces separately
                for iface in value:
                    row = self.sys_info_table.rowCount()
                    self.sys_info_table.insertRow(row)
                    self.sys_info_table.setItem(row, 0, QTableWidgetItem("网络接口"))
                    self.sys_info_table.setItem(row, 1, QTableWidgetItem(iface))
            else:
                row = self.sys_info_table.rowCount()
                self.sys_info_table.insertRow(row)
                
                # Translate keys to Chinese
                key_translations = {
                    'hostname': '主机名',
                    'platform': '操作系统',
                    'processor': '处理器',
                    'architecture': '架构',
                    'python_version': 'Python版本',
                    'total_memory': '总内存',
                    'available_memory': '可用内存',
                    'memory_percent': '内存使用率',
                    'cpu_count': 'CPU核心数',
                    'cpu_percent': 'CPU使用率',
                    'disk_total': '磁盘总容量',
                    'disk_free': '磁盘可用',
                    'disk_percent': '磁盘使用率',
                    'boot_time': '启动时间',
                    'windows_version': 'Windows版本',
                    'current_user': '当前用户',
                    'is_admin': '管理员权限'
                }
                
                display_key = key_translations.get(key, key)
                self.sys_info_table.setItem(row, 0, QTableWidgetItem(display_key))
                self.sys_info_table.setItem(row, 1, QTableWidgetItem(str(value)))
        
    def load_hotfixes(self):
        """Load installed hotfixes"""
        try:
            runner = CommandRunner()
            result = runner.run_powershell(
                "Get-HotFix | Select-Object HotFixID, InstalledOn | ConvertTo-Json"
            )
            
            if result.success and result.stdout:
                import json
                hotfixes = json.loads(result.stdout)
                
                if isinstance(hotfixes, list):
                    hotfix_text = "已安装的补丁:\n\n"
                    for hf in hotfixes[-10:]:  # Show last 10 hotfixes
                        hotfix_id = hf.get('HotFixID', 'Unknown')
                        installed = hf.get('InstalledOn', 'Unknown')
                        hotfix_text += f"{hotfix_id} - {installed}\n"
                else:
                    hotfix_text = "无法获取补丁信息"
            else:
                hotfix_text = "获取补丁信息失败"
                
            self.hotfix_text.setText(hotfix_text)
            
        except Exception as e:
            logger.error(f"Failed to load hotfixes: {e}")
            self.hotfix_text.setText(f"加载补丁信息时出错: {str(e)}")
    
    def export_data(self, filename: str, format: str = "CSV"):
        """Export dashboard data"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"WinIR-AIO 系统信息报告\n")
                f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")
                
                if hasattr(self, 'data'):
                    for key, value in self.data.items():
                        if key == 'network_interfaces':
                            f.write("网络接口:\n")
                            for iface in value:
                                f.write(f"  - {iface}\n")
                        else:
                            f.write(f"{key}: {value}\n")
                        
                f.write("\n" + "=" * 50 + "\n")
                f.write("补丁信息:\n")
                f.write(self.hotfix_text.toPlainText())
                
            self.emit_status(f"数据已导出到: {filename}")
            
        except Exception as e:
            self.handle_error(e, "导出失败")
            
    def cleanup(self):
        """Cleanup resources (TaskManager handles worker cleanup)"""
        super().cleanup()
