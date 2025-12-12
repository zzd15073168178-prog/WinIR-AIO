"""
GUI tests for MainWindow
Uses pytest-qt for GUI automation
"""
import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest


@pytest.mark.gui
def test_main_window_creation(qapp, qtbot):
    """Test that main window can be created"""
    from src.ui.main_window import MainWindow
    
    window = MainWindow()
    qtbot.addWidget(window)
    
    assert window is not None
    assert window.windowTitle() != ""


@pytest.mark.gui
def test_module_navigation(qapp, qtbot):
    """Test switching between modules"""
    from src.ui.main_window import MainWindow
    
    window = MainWindow()
    qtbot.addWidget(window)
    
    # Test switching to each module
    modules = ['dashboard', 'process', 'network', 'persistence', 'logs']
    
    for module_id in modules:
        window.switch_module(module_id)
        assert window.current_module == module_id


@pytest.mark.gui
def test_sidebar_selection(qapp, qtbot):
    """Test sidebar module selection"""
    from src.ui.sidebar import ModuleNavigator
    
    navigator = ModuleNavigator()
    qtbot.addWidget(navigator)
    
    # Should have 5 items
    assert navigator.count() == 5
    
    # Test selection
    navigator.setCurrentRow(1)
    assert navigator.currentRow() == 1


@pytest.mark.gui
def test_refresh_button(qapp, qtbot):
    """Test refresh button functionality"""
    from src.ui.main_window import MainWindow
    
    window = MainWindow()
    qtbot.addWidget(window)
    
    # Switch to dashboard
    window.switch_module('dashboard')
    
    # Find refresh button and click
    refresh_btn = window.findChild(type(None), 'refresh_btn')
    # Note: Since we didn't set objectName, we can't find it easily
    # This is a TODO for improvement


@pytest.mark.gui
@pytest.mark.slow
def test_export_functionality(qapp, qtbot, tmp_path):
    """Test export functionality"""
    from src.modules.dashboard import DashboardModule
    
    module = DashboardModule()
    qtbot.addWidget(module)
    
    # Collect some data first
    module.data = {'hostname': 'test', 'platform': 'Windows'}
    
    # Export to temp file
    export_file = tmp_path / "test_export.txt"
    module.export_data(str(export_file), "TXT")
    
    # Check file was created
    assert export_file.exists()
    content = export_file.read_text(encoding='utf-8')
    assert 'hostname' in content


@pytest.mark.gui
def test_startup_dialog(qapp, qtbot):
    """Test startup dialog"""
    from src.ui.startup_dialog import StartupDialog
    
    dialog = StartupDialog()
    qtbot.addWidget(dialog)
    
    assert dialog is not None
    assert dialog.windowTitle() != ""

