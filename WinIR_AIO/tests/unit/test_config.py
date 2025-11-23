"""
Unit tests for Configuration module
"""
import pytest
from pathlib import Path
from src.config import (
    APP_NAME, APP_VERSION, BIN_DIR, LOGS_DIR,
    get_tool_path, tool_exists, is_admin,
    SYSINTERNALS_TOOLS
)


class TestConfig:
    """Test configuration module"""
    
    @pytest.mark.unit
    def test_constants(self):
        """Test that constants are defined"""
        assert APP_NAME == "WinIR-AIO"
        assert APP_VERSION == "2.0.0"
        assert isinstance(BIN_DIR, Path)
        assert isinstance(LOGS_DIR, Path)
    
    @pytest.mark.unit
    def test_directories_exist(self):
        """Test that critical directories are created"""
        assert BIN_DIR.exists()
        assert LOGS_DIR.exists()
    
    @pytest.mark.unit
    def test_sysinternals_tools_config(self):
        """Test Sysinternals tools configuration"""
        assert 'autorunsc' in SYSINTERNALS_TOOLS
        assert 'sigcheck' in SYSINTERNALS_TOOLS
        
        # Check required fields
        for tool_name, tool_info in SYSINTERNALS_TOOLS.items():
            assert 'filename' in tool_info
            assert 'url' in tool_info
            assert 'required' in tool_info
    
    @pytest.mark.unit
    def test_get_tool_path(self):
        """Test get_tool_path function"""
        path = get_tool_path('autorunsc')
        assert isinstance(path, Path)
        assert path.name == 'autorunsc.exe'
        assert path.parent == BIN_DIR
    
    @pytest.mark.unit
    def test_get_tool_path_invalid(self):
        """Test get_tool_path with invalid tool"""
        with pytest.raises(ValueError):
            get_tool_path('nonexistent_tool')
    
    @pytest.mark.unit
    def test_tool_exists(self):
        """Test tool_exists function"""
        # This will return True/False depending on whether tools are downloaded
        result = tool_exists('autorunsc')
        assert isinstance(result, bool)
    
    @pytest.mark.unit
    def test_is_admin(self):
        """Test admin check"""
        result = is_admin()
        assert isinstance(result, bool)

