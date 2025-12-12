"""
Pytest configuration and shared fixtures
"""
import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from PySide6.QtWidgets import QApplication
from src.core.executor import CommandRunner
from src.core.signatures import SignatureVerifier
from src.core.parsers import CSVParser, AutorunsParser


@pytest.fixture(scope='session')
def qapp():
    """Create QApplication instance for GUI tests"""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    

@pytest.fixture
def command_runner():
    """Create CommandRunner instance"""
    return CommandRunner()


@pytest.fixture
def signature_verifier():
    """Create SignatureVerifier instance"""
    return SignatureVerifier()


@pytest.fixture
def csv_parser():
    """Create CSVParser instance"""
    return CSVParser()


@pytest.fixture
def sample_csv_data():
    """Sample CSV data for testing"""
    return """Header1,Header2,Header3
Value1,Value2,Value3
Value4,Value5,Value6"""


@pytest.fixture
def sample_autoruns_data():
    """Sample Autoruns CSV data"""
    return """Time,Entry Location,Entry,Enabled,Category,Profile,Description,Company,Image Path,Version,Launch String
2025-11-23 10:00,HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,TestApp,enabled,Logon,All Users,Test Application,Test Corp,C:\\Program Files\\TestApp\\test.exe,1.0.0,"""


@pytest.fixture
def skip_if_not_admin():
    """Skip test if not running as administrator"""
    from src.config import is_admin
    if not is_admin():
        pytest.skip("Test requires administrator privileges")

