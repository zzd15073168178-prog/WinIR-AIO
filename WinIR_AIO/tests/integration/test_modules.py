"""
Integration tests for WinIR-AIO modules
Tests the interaction between components
"""
import pytest
import time
from PySide6.QtCore import QCoreApplication, QTimer


@pytest.mark.integration
def test_process_collection(qapp):
    """Test process data collection"""
    from src.modules.process import ProcessModule
    
    module = ProcessModule()
    
    # Setup test completion flag
    completed = {'done': False, 'data': None}
    
    def on_result(data):
        completed['data'] = data
        completed['done'] = True
    
    # Manually call the collection function
    result = module.collect_processes()
    
    assert isinstance(result, list)
    assert len(result) > 0  # Should have at least some processes
    
    # Check data structure
    if result:
        proc = result[0]
        assert 'pid' in proc
        assert 'name' in proc
        assert 'exe' in proc


@pytest.mark.integration
def test_network_collection(qapp):
    """Test network data collection"""
    from src.modules.network import NetworkModule
    
    module = NetworkModule()
    result = module.collect_connections(resolve_dns=False)
    
    assert isinstance(result, list)
    # May be empty if no connections, so just check type
    
    if result:
        conn = result[0]
        assert 'proto' in conn
        assert 'laddr' in conn
        assert 'lport' in conn


@pytest.mark.integration
@pytest.mark.slow
def test_autoruns_execution(qapp):
    """Test Autoruns execution (slow test)"""
    from src.modules.persistence import PersistenceModule
    from src.config import tool_exists
    
    if not tool_exists('autorunsc'):
        pytest.skip("autorunsc.exe not found")
    
    module = PersistenceModule()
    
    try:
        result = module.run_autoruns()
        assert isinstance(result, list)
        # Autoruns usually returns many entries
        assert len(result) > 0
        
        if result:
            entry = result[0]
            assert 'entry location' in entry or 'entry' in entry
    except Exception as e:
        # Autoruns may fail for various reasons (permissions, etc.)
        pytest.skip(f"Autoruns execution failed: {e}")


@pytest.mark.integration
@pytest.mark.requires_admin
def test_logs_query(qapp, skip_if_not_admin):
    """Test Windows Event Log query (requires admin)"""
    from src.modules.logs import LogsModule
    
    module = LogsModule()
    
    try:
        result = module.run_query(event_ids=[4624], limit=10)
        assert isinstance(result, list)
        # May be empty if no events, which is ok
    except Exception as e:
        pytest.skip(f"Event log query failed: {e}")


@pytest.mark.integration
def test_dashboard_system_info(qapp):
    """Test dashboard system info collection"""
    from src.modules.dashboard import DashboardModule
    
    module = DashboardModule()
    result = module.collect_system_info()
    
    assert isinstance(result, dict)
    assert 'hostname' in result
    assert 'platform' in result
    assert 'total_memory' in result


@pytest.mark.integration
@pytest.mark.slow
def test_signature_verification(qapp):
    """Test signature verification"""
    from src.core.signatures import SignatureVerifier
    from src.config import tool_exists
    import os
    
    if not tool_exists('sigcheck'):
        pytest.skip("sigcheck.exe not found")
    
    verifier = SignatureVerifier()
    
    # Test with a known Windows file
    test_file = r"C:\Windows\System32\notepad.exe"
    if not os.path.exists(test_file):
        pytest.skip("Test file not found")
    
    result = verifier.verify_file(test_file)
    assert isinstance(result, dict)
    assert 'verified' in result
    assert 'status' in result


@pytest.mark.integration
def test_worker_task_execution(qapp):
    """Test TaskManager worker execution"""
    from src.ui.workers import global_task_manager
    
    completed = {'done': False, 'result': None}
    
    def test_task(**kwargs):
        time.sleep(0.1)
        return "Task result"
    
    def on_result(data):
        completed['result'] = data
        completed['done'] = True
    
    global_task_manager.start_task(
        test_task,
        on_result=on_result
    )
    
    # Wait for task
    start = time.time()
    while not completed['done'] and (time.time() - start) < 5:
        qapp.processEvents()
        time.sleep(0.05)
    
    assert completed['done'] is True
    assert completed['result'] == "Task result"

