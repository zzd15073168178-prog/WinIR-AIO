"""
Unit tests for CommandRunner
"""
import pytest
import time
from src.core.executor import CommandRunner, CommandResult, check_admin_privileges


class TestCommandRunner:
    """Test CommandRunner class"""
    
    @pytest.mark.unit
    def test_init(self, command_runner):
        """Test CommandRunner initialization"""
        assert command_runner is not None
        assert command_runner.timeout > 0
        assert command_runner.encoding in ['gbk', 'utf-8']
    
    @pytest.mark.unit
    def test_run_simple_command(self, command_runner):
        """Test running a simple command"""
        result = command_runner.run_command(['hostname'], shell=False)
        assert isinstance(result, CommandResult)
        assert result.success is True
        assert result.return_code == 0
        assert len(result.stdout) > 0
        assert result.execution_time > 0
    
    @pytest.mark.unit
    def test_run_command_with_shell(self, command_runner):
        """Test running command with shell"""
        result = command_runner.run_command('hostname', shell=True)
        assert result.success is True
        assert len(result.stdout) > 0
    
    @pytest.mark.unit
    def test_run_command_list_form(self, command_runner):
        """Test list-form command (safer)"""
        result = command_runner.run_command(['echo', 'test'], shell=False)
        assert result.success is True
    
    @pytest.mark.unit
    def test_run_command_timeout(self, command_runner):
        """Test command timeout"""
        # This command should timeout
        result = command_runner.run_command(
            ['ping', 'localhost', '-n', '100'], 
            timeout=1,
            shell=False
        )
        assert result.success is False
        assert 'timeout' in result.stderr.lower()
    
    @pytest.mark.unit
    def test_run_command_with_process_id(self, command_runner):
        """Test command with process tracking"""
        process_id = "test_process_123"
        result = command_runner.run_command(
            ['whoami'], 
            process_id=process_id,
            shell=False
        )
        assert result.success is True
        # Process should be removed from active_processes after completion
        assert process_id not in command_runner.active_processes
    
    @pytest.mark.unit
    def test_terminate_process(self, command_runner):
        """Test process termination"""
        import threading
        
        process_id = "test_cancel"
        result_holder = {'completed': False}
        
        def run_long_task():
            result = command_runner.run_command(
                ['ping', 'localhost', '-n', '50'],
                process_id=process_id,
                shell=False
            )
            result_holder['completed'] = True
        
        # Start long task in thread
        thread = threading.Thread(target=run_long_task, daemon=True)
        thread.start()
        
        # Wait a bit then cancel
        time.sleep(0.5)
        cancelled = command_runner.terminate_process(process_id)
        
        assert cancelled is True
        thread.join(timeout=2)
    
    @pytest.mark.unit
    def test_run_powershell(self, command_runner):
        """Test PowerShell execution"""
        script = "Write-Output 'Hello from PowerShell'"
        result = command_runner.run_powershell(script)
        assert result.success is True
        assert 'Hello' in result.stdout
    
    @pytest.mark.unit
    def test_encoding_detection(self, command_runner):
        """Test encoding detection"""
        encoding = command_runner._detect_encoding()
        assert encoding in ['gbk', 'utf-8', 'cp936', 'cp65001']
    
    @pytest.mark.unit
    def test_utf16_decode(self, command_runner):
        """Test UTF-16 decoding"""
        # UTF-16LE with BOM
        utf16_data = b'\xff\xfeH\x00e\x00l\x00l\x00o\x00'
        decoded = command_runner._decode_output(utf16_data)
        assert decoded == 'Hello'
    
    @pytest.mark.unit
    def test_check_admin_privileges(self):
        """Test admin check"""
        # This should not raise an exception
        result = check_admin_privileges()
        assert isinstance(result, bool)


class TestCommandResult:
    """Test CommandResult dataclass"""
    
    @pytest.mark.unit
    def test_to_dict(self):
        """Test conversion to dictionary"""
        result = CommandResult(
            success=True,
            stdout="test output",
            stderr="",
            return_code=0,
            execution_time=1.5,
            command="test command"
        )
        
        d = result.to_dict()
        assert d['success'] is True
        assert d['stdout'] == "test output"
        assert d['return_code'] == 0
        assert d['execution_time'] == 1.5

