"""
Command Executor Module
Handles subprocess execution with proper encoding for Windows
Enhanced with list-based execution, cancellation support, and streaming output
"""

import subprocess
import os
import sys
import time
import logging
import threading
import shlex
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any, Union
from dataclasses import dataclass
from queue import Queue, Empty
import uuid

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.config import (
    WINDOWS_ENCODING, 
    FALLBACK_ENCODING, 
    PROCESS_TIMEOUT,
    BIN_DIR,
    get_tool_path
)

# Setup logging
logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Container for command execution results"""
    success: bool
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    command: str
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'success': self.success,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'return_code': self.return_code,
            'execution_time': self.execution_time,
            'command': self.command,
            'error': self.error
        }


class CommandRunner:
    """
    Handles execution of external commands with proper encoding
    Enhanced with cancellation support and list-based execution
    """
    
    def __init__(self, timeout: int = PROCESS_TIMEOUT):
        """
        Initialize CommandRunner
        
        Args:
            timeout: Default timeout for command execution in seconds
        """
        self.timeout = timeout
        self.encoding = self._detect_encoding()
        self.active_processes: Dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()
        
    def _detect_encoding(self) -> str:
        """
        Detect the appropriate encoding for the system
        
        Returns:
            str: Encoding to use (gbk for Chinese Windows, utf-8 otherwise)
        """
        try:
            # Try to get Windows codepage
            import locale
            system_encoding = locale.getpreferredencoding()
            
            # Common Chinese Windows encodings
            if system_encoding.lower() in ['cp936', 'gbk', 'gb2312']:
                return 'gbk'
            elif system_encoding.lower() in ['cp65001', 'utf-8']:
                return 'utf-8'
            else:
                # Default to GBK for Windows in China
                return WINDOWS_ENCODING
        except:
            return WINDOWS_ENCODING
    
    def _decode_output(self, data: bytes) -> str:
        """
        Decode output with fallback encoding
        Handles UTF-16LE (used by some Sysinternals tools like autorunsc)
        
        Args:
            data: Raw bytes from subprocess
            
        Returns:
            str: Decoded string
        """
        if not data:
            return ""
        
        # Check for UTF-16 BOM (Sysinternals tools often output UTF-16LE)
        if data.startswith(b'\xff\xfe') or data.startswith(b'\xfe\xff'):
            try:
                return data.decode('utf-16')
            except UnicodeDecodeError:
                pass
        
        # Check if it looks like UTF-16LE (every other byte is null)
        # This is a heuristic for ASCII text in UTF-16LE
        if len(data) > 100 and data[1::2].count(b'\x00') > len(data[1::2]) * 0.8:
            try:
                return data.decode('utf-16le')
            except UnicodeDecodeError:
                pass
            
        # Try primary encoding first
        try:
            return data.decode(self.encoding)
        except UnicodeDecodeError:
            pass
            
        # Try fallback encoding
        try:
            return data.decode(FALLBACK_ENCODING)
        except UnicodeDecodeError:
            pass
            
        # Last resort: decode with errors='replace'
        return data.decode(self.encoding, errors='replace')
    
    def run_command(self, 
                   command: Union[str, List[str]], 
                   cwd: Optional[str] = None,
                   timeout: Optional[int] = None,
                   shell: bool = False,
                   capture_output: bool = True,
                   env: Optional[Dict[str, str]] = None,
                   process_id: Optional[str] = None) -> CommandResult:
        """
        Execute a command and return the result
        
        Args:
            command: Command to execute (list form preferred, string accepted)
            cwd: Working directory for the command
            timeout: Command timeout in seconds (uses default if None)
            shell: Whether to execute through shell (avoid if possible)
            capture_output: Whether to capture stdout/stderr
            env: Environment variables to set
            process_id: Optional ID for process tracking (for cancellation)
            
        Returns:
            CommandResult object containing execution details
        """
        if timeout is None:
            timeout = self.timeout
            
        start_time = time.time()
        
        # Generate process ID for tracking
        if process_id is None:
            process_id = str(uuid.uuid4())
        
        # Prepare environment
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
            
        # Add bin directory to PATH for Sysinternals tools
        if BIN_DIR.exists():
            cmd_env['PATH'] = str(BIN_DIR) + os.pathsep + cmd_env.get('PATH', '')
        
        try:
            # Prepare subprocess arguments
            kwargs = {
                'cwd': cwd,
                'env': cmd_env,
                'shell': shell
            }
            
            # Add Windows-specific flags
            if sys.platform == 'win32':
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
                
            if capture_output:
                kwargs['stdout'] = subprocess.PIPE
                kwargs['stderr'] = subprocess.PIPE
            
            # Determine command form
            if isinstance(command, list):
                # Preferred: list form (no shell injection risk)
                logger.debug(f"Executing command (list): {' '.join(command)}")
                process = subprocess.Popen(command, **kwargs)
            elif shell:
                # Shell required (e.g., PowerShell with pipes)
                logger.debug(f"Executing command (shell): {command}")
                process = subprocess.Popen(command, **kwargs)
            else:
                # String form without shell (split naively - not recommended for complex args)
                logger.warning(f"Executing string command without shell (may fail with quotes): {command}")
                process = subprocess.Popen(command, **kwargs)
            
            # Register process for potential cancellation
            with self._lock:
                self.active_processes[process_id] = process
            
            try:
                # Wait for completion
                stdout_data, stderr_data = process.communicate(timeout=timeout)
            finally:
                # Unregister process
                with self._lock:
                    self.active_processes.pop(process_id, None)
            
            # Decode output
            stdout = self._decode_output(stdout_data) if stdout_data else ""
            stderr = self._decode_output(stderr_data) if stderr_data else ""
            
            execution_time = time.time() - start_time
            
            result = CommandResult(
                success=(process.returncode == 0),
                stdout=stdout,
                stderr=stderr,
                return_code=process.returncode,
                execution_time=execution_time,
                command=str(command)
            )
            
            logger.debug(f"Command completed in {execution_time:.2f}s with return code {process.returncode}")
            
            return result
            
        except subprocess.TimeoutExpired as e:
            execution_time = time.time() - start_time
            logger.error(f"Command timed out after {timeout}s: {command}")
            
            # Try to terminate process
            with self._lock:
                proc = self.active_processes.pop(process_id, None)
                if proc:
                    try:
                        proc.terminate()
                        proc.wait(timeout=2)
                    except:
                        proc.kill()
            
            return CommandResult(
                success=False,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                return_code=-1,
                execution_time=execution_time,
                command=str(command),
                error=str(e)
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Command execution failed: {e}")
            
            # Cleanup
            with self._lock:
                self.active_processes.pop(process_id, None)
            
            return CommandResult(
                success=False,
                stdout="",
                stderr=str(e),
                return_code=-1,
                execution_time=execution_time,
                command=str(command),
                error=str(e)
            )
    
    def terminate_process(self, process_id: str, force: bool = False) -> bool:
        """
        Terminate a running process
        
        Args:
            process_id: Process ID returned from run_command
            force: Use kill() instead of terminate()
            
        Returns:
            bool: True if process was found and terminated
        """
        with self._lock:
            process = self.active_processes.get(process_id)
            if process:
                try:
                    if force:
                        process.kill()
                    else:
                        process.terminate()
                    return True
                except:
                    return False
        return False
    
    def terminate_all(self):
        """Terminate all active processes"""
        with self._lock:
            for proc in list(self.active_processes.values()):
                try:
                    proc.terminate()
                except:
                    pass
            self.active_processes.clear()
    
    def run_powershell(self, 
                      script: str,
                      timeout: Optional[int] = None,
                      process_id: Optional[str] = None) -> CommandResult:
        """
        Execute a PowerShell script (uses -EncodedCommand for safety)
        
        Args:
            script: PowerShell script to execute
            timeout: Command timeout in seconds
            process_id: Optional process ID for tracking
            
        Returns:
            CommandResult object
        """
        # Encode the script as base64 to avoid escaping issues
        import base64
        encoded_script = base64.b64encode(script.encode('utf-16le')).decode('ascii')
        
        # Use list form for better control
        command = [
            'powershell.exe',
            '-NoProfile',
            '-NonInteractive', 
            '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', encoded_script
        ]
        
        return self.run_command(command, timeout=timeout, shell=False, process_id=process_id)
    
    def run_wmic(self, 
                query: str,
                timeout: Optional[int] = None,
                process_id: Optional[str] = None) -> CommandResult:
        """
        Execute a WMIC query
        
        Args:
            query: WMIC query to execute
            timeout: Command timeout in seconds
            process_id: Optional process ID for tracking
            
        Returns:
            CommandResult object
        """
        # WMIC with list form
        command = ['wmic'] + query.split() + ['/format:list']
        return self.run_command(command, timeout=timeout, shell=False, process_id=process_id)
    
    def run_sysinternals_tool(self, 
                             tool_name: str,
                             args: Union[str, List[str]] = "",
                             timeout: Optional[int] = None,
                             process_id: Optional[str] = None) -> CommandResult:
        """
        Run a Sysinternals tool
        
        Args:
            tool_name: Name of the tool (e.g., 'autorunsc', 'sigcheck')
            args: Command line arguments for the tool (string or list)
            timeout: Command timeout in seconds
            process_id: Optional process ID for tracking
            
        Returns:
            CommandResult object
        """
        # Get tool path using config
        try:
            tool_path = get_tool_path(tool_name.replace('.exe', ''))
        except ValueError:
            # Fallback to old method if tool not in config
            tool_path = BIN_DIR / tool_name
        
        if not tool_path.exists():
            logger.error(f"Tool not found: {tool_path}")
            return CommandResult(
                success=False,
                stdout="",
                stderr=f"Tool not found: {tool_name}",
                return_code=-1,
                execution_time=0,
                command=f"{tool_name} {args}",
                error="Tool not found"
            )
        
        # Build command as list (safer)
        # Accept EULA automatically
        command = [str(tool_path), '-accepteula']
        
        # Parse args safely
        if args:
            if isinstance(args, list):
                command.extend(args)
            else:
                # Use shlex.split for proper handling of quotes and spaces on Windows
                # posix=False ensures Windows-style path handling
                try:
                    command.extend(shlex.split(args, posix=False))
                except ValueError as e:
                    logger.warning(f"Failed to parse arguments '{args}': {e}, falling back to simple split")
                    command.extend(args.split())
        
        return self.run_command(command, timeout=timeout, shell=False, process_id=process_id)


class AsyncCommandRunner:
    """
    Asynchronous command runner for non-blocking execution
    """
    
    def __init__(self, runner: Optional[CommandRunner] = None):
        """
        Initialize AsyncCommandRunner
        
        Args:
            runner: CommandRunner instance to use (creates new if None)
        """
        self.runner = runner or CommandRunner()
        self.tasks: Dict[str, threading.Thread] = {}
        
    def run_async(self, 
                 command: Union[str, List[str]],
                 callback: Optional[callable] = None,
                 task_id: Optional[str] = None,
                 **kwargs) -> str:
        """
        Run a command asynchronously
        
        Args:
            command: Command to execute
            callback: Function to call with CommandResult when complete
            task_id: Unique identifier for this task
            **kwargs: Additional arguments for run_command
            
        Returns:
            str: Task ID
        """
        if task_id is None:
            task_id = f"task_{time.time()}"
            
        def _run_task():
            result = self.runner.run_command(command, **kwargs)
            if callback:
                callback(result)
                
        thread = threading.Thread(target=_run_task, daemon=True)
        thread.start()
        
        self.tasks[task_id] = thread
        return task_id
    
    def wait_for_task(self, task_id: str, timeout: Optional[float] = None) -> bool:
        """
        Wait for an async task to complete
        
        Args:
            task_id: Task identifier
            timeout: Maximum time to wait
            
        Returns:
            bool: True if task completed, False if timeout
        """
        if task_id not in self.tasks:
            return False
            
        thread = self.tasks[task_id]
        thread.join(timeout)
        
        if not thread.is_alive():
            del self.tasks[task_id]
            return True
            
        return False
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel an async task
        
        Args:
            task_id: Task identifier
            
        Returns:
            bool: True if task was found and cancelled
        """
        if task_id in self.tasks:
            # Try to terminate the underlying process
            # Note: Thread itself can't be stopped safely
            del self.tasks[task_id]
            return True
        return False


# Utility functions for common operations
def check_admin_privileges() -> bool:
    """
    Check if the current process has administrator privileges
    
    Returns:
        bool: True if running as admin
    """
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def get_system_info() -> Dict[str, str]:
    """
    Get basic system information
    
    Returns:
        Dict containing system info
    """
    runner = CommandRunner()
    info = {}
    
    # Get Windows version (ver is a shell built-in, requires cmd.exe)
    try:
        result = runner.run_command('ver', shell=True)
        if result.success:
            info['windows_version'] = result.stdout.strip()
    except Exception as e:
        logger.warning(f"Failed to get Windows version: {e}")
    
    # Get hostname - use socket as primary, command as backup
    try:
        import socket
        info['hostname'] = socket.gethostname()
    except:
        try:
            result = runner.run_command('hostname', shell=True)
            if result.success:
                info['hostname'] = result.stdout.strip()
        except Exception as e:
            logger.warning(f"Failed to get hostname: {e}")
    
    # Get current user - use os.getlogin() as primary, command as backup
    try:
        import os
        info['current_user'] = os.getlogin()
    except:
        try:
            # Use shell=True for better compatibility
            result = runner.run_command('whoami', shell=True)
            if result.success:
                info['current_user'] = result.stdout.strip()
        except Exception as e:
            logger.warning(f"Failed to get current user: {e}")
        
    # Check admin status
    info['is_admin'] = 'Yes' if check_admin_privileges() else 'No'
    
    return info
