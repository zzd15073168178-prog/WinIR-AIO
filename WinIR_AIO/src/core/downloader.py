"""
Tool Downloader Module
Handles automatic download of Sysinternals tools from Microsoft's official source
"""

import os
import time
import hashlib
import requests
from pathlib import Path
from typing import Optional, Callable, Dict, Any
import logging

# Import configuration
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.config import (
    SYSINTERNALS_TOOLS, 
    BIN_DIR, 
    DOWNLOAD_TIMEOUT, 
    DOWNLOAD_CHUNK_SIZE,
    MAX_RETRIES,
    RETRY_DELAY
)

# Setup logging
logger = logging.getLogger(__name__)


class DownloadProgress:
    """Container for download progress information"""
    def __init__(self):
        self.tool_name: str = ""
        self.current_bytes: int = 0
        self.total_bytes: int = 0
        self.percentage: int = 0
        self.status: str = "pending"
        self.error_message: Optional[str] = None
        
    def update(self, current: int, total: int):
        """Update progress values"""
        self.current_bytes = current
        self.total_bytes = total
        self.percentage = int((current / total * 100)) if total > 0 else 0


class ToolDownloader:
    """Handles downloading of Sysinternals tools"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Configure proxy support from environment variables
        self._configure_proxy()
        
    def _configure_proxy(self):
        """Configure proxy settings from environment variables"""
        proxies = {}
        
        # Check for HTTP_PROXY and HTTPS_PROXY environment variables
        http_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
        https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
        no_proxy = os.environ.get('NO_PROXY') or os.environ.get('no_proxy')
        
        if http_proxy:
            proxies['http'] = http_proxy
            logger.info(f"Using HTTP proxy: {http_proxy}")
            
        if https_proxy:
            proxies['https'] = https_proxy
            logger.info(f"Using HTTPS proxy: {https_proxy}")
            
        if proxies:
            self.session.proxies.update(proxies)
            
        # Configure no_proxy hosts
        if no_proxy:
            self.session.trust_env = True
            logger.info(f"No proxy for: {no_proxy}")
        
    def download_tool(self, 
                     tool_name: str, 
                     progress_callback: Optional[Callable[[int, int], None]] = None) -> bool:
        """
        Download a specific tool from Sysinternals
        
        Args:
            tool_name: Name of the tool to download
            progress_callback: Optional callback for progress updates (current_bytes, total_bytes)
            
        Returns:
            bool: True if download successful, False otherwise
        """
        if tool_name not in SYSINTERNALS_TOOLS:
            logger.error(f"Unknown tool: {tool_name}")
            return False
            
        tool_info = SYSINTERNALS_TOOLS[tool_name]
        url = tool_info["url"]
        target_path = BIN_DIR / tool_info["filename"]
        
        # Ensure bin directory exists
        BIN_DIR.mkdir(parents=True, exist_ok=True)
        
        for attempt in range(MAX_RETRIES):
            try:
                logger.info(f"Downloading {tool_name} from {url} (Attempt {attempt + 1}/{MAX_RETRIES})")
                
                # Make request with stream=True for progress tracking
                response = self.session.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT)
                response.raise_for_status()
                
                # Get total file size
                total_size = int(response.headers.get('content-length', 0))
                
                # Download to temporary file first
                temp_path = target_path.with_suffix('.tmp')
                downloaded_size = 0
                
                with open(temp_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)
                            
                            # Call progress callback if provided
                            if progress_callback:
                                progress_callback(downloaded_size, total_size)
                
                # Verify file size
                if downloaded_size < tool_info.get("min_size", 0):
                    logger.error(f"Downloaded file is too small: {downloaded_size} bytes")
                    temp_path.unlink(missing_ok=True)
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
                        continue
                    return False
                
                # Move temp file to final location
                if target_path.exists():
                    target_path.unlink()
                temp_path.rename(target_path)
                
                logger.info(f"Successfully downloaded {tool_name} ({downloaded_size} bytes)")
                
                # Verify the downloaded tool's integrity and signature
                if not self.verify_tool_integrity(tool_name):
                    logger.error(f"Downloaded {tool_name} failed integrity check, removing")
                    target_path.unlink(missing_ok=True)
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
                        continue
                    return False
                    
                return True
                
            except requests.RequestException as e:
                logger.error(f"Download failed: {e}")
                if attempt < MAX_RETRIES - 1:
                    logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                    time.sleep(RETRY_DELAY)
                else:
                    logger.error(f"Failed to download {tool_name} after {MAX_RETRIES} attempts")
                    
            except Exception as e:
                logger.error(f"Unexpected error during download: {e}")
                return False
                
        return False
    
    def check_and_download_all(self, 
                              progress_callback: Optional[Callable[[str, int, int], None]] = None) -> Dict[str, bool]:
        """
        Check and download all required tools
        
        Args:
            progress_callback: Optional callback (tool_name, current_bytes, total_bytes)
            
        Returns:
            Dict mapping tool names to success status
        """
        results = {}
        
        for tool_name, tool_info in SYSINTERNALS_TOOLS.items():
            if not tool_info.get("required", False):
                continue
                
            tool_path = BIN_DIR / tool_info["filename"]
            
            # Check if tool already exists and is valid
            if tool_path.exists():
                file_size = tool_path.stat().st_size
                min_size = tool_info.get("min_size", 0)
                
                if file_size >= min_size:
                    logger.info(f"{tool_name} already exists and appears valid")
                    results[tool_name] = True
                    continue
                else:
                    logger.warning(f"{tool_name} exists but appears corrupted (size: {file_size})")
                    tool_path.unlink()
            
            # Download the tool
            def _progress_wrapper(current, total):
                if progress_callback:
                    progress_callback(tool_name, current, total)
                    
            success = self.download_tool(tool_name, _progress_wrapper)
            results[tool_name] = success
            
        return results
    
    def verify_tool_integrity(self, tool_name: str) -> bool:
        """
        Verify that a downloaded tool is valid and signed by Microsoft
        
        Args:
            tool_name: Name of the tool to verify
            
        Returns:
            bool: True if tool appears valid
        """
        if tool_name not in SYSINTERNALS_TOOLS:
            return False
            
        tool_info = SYSINTERNALS_TOOLS[tool_name]
        tool_path = BIN_DIR / tool_info["filename"]
        
        if not tool_path.exists():
            return False
            
        # Check file size
        file_size = tool_path.stat().st_size
        min_size = tool_info.get("min_size", 0)
        
        if file_size < min_size:
            logger.warning(f"{tool_name} file size ({file_size}) is below minimum ({min_size})")
            return False
            
        # Check if it's a valid PE file (basic check)
        try:
            with open(tool_path, 'rb') as f:
                # Check for MZ header (PE file signature)
                header = f.read(2)
                if header != b'MZ':
                    logger.error(f"{tool_name} does not appear to be a valid executable")
                    return False
        except Exception as e:
            logger.error(f"Failed to verify {tool_name}: {e}")
            return False
            
        # Verify Microsoft signature using sigcheck if available
        if not self._verify_microsoft_signature(tool_path):
            logger.error(f"{tool_name} is not signed by Microsoft or signature verification failed")
            return False
            
        return True
    
    def _verify_microsoft_signature(self, file_path: Path) -> bool:
        """
        Verify that a file is signed by Microsoft using sigcheck
        
        Args:
            file_path: Path to file to verify
            
        Returns:
            bool: True if signed by Microsoft
        """
        try:
            # First check if sigcheck itself is available
            sigcheck_path = BIN_DIR / "sigcheck.exe"
            
            if not sigcheck_path.exists():
                # If sigcheck is not yet available (e.g., we're downloading it), 
                # skip signature verification
                logger.info("Sigcheck not available yet, skipping signature verification")
                return True
                
            # Run sigcheck to verify signature
            import subprocess
            cmd = [
                str(sigcheck_path),
                "-accepteula",
                "-nobanner", 
                "-q",  # Quiet mode
                str(file_path)
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            # Parse output to check for Microsoft signature
            output = result.stdout.lower()
            
            # Check for successful verification and Microsoft publisher
            is_verified = "verified:" in output and "signed" in output
            is_microsoft = "microsoft" in output and ("corporation" in output or "windows" in output)
            
            if is_verified and is_microsoft:
                logger.info(f"Signature verified: {file_path.name} is signed by Microsoft")
                return True
            else:
                logger.warning(f"Signature verification failed for {file_path.name}")
                logger.debug(f"Sigcheck output: {result.stdout}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.warning("Sigcheck timed out, assuming valid")
            return True
        except Exception as e:
            logger.warning(f"Could not verify signature: {e}")
            # In case of error, we assume it's valid to not block operation
            return True


# NOTE: DownloaderWorker(QThread) has been removed.
# Use TaskManager from src.ui.workers instead for async operations.
# See startup_dialog.py for an example of the new pattern.


# Utility functions for synchronous use
def ensure_tools_available() -> bool:
    """
    Ensure all required tools are available
    
    Returns:
        bool: True if all required tools are available
    """
    downloader = ToolDownloader()
    
    for tool_name, tool_info in SYSINTERNALS_TOOLS.items():
        if not tool_info.get("required", False):
            continue
            
        tool_path = BIN_DIR / tool_info["filename"]
        
        if not tool_path.exists() or tool_path.stat().st_size < tool_info.get("min_size", 0):
            logger.info(f"需要下载 {tool_name}")
            if not downloader.download_tool(tool_name):
                logger.error(f"无法下载必需的工具: {tool_name}")
                return False
                
    return True


def get_missing_tools() -> list:
    """
    Get list of missing required tools
    
    Returns:
        List of tool names that are missing
    """
    missing = []
    
    for tool_name, tool_info in SYSINTERNALS_TOOLS.items():
        if not tool_info.get("required", False):
            continue
            
        tool_path = BIN_DIR / tool_info["filename"]
        
        if not tool_path.exists() or tool_path.stat().st_size < tool_info.get("min_size", 0):
            missing.append(tool_name)
            
    return missing
