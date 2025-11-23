"""
Timestamp Analyzer - 时间戳分析与反篡改检测
Detects timestamp manipulation and provides multiple timestamp sources
"""

import os
import win32api
import win32con
import win32file
import wmi
import struct
import datetime
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
import subprocess
import json

logger = logging.getLogger(__name__)

class TimestampAnalyzer:
    """
    分析文件时间戳，检测可能的时间戳篡改
    Multiple timestamp sources:
    1. Standard NTFS timestamps (easily forged)
    2. $MFT Entry Modified time (harder to forge)  
    3. USN Journal records
    4. Prefetch files
    5. Registry LastWriteTime
    """
    
    def __init__(self, command_callback: Optional[Callable] = None):
        self.wmi_conn = wmi.WMI()
        self.command_callback = command_callback  # Callback for logging commands
        self.is_admin = self._check_admin_privileges()
        
    def _check_admin_privileges(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
        
    def get_all_timestamps(self, file_path: str) -> Dict[str, Any]:
        """
        获取文件的所有时间戳信息
        Returns dict with multiple timestamp sources
        """
        result = {
            'file_path': file_path,
            'exists': os.path.exists(file_path),
            'standard': {},
            'mft': {},
            'prefetch': {},
            'usn': {},
            'anomalies': []
        }
        
        if not result['exists']:
            return result
            
        # 1. Standard NTFS timestamps (can be forged)
        result['standard'] = self._get_standard_timestamps(file_path)
        
        # 2. $MFT timestamps (harder to forge)
        result['mft'] = self._get_mft_timestamps(file_path)
        
        # 3. Prefetch information
        result['prefetch'] = self._get_prefetch_info(file_path)
        
        # 4. USN Journal (if available)
        result['usn'] = self._get_usn_info(file_path)
        
        # 5. Detect anomalies
        result['anomalies'] = self._detect_timestamp_anomalies(result)
        
        return result
        
    def _get_standard_timestamps(self, file_path: str) -> Dict[str, Any]:
        """获取标准文件时间戳（可被篡改）"""
        try:
            self._log_command(f"os.stat('{file_path}')", "获取标准 NTFS 时间戳")
            stat = os.stat(file_path)
            
            # Get Windows file times using win32api
            handle = win32api.CreateFile(
                file_path,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_ATTRIBUTE_NORMAL,
                None
            )
            
            creation_time, access_time, write_time = win32file.GetFileTime(handle)
            win32api.CloseHandle(handle)
            
            return {
                'created': self._filetime_to_datetime(creation_time),
                'modified': self._filetime_to_datetime(write_time),
                'accessed': self._filetime_to_datetime(access_time),
                'size': stat.st_size,
                'attributes': win32api.GetFileAttributes(file_path)
            }
        except Exception as e:
            logger.debug(f"Failed to get standard timestamps for {file_path}: {e}")
            return {}
            
    def _log_command(self, cmd: str, description: str = None, output: str = None, success: bool = True):
        """Log command execution if callback is set"""
        if self.command_callback:
            self.command_callback({
                'type': 'command',
                'command': cmd,
                'description': description,
                'output': output,
                'success': success
            })
    
    def _get_mft_timestamps(self, file_path: str) -> Dict[str, Any]:
        """
        获取 $MFT (Master File Table) 时间戳
        These are harder to forge and may reveal tampering
        """
        # MFT access typically requires admin privileges
        if not self.is_admin:
            logger.debug("MFT timestamp access requires administrator privileges")
            return {"status": "unavailable", "reason": "需要管理员权限"}
            
        try:
            # 使用 fsutil 获取 MFT 信息
            cmd = ['fsutil', 'usn', 'readdata', file_path]
            cmd_str = ' '.join(cmd)
            
            self._log_command(cmd_str, "获取 MFT 时间戳信息")
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                self._log_command(None, None, result.stdout[:500], True)  # Log first 500 chars
                mft_info = {}
                for line in result.stdout.split('\n'):
                    if 'File ID' in line:
                        mft_info['file_id'] = line.split(':')[1].strip()
                    elif 'Parent File ID' in line:
                        mft_info['parent_id'] = line.split(':')[1].strip()
                    elif 'Usn' in line and 'Usn :' in line:
                        mft_info['usn'] = line.split(':')[1].strip()
                    elif 'Time Stamp' in line:
                        mft_info['timestamp'] = line.split(':', 1)[1].strip()
                        
                # 使用 WMI 获取更详细的信息
                drive = Path(file_path).drive
                file_name = Path(file_path).name
                
                query = f"SELECT * FROM CIM_DataFile WHERE Name='{file_path.replace(chr(92), chr(92)*2)}'"
                self._log_command(f"WMI Query: {query}", "查询文件 WMI 信息")
                
                for file_obj in self.wmi_conn.query(query):
                    mft_info['install_date'] = file_obj.InstallDate
                    mft_info['last_modified'] = file_obj.LastModified
                    mft_info['last_accessed'] = file_obj.LastAccessed
                    mft_info['creation_date'] = file_obj.CreationDate
                    break
                    
                return mft_info
        except Exception as e:
            logger.debug(f"Failed to get MFT timestamps for {file_path}: {e}")
            return {}
            
    def _get_prefetch_info(self, file_path: str) -> Dict[str, Any]:
        """
        获取 Prefetch 文件信息
        Prefetch files track program execution
        """
        # Prefetch access may require admin privileges
        if not self.is_admin:
            logger.debug("Prefetch access may be limited without administrator privileges")
            
        try:
            prefetch_dir = Path(os.environ['SystemRoot']) / 'Prefetch'
            exe_name = Path(file_path).name.upper()
            
            prefetch_info = {
                'found': False,
                'files': [],
                'last_run': None,
                'run_count': 0
            }
            
            # Look for prefetch files
            for pf_file in prefetch_dir.glob(f"{exe_name}*.pf"):
                pf_stat = os.stat(pf_file)
                prefetch_info['found'] = True
                prefetch_info['files'].append({
                    'name': pf_file.name,
                    'modified': datetime.datetime.fromtimestamp(pf_stat.st_mtime),
                    'size': pf_stat.st_size
                })
                
                # Last modification time of prefetch = last run time
                if not prefetch_info['last_run'] or pf_stat.st_mtime > prefetch_info['last_run'].timestamp():
                    prefetch_info['last_run'] = datetime.datetime.fromtimestamp(pf_stat.st_mtime)
                    
            return prefetch_info
        except Exception as e:
            logger.debug(f"Failed to get prefetch info for {file_path}: {e}")
            return {}
            
    def _get_usn_info(self, file_path: str) -> Dict[str, Any]:
        """
        获取 USN Journal 信息
        USN Journal tracks all file system changes
        """
        try:
            drive = Path(file_path).drive
            
            # Query USN journal for this file
            cmd = ['fsutil', 'usn', 'readdata', file_path]
            cmd_str = ' '.join(cmd)
            
            self._log_command(cmd_str, "查询 USN Journal 信息")
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                self._log_command(None, None, result.stdout[:500], True)  # Log first 500 chars
            
            if result.returncode == 0:
                usn_info = {'entries': []}
                current_entry = {}
                
                for line in result.stdout.split('\n'):
                    if 'Major Version' in line:
                        if current_entry:
                            usn_info['entries'].append(current_entry)
                        current_entry = {}
                    elif ':' in line:
                        key = line.split(':')[0].strip()
                        value = line.split(':', 1)[1].strip()
                        current_entry[key] = value
                        
                if current_entry:
                    usn_info['entries'].append(current_entry)
                    
                return usn_info
        except Exception as e:
            logger.debug(f"Failed to get USN info for {file_path}: {e}")
            return {}
            
    def _detect_timestamp_anomalies(self, timestamps: Dict[str, Any]) -> List[str]:
        """
        检测时间戳异常
        Common indicators of timestamp manipulation
        """
        anomalies = []
        
        if not timestamps['standard']:
            return anomalies
            
        std_times = timestamps['standard']
        
        # 1. Creation time > Modification time (impossible normally)
        if 'created' in std_times and 'modified' in std_times:
            if std_times['created'] > std_times['modified']:
                anomalies.append("[WARNING] 创建时间晚于修改时间（可能被篡改）")
                
        # 2. All timestamps are identical (suspicious)
        if 'created' in std_times and 'modified' in std_times and 'accessed' in std_times:
            if std_times['created'] == std_times['modified'] == std_times['accessed']:
                anomalies.append("[WARNING] 所有时间戳相同（可疑）")
                
        # 3. Timestamps in the future
        now = datetime.datetime.now()
        for time_type in ['created', 'modified', 'accessed']:
            if time_type in std_times and isinstance(std_times[time_type], datetime.datetime):
                if std_times[time_type] > now:
                    anomalies.append(f"[WARNING] {time_type}时间在未来")
                    
        # 4. Very old but recently accessed (suspicious for malware)
        if 'created' in std_times and 'accessed' in std_times:
            created = std_times['created']
            accessed = std_times['accessed']
            if isinstance(created, datetime.datetime) and isinstance(accessed, datetime.datetime):
                age_days = (now - created).days
                last_access_days = (now - accessed).days
                
                if age_days > 365 * 5 and last_access_days < 7:  # 5+ years old but accessed recently
                    anomalies.append("[WARNING] 文件很旧但最近被访问（可疑）")
                    
        # 5. Prefetch mismatch
        if timestamps['prefetch'] and timestamps['prefetch']['found']:
            last_run = timestamps['prefetch']['last_run']
            if last_run and 'modified' in std_times:
                modified = std_times['modified']
                if isinstance(modified, datetime.datetime) and isinstance(last_run, datetime.datetime):
                    if last_run < modified:
                        anomalies.append("[WARNING] Prefetch显示运行时间早于文件修改时间")
                        
        # 6. MFT vs Standard timestamp mismatch
        if timestamps['mft']:
            # Compare MFT and standard timestamps
            mft = timestamps['mft']
            if 'creation_date' in mft and 'created' in std_times:
                try:
                    mft_created = self._parse_wmi_datetime(mft['creation_date'])
                    std_created = std_times['created']
                    if abs((mft_created - std_created).total_seconds()) > 60:  # More than 1 minute difference
                        anomalies.append("[WARNING] MFT与标准创建时间不匹配（可能被篡改）")
                except:
                    pass
                    
        return anomalies
        
    def _filetime_to_datetime(self, filetime) -> datetime.datetime:
        """Convert Windows FILETIME or pywintypes.Time to datetime"""
        try:
            # Check if it's a pywintypes.Time object
            if hasattr(filetime, 'timestamp'):
                # It's likely a pywintypes.Time object
                return datetime.datetime.fromtimestamp(filetime.timestamp())
            elif hasattr(filetime, '__int__'):
                # Try to get integer representation
                filetime_int = int(filetime)
                # Windows FILETIME is 100-nanosecond intervals since 1601-01-01
                EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as FILETIME
                return datetime.datetime.utcfromtimestamp((filetime_int - EPOCH_AS_FILETIME) / 10000000.0)
            else:
                # Fallback: try to convert to string and parse
                return datetime.datetime.fromisoformat(str(filetime))
        except Exception as e:
            logger.debug(f"Failed to convert filetime {filetime}: {e}")
            # Return current time as fallback
            return datetime.datetime.now()
        
    def _parse_wmi_datetime(self, wmi_datetime: str) -> datetime.datetime:
        """Parse WMI datetime string (yyyymmddHHMMSS.mmmmmmsUUU)"""
        if not wmi_datetime:
            return None
        # Format: 20231123093045.123456+480
        dt_str = wmi_datetime.split('.')[0]
        return datetime.datetime.strptime(dt_str, '%Y%m%d%H%M%S')
        
    def check_file_timestamps(self, file_path: str) -> Tuple[bool, List[str]]:
        """
        Quick check for timestamp anomalies
        Returns: (is_suspicious, list_of_reasons)
        """
        timestamps = self.get_all_timestamps(file_path)
        is_suspicious = len(timestamps['anomalies']) > 0
        return is_suspicious, timestamps['anomalies']
        
    def get_summary(self, file_path: str) -> str:
        """Get a summary of timestamp analysis"""
        timestamps = self.get_all_timestamps(file_path)
        
        summary = []
        
        if timestamps['standard']:
            std = timestamps['standard']
            summary.append(f"[标准时间戳]")
            if 'created' in std:
                summary.append(f"  创建: {std['created']}")
            if 'modified' in std:
                summary.append(f"  修改: {std['modified']}")
            if 'accessed' in std:
                summary.append(f"  访问: {std['accessed']}")
                
        if timestamps['prefetch'] and timestamps['prefetch']['found']:
            pf = timestamps['prefetch']
            summary.append(f"[Prefetch]")
            summary.append(f"  最后运行: {pf['last_run']}")
            summary.append(f"  Prefetch文件: {len(pf['files'])}个")
            
        if timestamps['anomalies']:
            summary.append(f"[发现异常]")
            for anomaly in timestamps['anomalies']:
                summary.append(f"  {anomaly}")
        else:
            summary.append("[OK] 未发现时间戳异常")
            
        return '\n'.join(summary)
