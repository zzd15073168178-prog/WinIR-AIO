#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异常处理模块
定义项目统一的异常类和错误处理机制
"""

from typing import Optional, Dict, Any


class SysmonError(Exception):
    """项目基础异常类
    
    所有自定义异常的基类，提供统一的错误信息格式。
    
    Attributes:
        message: 错误消息
        error_code: 错误代码（可选）
        details: 错误详情（可选）
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)
    
    def __str__(self) -> str:
        """返回格式化的错误信息"""
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式，便于日志记录和API返回"""
        return {
            'error_type': self.__class__.__name__,
            'message': self.message,
            'error_code': self.error_code,
            'details': self.details
        }


class ProcessError(SysmonError):
    """进程相关错误"""
    pass


class NetworkError(SysmonError):
    """网络相关错误"""
    pass


class FileError(SysmonError):
    """文件操作相关错误"""
    pass


class RegistryError(SysmonError):
    """注册表操作相关错误"""
    pass


class DllError(SysmonError):
    """DLL相关错误"""
    pass


class HandleError(SysmonError):
    """句柄查询相关错误"""
    pass


class DumpError(SysmonError):
    """进程转储相关错误"""
    pass


class PersistenceError(SysmonError):
    """持久化检测相关错误"""
    pass


class AnalysisError(SysmonError):
    """分析相关错误"""
    pass


class ConfigError(SysmonError):
    """配置相关错误"""
    pass


class ReportError(SysmonError):
    """报告生成相关错误"""
    pass


# 错误代码常量
class ErrorCodes:
    """预定义的错误代码"""
    
    # 进程错误
    PROCESS_NOT_FOUND = "PROC_001"
    PROCESS_ACCESS_DENIED = "PROC_002"
    PROCESS_TERMINATION_FAILED = "PROC_003"
    
    # 网络错误
    NETWORK_CONNECTION_FAILED = "NET_001"
    NETWORK_SOCKET_ERROR = "NET_002"
    NETWORK_TIMEOUT = "NET_003"
    
    # 文件错误
    FILE_NOT_FOUND = "FILE_001"
    FILE_ACCESS_DENIED = "FILE_002"
    FILE_WRITE_FAILED = "FILE_003"
    
    # 注册表错误
    REGISTRY_KEY_NOT_FOUND = "REG_001"
    REGISTRY_ACCESS_DENIED = "REG_002"
    REGISTRY_WRITE_FAILED = "REG_003"
    
    # DLL错误
    DLL_NOT_FOUND = "DLL_001"
    DLL_INJECTION_FAILED = "DLL_002"
    DLL_SIGNATURE_INVALID = "DLL_003"
    
    # 句柄错误
    HANDLE_QUERY_FAILED = "HND_001"
    HANDLE_ACCESS_DENIED = "HND_002"
    
    # 转储错误
    DUMP_FAILED = "DMP_001"
    DUMP_FILE_CORRUPT = "DMP_002"
    
    # 持久化错误
    PERSISTENCE_DETECTION_FAILED = "PER_001"
    PERSISTENCE_VERIFICATION_FAILED = "PER_002"
    
    # 分析错误
    ANALYSIS_FAILED = "ANA_001"
    ANALYSIS_TIMEOUT = "ANA_002"

    # 配置错误
    CONFIG_FILE_NOT_FOUND = "CFG_001"
    CONFIG_INVALID_FORMAT = "CFG_002"
    CONFIG_VALUE_ERROR = "CFG_003"
    
    # 报告错误
    REPORT_GENERATION_FAILED = "RPT_001"
    REPORT_SAVE_FAILED = "RPT_002"
    
    # 通用错误
    UNKNOWN_ERROR = "GEN_001"
    INVALID_PARAMETER = "GEN_002"
    OPERATION_TIMEOUT = "GEN_003"


def handle_subprocess_error(
    operation: str, 
    result, 
    error_code: Optional[str] = None
) -> tuple[bool, str]:
    """处理子进程执行错误
    
    这是一个便利函数，用于统一处理子进程错误。
    
    Args:
        operation: 操作名称
        result: subprocess.CompletedProcess 对象
        error_code: 错误代码（可选）
        
    Returns:
        (是否成功, 错误消息)
    """
    if result.returncode != 0:
        error_msg = f"{operation}失败"
        if result.stderr:
            error_msg += f": {result.stderr.decode('utf-8', errors='ignore').strip()}"
        return False, error_msg
    return True, "操作成功"


def handle_psutil_error(
    operation: str, 
    exc: Exception,
    error_code_map: Optional[dict[type, str]] = None
) -> SysmonError:
    """处理psutil相关错误
    
    Args:
        operation: 操作名称
        exc: 异常对象
        error_code_map: 异常类型到错误代码的映射（可选）
        
    Returns:
        转换后的 SysmonError 异常
    """
    import psutil
    
    error_code = ErrorCodes.UNKNOWN_ERROR
    
    if error_code_map and type(exc) in error_code_map:
        error_code = error_code_map[type(exc)]
    elif isinstance(exc, psutil.NoSuchProcess):
        error_code = ErrorCodes.PROCESS_NOT_FOUND
    elif isinstance(exc, psutil.AccessDenied):
        error_code = ErrorCodes.PROCESS_ACCESS_DENIED
    elif isinstance(exc, psutil.TimeoutExpired):
        error_code = ErrorCodes.OPERATION_TIMEOUT
    
    message = f"{operation}失败: {str(exc)}"
    
    return ProcessError(
        message=message,
        error_code=error_code,
        details={'original_exception': type(exc).__name__}
    )