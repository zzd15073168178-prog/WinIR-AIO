#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工具函数模块（重构版本）
整合所有辅助功能，提供向后兼容的接口
"""

# 导入所有子模块
from . import permissions
from . import filesystem
from . import processes
from . import network
from . import validation
from . import format as format_utils

# 重新导出所有函数（保持向后兼容）
# 权限检查
is_admin = permissions.is_admin

# 目录管理
ensure_logs_directory = filesystem.ensure_logs_directory
ensure_directory = filesystem.ensure_directory

# 进程相关
is_system_process = processes.is_system_process
is_suspicious_process_name = processes.is_suspicious_process_name
get_process_info = processes.get_process_info
get_process_parent = processes.get_process_parent
get_process_children = processes.get_process_children

# 网络相关
is_suspicious_port = network.is_suspicious_port
is_local_ip = network.is_local_ip

# 路径相关
is_suspicious_path = filesystem.is_suspicious_path
is_suspicious_extension = filesystem.is_suspicious_extension
is_system_directory = filesystem.is_system_directory

# 输入验证
validate_pid_input = validation.validate_pid_input

# 文件操作
create_procmon_log_path = filesystem.create_procmon_log_path
get_file_size_str = format_utils.get_file_size_str

# 时间格式化
format_timestamp = format_utils.format_timestamp
get_current_timestamp = format_utils.get_current_timestamp

# 文件信息获取
get_file_info = filesystem.get_file_info
get_file_version_info = filesystem.get_file_version_info
get_file_signature_info = filesystem.get_file_signature_info
get_file_hashes = filesystem.get_file_hashes
get_file_pe_info = filesystem.get_file_pe_info
get_dll_detailed_info = filesystem.get_dll_detailed_info

__all__ = [
    # 权限
    'is_admin',
    # 目录
    'ensure_logs_directory', 'ensure_directory',
    # 进程
    'is_system_process', 'is_suspicious_process_name',
    'get_process_info', 'get_process_parent', 'get_process_children',
    # 网络
    'is_suspicious_port', 'is_local_ip',
    # 路径
    'is_suspicious_path', 'is_suspicious_extension', 'is_system_directory',
    # 验证
    'validate_pid_input',
    # 文件操作
    'create_procmon_log_path', 'get_file_size_str',
    # 时间
    'format_timestamp', 'get_current_timestamp',
    # 文件信息
    'get_file_info', 'get_file_version_info', 'get_file_signature_info',
    'get_file_hashes', 'get_file_pe_info', 'get_dll_detailed_info',
]