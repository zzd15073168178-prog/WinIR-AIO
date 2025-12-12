#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
输入验证模块 - 包含安全验证函数防止命令注入
"""

import os
import re
import psutil


# 危险字符黑名单 - 用于命令注入检测
DANGEROUS_CHARS = set(';&|`$(){}[]<>!\n\r\'\"\\')
DANGEROUS_PATTERNS = [
    r'&&',           # 命令链接
    r'\|\|',         # 或操作
    r'\|',           # 管道
    r';',            # 命令分隔
    r'`',            # 命令替换
    r'\$\(',         # 命令替换
    r'\$\{',         # 变量展开
    r'>',            # 重定向
    r'<',            # 重定向
    r'\.\.',         # 路径遍历
]


def validate_pid_input(pid_str):
    """验证PID输入"""
    if not pid_str:
        return False, "请输入进程PID"

    try:
        pid = int(pid_str)
        if pid <= 0:
            return False, "PID必须大于0"

        # 检查进程是否存在
        if not psutil.pid_exists(pid):
            return False, f"进程 {pid} 不存在"

        return True, ""
    except ValueError:
        return False, "PID必须是数字"


def sanitize_pid(pid_input) -> tuple[bool, int, str]:
    """
    安全地验证和转换 PID 输入
    返回: (是否有效, PID整数, 错误信息)
    """
    if pid_input is None:
        return False, 0, "PID 不能为空"

    # 转换为字符串处理
    pid_str = str(pid_input).strip()

    # 只允许数字
    if not pid_str.isdigit():
        return False, 0, "PID 必须是纯数字"

    try:
        pid = int(pid_str)
        if pid <= 0 or pid > 4194304:  # Linux 最大 PID 值
            return False, 0, "PID 超出有效范围"
        return True, pid, ""
    except (ValueError, OverflowError):
        return False, 0, "无效的 PID 值"


def sanitize_path(path_input: str) -> tuple[bool, str, str]:
    """
    安全地验证文件路径，防止命令注入和路径遍历
    返回: (是否有效, 清理后的路径, 错误信息)
    """
    if not path_input:
        return False, "", "路径不能为空"

    path = str(path_input).strip()

    # 检查危险字符
    for char in DANGEROUS_CHARS:
        if char in path and char not in ('\\', '\'', '\"'):  # Windows 路径允许反斜杠
            return False, "", f"路径包含非法字符: {repr(char)}"

    # 检查危险模式
    for pattern in DANGEROUS_PATTERNS:
        if pattern not in (r'\\', r'\.\.'):  # 跳过 Windows 相关
            if re.search(pattern, path):
                return False, "", f"路径包含非法模式"

    # 检查路径遍历 (但允许绝对路径)
    normalized = os.path.normpath(path)

    # 检查是否存在
    if not os.path.exists(normalized):
        return False, "", f"路径不存在: {normalized}"

    return True, normalized, ""


def sanitize_executable_path(path_input: str) -> tuple[bool, str, str]:
    """
    验证可执行文件路径
    返回: (是否有效, 清理后的路径, 错误信息)
    """
    valid, path, error = sanitize_path(path_input)
    if not valid:
        return False, "", error

    # 检查是否是文件
    if not os.path.isfile(path):
        return False, "", "路径不是文件"

    # 检查扩展名（可选，但推荐）
    valid_extensions = {'.exe', '.bat', '.cmd', '.com', '.msi', '.ps1'}
    ext = os.path.splitext(path)[1].lower()
    if ext and ext not in valid_extensions:
        # 不阻止，但记录警告
        pass

    return True, path, ""


def sanitize_args(args_input: str) -> tuple[bool, list, str]:
    """
    安全地解析命令行参数，返回参数列表而非字符串
    返回: (是否有效, 参数列表, 错误信息)
    """
    if not args_input:
        return True, [], ""

    args_str = str(args_input).strip()

    # 检查最危险的字符
    dangerous_for_args = {'`', '$', '|', ';', '&', '\n', '\r'}
    for char in dangerous_for_args:
        if char in args_str:
            return False, [], f"参数包含非法字符: {repr(char)}"

    # 简单分割（不使用 shell 解析）
    # 这里使用 shlex 进行安全分割
    import shlex
    try:
        args_list = shlex.split(args_str, posix=False)  # Windows 模式
        return True, args_list, ""
    except ValueError as e:
        return False, [], f"参数解析错误: {e}"


def sanitize_filter_type(filter_input: str, allowed_values: list) -> tuple[bool, str, str]:
    """
    验证过滤类型参数（用于 handle.exe 等工具的 -t 参数）
    返回: (是否有效, 清理后的值, 错误信息)
    """
    if not filter_input:
        return True, "", ""

    filter_str = str(filter_input).strip()

    # 检查是否在允许列表中
    if filter_str not in allowed_values:
        return False, "", f"无效的过滤类型，允许值: {allowed_values}"

    return True, filter_str, ""


def is_safe_for_powershell(value: str) -> bool:
    """
    检查值是否可以安全用于 PowerShell
    """
    if not value:
        return True

    # PowerShell 特殊字符
    ps_dangerous = {'`', '$', '(', ')', '{', '}', ';', '|', '&', '\n', '\r'}
    return not any(char in value for char in ps_dangerous)


def escape_powershell_string(value: str) -> str:
    """
    转义 PowerShell 字符串中的特殊字符
    使用单引号包裹并转义内部单引号
    """
    if not value:
        return "''"
    # 单引号内只需要转义单引号本身（用两个单引号）
    escaped = value.replace("'", "''")
    return f"'{escaped}'"