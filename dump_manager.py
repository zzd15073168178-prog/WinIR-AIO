#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程转储管理模块
处理进程内存转储功能
"""

import subprocess
import os
from datetime import datetime
from utils import ensure_directory
from constants import TOOLS, DUMPS_DIR
from utils.validation import sanitize_pid


class DumpManager:
    """进程转储管理器"""

    def __init__(self):
        ensure_directory(DUMPS_DIR)
    
    def create_dump(self, pid, save_path=None, dump_type='mini'):
        """创建进程转储

        Args:
            pid: 进程PID
            save_path: 保存路径（可选，默认使用DUMPS_DIR）
            dump_type: 转储类型 ('mini', 'full', 'ma')

        Returns:
            (success, message, dump_file_path)
        """
        # 安全验证：验证 PID
        valid, safe_pid, error = sanitize_pid(pid)
        if not valid:
            return False, f"PID 验证失败: {error}", None

        # 验证 dump_type（白名单）
        allowed_dump_types = {'mini', 'full', 'ma'}
        if dump_type not in allowed_dump_types:
            return False, f"无效的转储类型，允许值: {allowed_dump_types}", None

        # 检查工具是否存在
        if not os.path.exists(TOOLS['procdump']):
            return False, f"未找到工具: {TOOLS['procdump']}", None

        # 确定保存路径
        if not save_path:
            save_path = DUMPS_DIR

        if not os.path.exists(save_path):
            return False, "保存路径不存在", None

        # 生成文件名（使用验证后的安全 PID）
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dump_filename = f'dump_{safe_pid}_{timestamp}.dmp'
        dump_filepath = os.path.join(save_path, dump_filename)

        try:
            # 构建命令（使用列表形式）
            cmd = [TOOLS['procdump'], '-accepteula']

            # 添加转储类型参数
            if dump_type == 'mini':
                cmd.append('-mm')  # Mini dump
            elif dump_type == 'full':
                cmd.append('-ma')  # Full dump

            cmd.extend([str(safe_pid), dump_filepath])

            # 安全执行：使用列表形式，禁用 shell
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=120,  # 转储可能需要较长时间
                shell=False  # 关键：禁用 shell 解析
            )
            
            # 检查是否成功
            if os.path.exists(dump_filepath):
                file_size = os.path.getsize(dump_filepath)
                size_mb = file_size / 1024 / 1024
                return True, f"转储成功！文件大小: {size_mb:.2f} MB", dump_filepath
            else:
                # 检查错误信息
                error_msg = result.stderr.lower() if result.stderr else ""

                # 权限错误
                if 'access' in error_msg or 'denied' in error_msg or result.returncode == 5:
                    return False, (
                        "转储失败：权限不足\n\n"
                        "可能的原因：\n"
                        "1. 需要以管理员身份运行程序\n"
                        "2. 目标进程是系统进程，需要更高权限\n"
                        "3. 目标进程受保护（如杀毒软件）\n\n"
                        "解决方案：\n"
                        "- 右键点击程序，选择'以管理员身份运行'\n"
                        "- 选择非系统进程进行转储"
                    ), None

                # 进程不存在
                elif 'not found' in error_msg or 'invalid' in error_msg:
                    return False, f"转储失败：进程 {pid} 不存在或已退出", None

                # 其他错误
                else:
                    return False, f"转储失败: {result.stderr if result.stderr else '未知错误'}", None

        except subprocess.TimeoutExpired:
            return False, "转储超时（进程可能太大或响应缓慢）", None
        except PermissionError:
            return False, (
                "转储失败：权限不足\n\n"
                "请以管理员身份运行程序：\n"
                "1. 右键点击程序\n"
                "2. 选择'以管理员身份运行'"
            ), None
        except Exception as e:
            error_str = str(e)
            # 检查是否是权限错误
            if 'WinError 5' in error_str or '拒绝访问' in error_str:
                return False, (
                    "转储失败：权限不足 (WinError 5)\n\n"
                    "请以管理员身份运行程序：\n"
                    "1. 关闭当前程序\n"
                    "2. 右键点击程序图标\n"
                    "3. 选择'以管理员身份运行'\n\n"
                    "注意：某些系统进程即使以管理员身份运行也无法转储"
                ), None
            else:
                return False, f"转储出错: {error_str}", None
    
    def create_multiple_dumps(self, pid, count=3, interval=5, save_path=None):
        """创建多个转储（用于分析间歇性问题）
        
        Args:
            pid: 进程PID
            count: 转储次数
            interval: 间隔时间（秒）
            save_path: 保存路径
        
        Returns:
            (success, message, dump_files)
        """
        import time
        
        dump_files = []
        
        for i in range(count):
            success, message, dump_file = self.create_dump(pid, save_path, 'mini')
            
            if success:
                dump_files.append(dump_file)
            else:
                return False, f"第{i+1}次转储失败: {message}", dump_files
            
            # 如果不是最后一次，等待间隔
            if i < count - 1:
                time.sleep(interval)
        
        return True, f"成功创建{count}个转储文件", dump_files
    
    def create_crash_dump(self, pid, save_path=None):
        """创建崩溃转储（等待进程崩溃时自动转储）

        Args:
            pid: 进程PID
            save_path: 保存路径

        Returns:
            (success, message, dump_file_path)
        """
        # 安全验证：验证 PID
        valid, safe_pid, error = sanitize_pid(pid)
        if not valid:
            return False, f"PID 验证失败: {error}", None

        # 检查工具是否存在
        if not os.path.exists(TOOLS['procdump']):
            return False, f"未找到工具: {TOOLS['procdump']}", None

        # 确定保存路径
        if not save_path:
            save_path = DUMPS_DIR

        if not os.path.exists(save_path):
            return False, "保存路径不存在", None

        # 生成文件名（使用验证后的安全 PID）
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dump_filename = f'crash_dump_{safe_pid}_{timestamp}.dmp'
        dump_filepath = os.path.join(save_path, dump_filename)

        try:
            # 构建命令（使用列表形式）
            cmd = [TOOLS['procdump'], '-accepteula', '-e', str(safe_pid), dump_filepath]

            # 安全执行：使用列表形式，禁用 shell
            subprocess.Popen(
                cmd,
                shell=False,  # 关键：禁用 shell 解析
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            return True, "崩溃转储监控已启动，等待进程崩溃...", dump_filepath

        except Exception as e:
            return False, f"启动崩溃转储失败: {str(e)}", None
    
    def get_dump_list(self, save_path=None):
        """获取转储文件列表
        
        Args:
            save_path: 保存路径（可选）
        
        Returns:
            转储文件列表
        """
        if not save_path:
            save_path = DUMPS_DIR
        
        if not os.path.exists(save_path):
            return []
        
        dump_files = []
        
        for filename in os.listdir(save_path):
            if filename.endswith('.dmp'):
                filepath = os.path.join(save_path, filename)
                file_size = os.path.getsize(filepath)
                file_time = os.path.getmtime(filepath)
                
                dump_files.append({
                    'filename': filename,
                    'filepath': filepath,
                    'size': file_size,
                    'size_mb': file_size / 1024 / 1024,
                    'time': file_time
                })
        
        # 按时间排序（最新的在前）
        dump_files.sort(key=lambda x: x['time'], reverse=True)
        
        return dump_files

