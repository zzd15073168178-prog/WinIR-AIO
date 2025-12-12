#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文件 Hash 计算管理模块"""

import os
import hashlib
from typing import Dict, List, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class HashManager:
    """文件 Hash 计算管理器"""

    # 支持的 Hash 算法
    ALGORITHMS = ['MD5', 'SHA1', 'SHA256', 'SHA512']

    # 文件读取缓冲区大小 (64KB)
    BUFFER_SIZE = 65536

    def __init__(self):
        self.results = []
        self.is_cancelled = False

    def calculate_file_hash(self, file_path: str, algorithms: List[str] = None) -> Dict:
        """
        计算单个文件的 Hash 值

        Args:
            file_path: 文件路径
            algorithms: 要计算的算法列表，默认全部

        Returns:
            包含文件信息和 Hash 值的字典
        """
        if algorithms is None:
            algorithms = self.ALGORITHMS

        result = {
            'path': file_path,
            'name': os.path.basename(file_path),
            'size': 0,
            'size_str': '',
            'error': None,
            'MD5': '',
            'SHA1': '',
            'SHA256': '',
            'SHA512': ''
        }

        if not os.path.exists(file_path):
            result['error'] = '文件不存在'
            return result

        if not os.path.isfile(file_path):
            result['error'] = '不是文件'
            return result

        try:
            file_size = os.path.getsize(file_path)
            result['size'] = file_size
            result['size_str'] = self._format_size(file_size)

            # 初始化 hash 对象
            hashers = {}
            for algo in algorithms:
                algo_upper = algo.upper()
                if algo_upper == 'MD5':
                    hashers['MD5'] = hashlib.md5()
                elif algo_upper == 'SHA1':
                    hashers['SHA1'] = hashlib.sha1()
                elif algo_upper == 'SHA256':
                    hashers['SHA256'] = hashlib.sha256()
                elif algo_upper == 'SHA512':
                    hashers['SHA512'] = hashlib.sha512()

            # 读取文件并计算 hash
            with open(file_path, 'rb') as f:
                while True:
                    if self.is_cancelled:
                        result['error'] = '已取消'
                        return result

                    data = f.read(self.BUFFER_SIZE)
                    if not data:
                        break
                    for hasher in hashers.values():
                        hasher.update(data)

            # 获取 hash 值
            for algo, hasher in hashers.items():
                result[algo] = hasher.hexdigest().upper()

        except PermissionError:
            result['error'] = '无访问权限'
        except Exception as e:
            result['error'] = str(e)

        return result

    def calculate_folder_hash(self, folder_path: str, algorithms: List[str] = None,
                              recursive: bool = True, max_workers: int = 4,
                              progress_callback: Callable = None,
                              file_extensions: List[str] = None) -> List[Dict]:
        """
        计算文件夹中所有文件的 Hash 值

        Args:
            folder_path: 文件夹路径
            algorithms: 要计算的算法列表
            recursive: 是否递归子目录
            max_workers: 并行线程数
            progress_callback: 进度回调函数 (current, total, file_path)
            file_extensions: 限制文件扩展名列表，如 ['.exe', '.dll']

        Returns:
            所有文件的 Hash 结果列表
        """
        self.results = []
        self.is_cancelled = False

        if not os.path.exists(folder_path):
            return []

        # 收集所有文件
        files = []
        if recursive:
            for root, dirs, filenames in os.walk(folder_path):
                if self.is_cancelled:
                    break
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    if file_extensions:
                        ext = os.path.splitext(filename)[1].lower()
                        if ext not in [e.lower() for e in file_extensions]:
                            continue
                    files.append(file_path)
        else:
            for filename in os.listdir(folder_path):
                file_path = os.path.join(folder_path, filename)
                if os.path.isfile(file_path):
                    if file_extensions:
                        ext = os.path.splitext(filename)[1].lower()
                        if ext not in [e.lower() for e in file_extensions]:
                            continue
                    files.append(file_path)

        total = len(files)
        completed = 0

        # 并行计算
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.calculate_file_hash, f, algorithms): f for f in files}

            for future in as_completed(futures):
                if self.is_cancelled:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                result = future.result()
                self.results.append(result)
                completed += 1

                if progress_callback:
                    progress_callback(completed, total, result['path'])

        return self.results

    def cancel(self):
        """取消计算"""
        self.is_cancelled = True

    def verify_hash(self, file_path: str, expected_hash: str, algorithm: str = 'SHA256') -> bool:
        """
        验证文件 Hash

        Args:
            file_path: 文件路径
            expected_hash: 预期的 Hash 值
            algorithm: 使用的算法

        Returns:
            是否匹配
        """
        result = self.calculate_file_hash(file_path, [algorithm])
        if result['error']:
            return False

        actual_hash = result.get(algorithm.upper(), '')
        return actual_hash.upper() == expected_hash.upper()

    def get_summary(self) -> Dict:
        """获取计算摘要"""
        total = len(self.results)
        success = len([r for r in self.results if not r['error']])
        failed = total - success
        total_size = sum(r['size'] for r in self.results if not r['error'])

        return {
            'total': total,
            'success': success,
            'failed': failed,
            'total_size': total_size,
            'total_size_str': self._format_size(total_size)
        }

    @staticmethod
    def _format_size(size: int) -> str:
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}" if unit != 'B' else f"{size} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    def export_results(self, output_path: str, format_type: str = 'csv') -> bool:
        """
        导出结果

        Args:
            output_path: 输出文件路径
            format_type: 格式类型 (csv, txt, json)

        Returns:
            是否成功
        """
        try:
            if format_type == 'csv':
                import csv
                with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(['文件名', '路径', '大小', 'MD5', 'SHA1', 'SHA256', 'SHA512', '错误'])
                    for r in self.results:
                        writer.writerow([
                            r['name'], r['path'], r['size_str'],
                            r['MD5'], r['SHA1'], r['SHA256'], r['SHA512'],
                            r['error'] or ''
                        ])

            elif format_type == 'txt':
                with open(output_path, 'w', encoding='utf-8') as f:
                    for r in self.results:
                        f.write(f"文件: {r['name']}\n")
                        f.write(f"路径: {r['path']}\n")
                        f.write(f"大小: {r['size_str']}\n")
                        if r['error']:
                            f.write(f"错误: {r['error']}\n")
                        else:
                            f.write(f"MD5:    {r['MD5']}\n")
                            f.write(f"SHA1:   {r['SHA1']}\n")
                            f.write(f"SHA256: {r['SHA256']}\n")
                            f.write(f"SHA512: {r['SHA512']}\n")
                        f.write("-" * 80 + "\n")

            elif format_type == 'json':
                import json
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, ensure_ascii=False, indent=2)

            return True
        except Exception:
            return False
