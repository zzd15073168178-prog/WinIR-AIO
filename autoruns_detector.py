#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Autoruns 持久化检测器
使用微软 Sysinternals Autoruns 工具进行全面的持久化检测

Autoruns 覆盖的位置包括：
- 注册表 Run/RunOnce 键
- 计划任务
- Windows 服务
- 驱动程序
- 启动文件夹
- WMI 订阅
- Winlogon
- IFEO 映像劫持
- AppInit DLLs
- KnownDLLs
- LSA Providers
- Print Monitors
- Winsock Providers
- 浏览器扩展
- Explorer 插件
- Office 插件
- 还有更多...
"""

import subprocess
import csv
import io
import os
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class AutorunCategory(Enum):
    """Autoruns 类别"""
    LOGON = "Logon"
    EXPLORER = "Explorer"
    INTERNET_EXPLORER = "Internet Explorer"
    SCHEDULED_TASKS = "Scheduled Tasks"
    SERVICES = "Services"
    DRIVERS = "Drivers"
    CODECS = "Codecs"
    BOOT_EXECUTE = "Boot Execute"
    IMAGE_HIJACKS = "Image Hijacks"
    APPINIT = "AppInit"
    KNOWN_DLLS = "KnownDLLs"
    WINLOGON = "Winlogon"
    WINSOCK_PROVIDERS = "Winsock Providers"
    PRINT_MONITORS = "Print Monitors"
    LSA_PROVIDERS = "LSA Providers"
    NETWORK_PROVIDERS = "Network Providers"
    WMI = "WMI"
    OFFICE = "Office"
    SIDEBAR_GADGETS = "Sidebar Gadgets"


@dataclass
class AutorunEntry:
    """单个自启动项"""
    time: str = ""
    entry_location: str = ""
    entry: str = ""
    enabled: str = ""
    category: str = ""
    profile: str = ""
    description: str = ""
    company: str = ""
    image_path: str = ""
    version: str = ""
    launch_string: str = ""
    md5: str = ""
    sha256: str = ""
    signer: str = ""

    @property
    def unique_key(self) -> str:
        """生成唯一标识"""
        return f"{self.entry_location}|{self.entry}|{self.image_path}"

    @property
    def is_microsoft_signed(self) -> bool:
        """是否微软签名"""
        return "Microsoft" in self.signer if self.signer else False

    @property
    def is_unsigned(self) -> bool:
        """是否未签名"""
        return not self.signer or "(Not verified)" in self.signer

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AutorunChange:
    """持久化变化"""
    type: str                    # 类别
    action: str                  # Created/Modified/Deleted
    location: str                # 位置
    entry: str                   # 条目名
    value: str                   # 值
    severity: str                # critical/warning/info
    description: str             # 描述
    md5: str = ""
    sha256: str = ""
    signer: str = ""
    company: str = ""
    old_value: str = ""          # 修改前的值

    def to_dict(self) -> Dict:
        return asdict(self)


class AutorunsDetector:
    """
    使用 Autoruns 进行持久化检测

    优点：
    - 微软官方工具，覆盖位置最全（100+ 位置）
    - 支持文件哈希计算
    - 支持数字签名验证
    - 输出格式标准化

    使用方法：
    ```python
    detector = AutorunsDetector()
    detector.take_initial_snapshot()

    # ... 运行样本 ...

    detector.take_final_snapshot()
    changes = detector.detect_changes()
    ```
    """

    def __init__(self, autoruns_path: str = None):
        """
        初始化检测器

        Args:
            autoruns_path: autorunsc64.exe 路径，默认自动查找
        """
        # 自动查找 autorunsc64.exe
        if autoruns_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            candidates = [
                os.path.join(base_dir, 'autorunsc64.exe'),
                os.path.join(base_dir, 'autorunsc.exe'),
                os.path.join(base_dir, 'Autoruns', 'autorunsc64.exe'),
                os.path.join(base_dir, 'Autoruns', 'autorunsc.exe'),
            ]
            for path in candidates:
                if os.path.exists(path):
                    autoruns_path = path
                    break

        if not autoruns_path or not os.path.exists(autoruns_path):
            raise FileNotFoundError(
                "未找到 autorunsc64.exe，请确保工具存在或指定正确路径"
            )

        self.autoruns_path = autoruns_path
        self.initial_snapshot: List[AutorunEntry] = []
        self.final_snapshot: List[AutorunEntry] = []
        self.changes: List[AutorunChange] = []

        # 配置
        self.include_microsoft = True   # 是否包含微软签名的条目（默认包含，以便对比）
        self.include_verified = True    # 是否包含已验证签名的条目
        self.timeout = 120              # 超时时间（秒）

    def take_snapshot(self,
                      categories: List[str] = None,
                      include_hash: bool = True,
                      verify_signatures: bool = True) -> List[AutorunEntry]:
        """
        使用 Autoruns 获取系统快照

        Args:
            categories: 要扫描的类别，None 表示所有
            include_hash: 是否计算文件哈希
            verify_signatures: 是否验证数字签名

        Returns:
            AutorunEntry 列表
        """
        # 构建命令
        cmd = [
            self.autoruns_path,
            '-accepteula',  # 接受许可协议
            '-nobanner',    # 不显示横幅
            '-c',           # CSV 格式输出
        ]

        # 选择扫描类别
        if categories:
            # 只扫描指定类别
            for cat in categories:
                cmd.extend(['-a', cat])
        else:
            # 扫描所有
            cmd.extend(['-a', '*'])

        # 哈希选项
        if include_hash:
            cmd.append('-h')  # 计算文件哈希

        # 签名验证选项
        if verify_signatures:
            cmd.append('-s')  # 验证签名
            # 注意: -v 参数会触发 VirusTotal ToS 确认，不使用

        # 隐藏微软签名条目（可选）
        if not self.include_microsoft:
            cmd.append('-m')  # 隐藏微软条目

        try:
            print(f"[Autoruns] 执行命令: {' '.join(cmd[:5])}...")

            # 使用 bytes 模式读取，然后处理编码（Autoruns 可能输出 UTF-16）
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout
            )

            # 尝试解码输出（Autoruns 可能使用 UTF-16 或 UTF-8）
            stdout_text = ""
            for encoding in ['utf-8', 'utf-16', 'utf-16-le', 'gbk', 'latin-1']:
                try:
                    stdout_text = result.stdout.decode(encoding)
                    # 检查是否包含有效的 CSV 头
                    if 'Entry Location' in stdout_text or 'Time' in stdout_text:
                        break
                except:
                    continue

            if result.returncode != 0 and result.stderr:
                # Autoruns 有时返回非零但仍有输出
                try:
                    stderr_text = result.stderr.decode('utf-8', errors='replace')
                    print(f"[Autoruns] 警告: {stderr_text[:200]}")
                except:
                    pass

            return self._parse_csv(stdout_text)

        except subprocess.TimeoutExpired:
            print(f"[Autoruns] 执行超时 ({self.timeout}秒)")
            return []
        except Exception as e:
            print(f"[Autoruns] 执行错误: {e}")
            return []

    def _parse_csv(self, csv_content: str) -> List[AutorunEntry]:
        """解析 Autoruns CSV 输出"""
        entries = []

        if not csv_content or not csv_content.strip():
            return entries

        try:
            # 跳过可能的空行
            lines = [l for l in csv_content.split('\n') if l.strip()]
            if not lines:
                return entries

            reader = csv.DictReader(io.StringIO('\n'.join(lines)))

            for row in reader:
                try:
                    entry = AutorunEntry(
                        time=row.get('Time', ''),
                        entry_location=row.get('Entry Location', ''),
                        entry=row.get('Entry', ''),
                        enabled=row.get('Enabled', ''),
                        category=row.get('Category', ''),
                        profile=row.get('Profile', ''),
                        description=row.get('Description', ''),
                        company=row.get('Company', ''),
                        image_path=row.get('Image Path', ''),
                        version=row.get('Version', ''),
                        launch_string=row.get('Launch String', ''),
                        md5=row.get('MD5', ''),
                        sha256=row.get('SHA-256', ''),
                        signer=row.get('Signer', ''),
                    )

                    # 过滤空条目
                    if entry.entry or entry.image_path:
                        entries.append(entry)

                except Exception as e:
                    # 跳过解析错误的行
                    continue

        except Exception as e:
            print(f"[Autoruns] CSV 解析错误: {e}")

        return entries

    def take_initial_snapshot(self) -> List[AutorunEntry]:
        """
        获取初始快照（样本运行前）

        Returns:
            AutorunEntry 列表
        """
        print("[Autoruns] 正在获取初始快照（可能需要 30-60 秒）...")
        start_time = datetime.now()

        self.initial_snapshot = self.take_snapshot()

        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"[Autoruns] 初始快照完成，共 {len(self.initial_snapshot)} 项，耗时 {elapsed:.1f}秒")

        return self.initial_snapshot

    def take_final_snapshot(self) -> List[AutorunEntry]:
        """
        获取最终快照（样本运行后）

        Returns:
            AutorunEntry 列表
        """
        print("[Autoruns] 正在获取最终快照...")
        start_time = datetime.now()

        self.final_snapshot = self.take_snapshot()

        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"[Autoruns] 最终快照完成，共 {len(self.final_snapshot)} 项，耗时 {elapsed:.1f}秒")

        return self.final_snapshot

    def detect_changes(self) -> List[AutorunChange]:
        """
        对比快照，检测持久化变化

        Returns:
            AutorunChange 列表
        """
        if not self.initial_snapshot or not self.final_snapshot:
            print("[Autoruns] 错误：需要先获取初始和最终快照")
            return []

        print("[Autoruns] 正在分析变化...")
        self.changes = []

        # 构建索引
        initial_map = {e.unique_key: e for e in self.initial_snapshot}
        final_map = {e.unique_key: e for e in self.final_snapshot}

        # 检测新增
        for key, entry in final_map.items():
            if key not in initial_map:
                severity = self._calculate_severity(entry, 'Created')
                self.changes.append(AutorunChange(
                    type=entry.category,
                    action='Created',
                    location=entry.entry_location,
                    entry=entry.entry,
                    value=entry.launch_string or entry.image_path,
                    severity=severity,
                    description=f"新增自启动项: {entry.entry}",
                    md5=entry.md5,
                    sha256=entry.sha256,
                    signer=entry.signer,
                    company=entry.company,
                ))

        # 检测删除
        for key, entry in initial_map.items():
            if key not in final_map:
                self.changes.append(AutorunChange(
                    type=entry.category,
                    action='Deleted',
                    location=entry.entry_location,
                    entry=entry.entry,
                    value=entry.launch_string or entry.image_path,
                    severity='info',
                    description=f"自启动项被删除: {entry.entry}",
                    md5=entry.md5,
                    signer=entry.signer,
                ))

        # 检测修改
        for key, entry in final_map.items():
            if key in initial_map:
                old = initial_map[key]

                # 检查关键字段是否变化
                changes_detected = []

                if old.launch_string != entry.launch_string:
                    changes_detected.append(f"启动命令: {old.launch_string} -> {entry.launch_string}")

                if old.enabled != entry.enabled:
                    changes_detected.append(f"启用状态: {old.enabled} -> {entry.enabled}")

                if old.md5 and entry.md5 and old.md5 != entry.md5:
                    changes_detected.append(f"文件哈希变化")

                if changes_detected:
                    self.changes.append(AutorunChange(
                        type=entry.category,
                        action='Modified',
                        location=entry.entry_location,
                        entry=entry.entry,
                        value=entry.launch_string or entry.image_path,
                        old_value=old.launch_string or old.image_path,
                        severity='warning',
                        description=f"自启动项被修改: {'; '.join(changes_detected)}",
                        md5=entry.md5,
                        sha256=entry.sha256,
                        signer=entry.signer,
                        company=entry.company,
                    ))

        # 按严重程度排序
        severity_order = {'critical': 0, 'warning': 1, 'info': 2}
        self.changes.sort(key=lambda x: severity_order.get(x.severity, 3))

        print(f"[Autoruns] 检测到 {len(self.changes)} 个变化")
        return self.changes

    def _calculate_severity(self, entry: AutorunEntry, action: str) -> str:
        """
        计算严重程度

        规则：
        - 未签名的新增条目 -> critical
        - 已签名但非微软的新增条目 -> warning
        - 微软签名的新增条目 -> info
        - 敏感位置的变化 -> critical
        """
        if action == 'Created':
            # 检查敏感类别
            critical_categories = [
                'Services', 'Drivers', 'Boot Execute',
                'Winlogon', 'LSA Providers', 'Image Hijacks',
                'AppInit', 'WMI'
            ]

            if entry.category in critical_categories:
                return 'critical'

            # 检查签名
            if entry.is_unsigned:
                return 'critical'

            if not entry.is_microsoft_signed:
                return 'warning'

            return 'info'

        return 'warning'

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        if not self.changes:
            return {
                'total': 0,
                'created': 0,
                'modified': 0,
                'deleted': 0,
                'critical': 0,
                'warning': 0,
                'info': 0,
                'by_category': {},
            }

        stats = {
            'total': len(self.changes),
            'created': len([c for c in self.changes if c.action == 'Created']),
            'modified': len([c for c in self.changes if c.action == 'Modified']),
            'deleted': len([c for c in self.changes if c.action == 'Deleted']),
            'critical': len([c for c in self.changes if c.severity == 'critical']),
            'warning': len([c for c in self.changes if c.severity == 'warning']),
            'info': len([c for c in self.changes if c.severity == 'info']),
            'by_category': {},
        }

        for change in self.changes:
            cat = change.type
            stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1

        return stats

    def get_snapshot_statistics(self) -> Dict[str, Any]:
        """获取快照统计"""
        def snapshot_stats(snapshot: List[AutorunEntry]) -> Dict:
            if not snapshot:
                return {'total': 0, 'by_category': {}, 'unsigned': 0}

            by_cat = {}
            unsigned = 0

            for entry in snapshot:
                cat = entry.category
                by_cat[cat] = by_cat.get(cat, 0) + 1
                if entry.is_unsigned:
                    unsigned += 1

            return {
                'total': len(snapshot),
                'by_category': by_cat,
                'unsigned': unsigned,
            }

        return {
            'initial': snapshot_stats(self.initial_snapshot),
            'final': snapshot_stats(self.final_snapshot),
        }

    def export_changes(self, filepath: str, format: str = 'json') -> bool:
        """
        导出检测结果

        Args:
            filepath: 输出文件路径
            format: 'json' 或 'csv'
        """
        try:
            if format == 'json':
                data = {
                    'timestamp': datetime.now().isoformat(),
                    'statistics': self.get_statistics(),
                    'changes': [c.to_dict() for c in self.changes],
                }
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

            elif format == 'csv':
                with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
                    if self.changes:
                        writer = csv.DictWriter(f, fieldnames=self.changes[0].to_dict().keys())
                        writer.writeheader()
                        for change in self.changes:
                            writer.writerow(change.to_dict())

            return True

        except Exception as e:
            print(f"[Autoruns] 导出失败: {e}")
            return False

    def print_changes(self):
        """打印变化（彩色输出）"""
        if not self.changes:
            print("[Autoruns] 未检测到持久化变化")
            return

        # ANSI 颜色
        RED = '\033[91m'
        YELLOW = '\033[93m'
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        RESET = '\033[0m'
        BOLD = '\033[1m'

        severity_colors = {
            'critical': RED,
            'warning': YELLOW,
            'info': CYAN,
        }

        print(f"\n{BOLD}{'='*70}")
        print(f"  Autoruns 持久化检测结果")
        print(f"{'='*70}{RESET}")

        stats = self.get_statistics()
        print(f"\n总计: {stats['total']} 个变化")
        print(f"  - {RED}严重{RESET}: {stats['critical']}")
        print(f"  - {YELLOW}警告{RESET}: {stats['warning']}")
        print(f"  - {CYAN}信息{RESET}: {stats['info']}")

        print(f"\n{BOLD}详细列表:{RESET}")
        print("-" * 70)

        for change in self.changes:
            color = severity_colors.get(change.severity, RESET)
            action_icon = {'Created': '+', 'Deleted': '-', 'Modified': '~'}.get(change.action, '?')

            print(f"\n{color}[{change.severity.upper()}] [{action_icon}] {change.type}{RESET}")
            print(f"  条目: {change.entry}")
            print(f"  位置: {change.location}")
            print(f"  值: {change.value[:80]}{'...' if len(change.value) > 80 else ''}")

            if change.old_value:
                print(f"  旧值: {change.old_value[:80]}")

            if change.signer:
                signer_color = GREEN if 'Microsoft' in change.signer else YELLOW
                print(f"  签名: {signer_color}{change.signer}{RESET}")
            else:
                print(f"  签名: {RED}未签名{RESET}")

            if change.md5:
                print(f"  MD5: {change.md5}")


# ==================== 测试代码 ====================

if __name__ == '__main__':
    print("=" * 70)
    print("Autoruns 持久化检测器 - 测试模式")
    print("=" * 70)

    try:
        detector = AutorunsDetector()
        print(f"\n工具路径: {detector.autoruns_path}")

        # 获取当前快照
        print("\n[测试] 获取系统快照...")
        snapshot = detector.take_snapshot()

        print(f"\n快照统计:")
        print(f"  总条目: {len(snapshot)}")

        # 按类别统计
        categories = {}
        unsigned_count = 0

        for entry in snapshot:
            cat = entry.category
            categories[cat] = categories.get(cat, 0) + 1
            if entry.is_unsigned:
                unsigned_count += 1

        print(f"\n按类别统计:")
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            print(f"  {cat}: {count}")

        print(f"\n未签名条目: {unsigned_count}")

        # 显示部分条目
        print(f"\n示例条目 (前5个):")
        for entry in snapshot[:5]:
            print(f"\n  [{entry.category}] {entry.entry}")
            print(f"    位置: {entry.entry_location}")
            print(f"    路径: {entry.image_path}")
            print(f"    签名: {entry.signer or '未签名'}")

    except FileNotFoundError as e:
        print(f"\n错误: {e}")
    except Exception as e:
        print(f"\n错误: {e}")

    print("\n" + "=" * 70)
    print("测试完成")
    print("=" * 70)
