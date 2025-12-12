#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sysmon CLI - 应急响应命令行工具
专注功能性，无 GUI 依赖
"""

import sys
import os
import argparse
import json
from datetime import datetime

# 确保模块路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from process_manager import ProcessManager
from network_manager import NetworkManager
from dll_manager import DLLManager
from handle_manager import HandleManager
from dump_manager import DumpManager
from persistence_detector import PersistenceDetector


class Colors:
    """终端颜色"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

    @staticmethod
    def disable():
        Colors.RED = Colors.GREEN = Colors.YELLOW = ''
        Colors.BLUE = Colors.CYAN = Colors.RESET = Colors.BOLD = ''


def print_banner():
    """打印工具横幅"""
    print(f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗
║           Sysmon CLI - 应急响应工具箱                      ║
║                   v1.0 功能优先版                          ║
╚═══════════════════════════════════════════════════════════╝{Colors.RESET}
""")


def print_section(title):
    """打印分隔标题"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}[{title}]{Colors.RESET}")
    print("=" * 60)


def print_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")


def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")


def print_error(msg):
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")


def print_info(msg):
    print(f"{Colors.CYAN}[*]{Colors.RESET} {msg}")


# ==================== 功能命令 ====================

def cmd_processes(args):
    """列出进程"""
    print_section("进程列表")
    pm = ProcessManager()

    try:
        data = pm.get_process_tree()
        procs = data.get('all_procs', {})

        if args.filter:
            procs = {k: v for k, v in procs.items()
                    if args.filter.lower() in v.get('name', '').lower()}

        print(f"{'PID':<8} {'PPID':<8} {'进程名':<30} {'路径'}")
        print("-" * 100)

        for pid, info in sorted(procs.items(), key=lambda x: int(x[0])):
            name = info.get('name', 'N/A')[:30]
            ppid = info.get('ppid', 'N/A')
            path = info.get('path', '')[:50] if info.get('path') else ''
            print(f"{pid:<8} {ppid:<8} {name:<30} {path}")

        print(f"\n总计: {len(procs)} 个进程")

    except Exception as e:
        print_error(f"获取进程失败: {e}")


def cmd_network(args):
    """列出网络连接"""
    print_section("网络连接")
    nm = NetworkManager()

    try:
        connections = nm.get_all_connections()

        if args.listen:
            connections = [c for c in connections if c.get('status') == 'LISTEN']
        if args.established:
            connections = [c for c in connections if c.get('status') == 'ESTABLISHED']

        print(f"{'协议':<6} {'本地地址':<25} {'远程地址':<25} {'状态':<12} {'PID':<8} {'进程'}")
        print("-" * 110)

        for conn in connections:
            proto = conn.get('protocol', 'N/A')
            local = f"{conn.get('local_addr', '')}:{conn.get('local_port', '')}"[:25]
            remote = f"{conn.get('remote_addr', '')}:{conn.get('remote_port', '')}"[:25]
            status = conn.get('status', 'N/A')[:12]
            pid = conn.get('pid', 'N/A')
            name = conn.get('process_name', 'N/A')[:20]
            print(f"{proto:<6} {local:<25} {remote:<25} {status:<12} {pid:<8} {name}")

        print(f"\n总计: {len(connections)} 个连接")

    except Exception as e:
        print_error(f"获取网络连接失败: {e}")


def cmd_dll(args):
    """检查进程 DLL"""
    if not args.pid:
        print_error("请指定 PID: --pid <进程ID>")
        return

    print_section(f"DLL 列表 (PID: {args.pid})")
    dm = DLLManager()

    success, msg, dlls = dm.check_dll_injection(args.pid)

    if not success:
        print_error(msg)
        return

    # 标记可疑 DLL
    suspicious = []

    print(f"{'基址':<18} {'大小':<12} {'路径'}")
    print("-" * 100)

    for dll in dlls:
        base = dll.get('base', 'N/A')
        size = dll.get('size', 'N/A')
        path = dll.get('path', 'N/A')

        # 检查可疑特征
        is_suspicious = False
        if path and not path.lower().startswith('c:\\windows'):
            if not path.lower().startswith('c:\\program files'):
                is_suspicious = True

        if is_suspicious:
            suspicious.append(dll)
            print(f"{Colors.YELLOW}{base:<18} {size:<12} {path}{Colors.RESET}")
        else:
            print(f"{base:<18} {size:<12} {path}")

    print(f"\n总计: {len(dlls)} 个 DLL")
    if suspicious:
        print_warning(f"发现 {len(suspicious)} 个可疑 DLL（非系统目录）")


def cmd_handles(args):
    """查询进程句柄"""
    if not args.pid:
        print_error("请指定 PID: --pid <进程ID>")
        return

    print_section(f"句柄列表 (PID: {args.pid})")
    hm = HandleManager()

    filter_type = args.type if args.type else '全部'
    success, msg, handles = hm.query_handles(args.pid, filter_type)

    if not success:
        print_error(msg)
        return

    print(f"{'句柄':<10} {'类型':<15} {'名称'}")
    print("-" * 80)

    for h in handles[:100]:  # 限制输出
        handle = h.get('handle', 'N/A')
        htype = h.get('type', 'N/A')[:15]
        name = h.get('name', '')[:60]
        print(f"{handle:<10} {htype:<15} {name}")

    if len(handles) > 100:
        print(f"\n... 还有 {len(handles) - 100} 个句柄未显示")
    print(f"\n总计: {len(handles)} 个句柄")


def cmd_dump(args):
    """转储进程内存"""
    if not args.pid:
        print_error("请指定 PID: --pid <进程ID>")
        return

    print_section(f"内存转储 (PID: {args.pid})")
    dm = DumpManager()

    dump_type = args.type if args.type else 'mini'
    print_info(f"转储类型: {dump_type}")

    success, msg, filepath = dm.create_dump(args.pid, dump_type=dump_type)

    if success:
        print_success(msg)
        print_info(f"文件路径: {filepath}")
    else:
        print_error(msg)


def cmd_persistence(args):
    """检测持久化"""
    print_section("持久化检测")
    pd = PersistenceDetector()

    print_info("正在扫描启动项...")

    results = {
        '启动项': [],
        '服务': [],
        '计划任务': [],
        '注册表': []
    }

    # 获取启动项
    try:
        startups = pd.get_startup_items()
        results['启动项'] = startups
    except Exception as e:
        print_warning(f"获取启动项失败: {e}")

    # 获取服务
    try:
        services = pd.get_services()
        results['服务'] = [s for s in services if s.get('start_type') == 'auto']
    except Exception as e:
        print_warning(f"获取服务失败: {e}")

    # 打印结果
    for category, items in results.items():
        if items:
            print(f"\n{Colors.BOLD}[{category}] ({len(items)} 项){Colors.RESET}")
            for item in items[:20]:
                name = item.get('name', item.get('entry', 'N/A'))
                path = item.get('path', item.get('command', ''))
                print(f"  - {name}")
                if path:
                    print(f"    {Colors.CYAN}{path[:80]}{Colors.RESET}")

    total = sum(len(v) for v in results.values())
    print(f"\n总计发现 {total} 个持久化项")


def cmd_quick_scan(args):
    """快速安全扫描"""
    print_banner()
    print_section("快速安全扫描")
    print_info(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    issues = []

    # 1. 检查可疑进程
    print_info("检查进程...")
    pm = ProcessManager()
    try:
        data = pm.get_process_tree()
        procs = data.get('all_procs', {})

        suspicious_names = {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                          'mshta.exe', 'certutil.exe', 'bitsadmin.exe'}

        for pid, info in procs.items():
            name = info.get('name', '').lower()
            if name in suspicious_names:
                issues.append(f"可疑进程: {info.get('name')} (PID: {pid})")
    except:
        pass

    # 2. 检查网络连接
    print_info("检查网络连接...")
    nm = NetworkManager()
    try:
        connections = nm.get_all_connections()
        external_conns = [c for c in connections
                        if c.get('status') == 'ESTABLISHED'
                        and c.get('remote_addr')
                        and not c.get('remote_addr', '').startswith(('127.', '192.168.', '10.'))]

        if len(external_conns) > 20:
            issues.append(f"大量外部连接: {len(external_conns)} 个")
    except:
        pass

    # 3. 检查监听端口
    print_info("检查监听端口...")
    try:
        connections = nm.get_all_connections()
        listeners = [c for c in connections if c.get('status') == 'LISTEN']

        suspicious_ports = {4444, 5555, 6666, 7777, 8888, 1234, 31337}
        for conn in listeners:
            port = conn.get('local_port', 0)
            if port in suspicious_ports:
                issues.append(f"可疑监听端口: {port} ({conn.get('process_name', 'N/A')})")
    except:
        pass

    # 打印结果
    print_section("扫描结果")

    if issues:
        print_warning(f"发现 {len(issues)} 个潜在问题:")
        for issue in issues:
            print(f"  {Colors.YELLOW}!{Colors.RESET} {issue}")
    else:
        print_success("未发现明显异常")

    print_info("建议: 使用各子命令进行深入分析")


def cmd_watch(args):
    """监控文件夹变化"""
    import time
    from pathlib import Path

    watch_path = args.path
    if not os.path.isdir(watch_path):
        print_error(f"路径不存在或不是文件夹: {watch_path}")
        return

    print_section(f"文件夹监控: {watch_path}")
    print_info(f"开始监控，按 Ctrl+C 停止...")
    print_info(f"监控模式: {'递归' if args.recursive else '仅当前目录'}")
    print()

    # 记录初始状态
    def get_files(path, recursive=False):
        p = Path(path)
        pattern = '**/*' if recursive else '*'
        files = {}
        try:
            for f in p.glob(pattern):
                if f.is_file():
                    try:
                        stat = f.stat()
                        files[str(f)] = {
                            'size': stat.st_size,
                            'mtime': stat.st_mtime,
                            'ctime': stat.st_ctime
                        }
                    except:
                        pass
        except:
            pass
        return files

    previous_files = get_files(watch_path, args.recursive)
    print_info(f"初始文件数: {len(previous_files)}")
    print("-" * 60)

    created_count = 0
    modified_count = 0
    deleted_count = 0

    try:
        while True:
            time.sleep(args.interval)
            current_files = get_files(watch_path, args.recursive)

            # 检测新文件
            for filepath, info in current_files.items():
                if filepath not in previous_files:
                    created_count += 1
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"{Colors.GREEN}[{timestamp}] [新建] {filepath}{Colors.RESET}")
                    print(f"         大小: {info['size']} 字节")

                    # 尝试识别创建进程
                    try:
                        import psutil
                        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                            try:
                                open_files = proc.info.get('open_files') or []
                                for f in open_files:
                                    if filepath.lower() in f.path.lower():
                                        print(f"         {Colors.YELLOW}可能的创建进程: {proc.info['name']} (PID: {proc.info['pid']}){Colors.RESET}")
                                        break
                            except:
                                pass
                    except:
                        pass

                elif info['mtime'] != previous_files[filepath]['mtime']:
                    modified_count += 1
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"{Colors.YELLOW}[{timestamp}] [修改] {filepath}{Colors.RESET}")

            # 检测删除的文件
            for filepath in previous_files:
                if filepath not in current_files:
                    deleted_count += 1
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"{Colors.RED}[{timestamp}] [删除] {filepath}{Colors.RESET}")

            previous_files = current_files

    except KeyboardInterrupt:
        print()
        print_section("监控统计")
        print_info(f"新建文件: {created_count}")
        print_info(f"修改文件: {modified_count}")
        print_info(f"删除文件: {deleted_count}")


def cmd_fileinfo(args):
    """查看文件详细信息及打开它的进程"""
    filepath = args.path

    if not os.path.exists(filepath):
        print_error(f"文件不存在: {filepath}")
        return

    print_section(f"文件信息: {filepath}")

    # 文件基本信息
    stat = os.stat(filepath)
    print(f"大小: {stat.st_size:,} 字节")
    print(f"创建时间: {datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"修改时间: {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"访问时间: {datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')}")

    # 查找打开此文件的进程
    print_section("打开此文件的进程")

    try:
        import psutil
        found = False
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                open_files = proc.info.get('open_files') or []
                for f in open_files:
                    if os.path.normpath(filepath).lower() == os.path.normpath(f.path).lower():
                        found = True
                        print(f"  {Colors.YELLOW}PID: {proc.info['pid']:<8} 进程: {proc.info['name']}{Colors.RESET}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

        if not found:
            print_info("未找到打开此文件的进程")

    except Exception as e:
        print_error(f"查询失败: {e}")


def cmd_export(args):
    """导出报告"""
    print_section("导出系统报告")

    report = {
        'timestamp': datetime.now().isoformat(),
        'hostname': os.environ.get('COMPUTERNAME', 'Unknown'),
        'processes': [],
        'network': [],
        'persistence': []
    }

    # 收集进程
    print_info("收集进程信息...")
    try:
        pm = ProcessManager()
        data = pm.get_process_tree()
        report['processes'] = list(data.get('all_procs', {}).values())
    except Exception as e:
        print_warning(f"进程收集失败: {e}")

    # 收集网络
    print_info("收集网络连接...")
    try:
        nm = NetworkManager()
        report['network'] = nm.get_all_connections()
    except Exception as e:
        print_warning(f"网络收集失败: {e}")

    # 保存
    output_file = args.output if args.output else f"sysmon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print_success(f"报告已保存: {output_file}")


# ==================== 主入口 ====================

def main():
    parser = argparse.ArgumentParser(
        description='Sysmon CLI - 应急响应命令行工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s ps                     # 列出所有进程
  %(prog)s ps -f chrome           # 过滤进程名
  %(prog)s net -l                 # 只显示监听端口
  %(prog)s dll --pid 1234         # 查看进程 DLL
  %(prog)s handles --pid 1234     # 查看进程句柄
  %(prog)s dump --pid 1234        # 转储进程内存
  %(prog)s persist                # 检测持久化
  %(prog)s scan                   # 快速安全扫描
  %(prog)s export -o report.json  # 导出报告
  %(prog)s watch C:\\Temp -r      # 监控文件夹（检测病毒生成）
  %(prog)s fileinfo C:\\xxx.exe   # 查看文件信息及打开进程
        """
    )

    parser.add_argument('--no-color', action='store_true', help='禁用颜色输出')

    subparsers = parser.add_subparsers(dest='command', help='可用命令')

    # ps - 进程
    ps_parser = subparsers.add_parser('ps', help='列出进程')
    ps_parser.add_argument('-f', '--filter', help='过滤进程名')

    # net - 网络
    net_parser = subparsers.add_parser('net', help='列出网络连接')
    net_parser.add_argument('-l', '--listen', action='store_true', help='只显示监听')
    net_parser.add_argument('-e', '--established', action='store_true', help='只显示已建立连接')

    # dll - DLL检测
    dll_parser = subparsers.add_parser('dll', help='检查进程 DLL')
    dll_parser.add_argument('--pid', type=int, required=True, help='目标进程 PID')

    # handles - 句柄
    handles_parser = subparsers.add_parser('handles', help='查询进程句柄')
    handles_parser.add_argument('--pid', type=int, required=True, help='目标进程 PID')
    handles_parser.add_argument('-t', '--type', help='句柄类型过滤')

    # dump - 内存转储
    dump_parser = subparsers.add_parser('dump', help='转储进程内存')
    dump_parser.add_argument('--pid', type=int, required=True, help='目标进程 PID')
    dump_parser.add_argument('-t', '--type', choices=['mini', 'full'], default='mini', help='转储类型')

    # persist - 持久化检测
    persist_parser = subparsers.add_parser('persist', help='检测持久化机制')

    # scan - 快速扫描
    scan_parser = subparsers.add_parser('scan', help='快速安全扫描')

    # export - 导出
    export_parser = subparsers.add_parser('export', help='导出系统报告')
    export_parser.add_argument('-o', '--output', help='输出文件名')

    # watch - 文件夹监控
    watch_parser = subparsers.add_parser('watch', help='监控文件夹变化（检测病毒文件生成）')
    watch_parser.add_argument('path', help='要监控的文件夹路径')
    watch_parser.add_argument('-r', '--recursive', action='store_true', help='递归监控子文件夹')
    watch_parser.add_argument('-i', '--interval', type=float, default=1.0, help='检查间隔（秒），默认1秒')

    # fileinfo - 文件信息
    fileinfo_parser = subparsers.add_parser('fileinfo', help='查看文件信息及打开它的进程')
    fileinfo_parser.add_argument('path', help='文件路径')

    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    if not args.command:
        print_banner()
        parser.print_help()
        return

    # 执行命令
    commands = {
        'ps': cmd_processes,
        'net': cmd_network,
        'dll': cmd_dll,
        'handles': cmd_handles,
        'dump': cmd_dump,
        'persist': cmd_persistence,
        'scan': cmd_quick_scan,
        'export': cmd_export,
        'watch': cmd_watch,
        'fileinfo': cmd_fileinfo,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
