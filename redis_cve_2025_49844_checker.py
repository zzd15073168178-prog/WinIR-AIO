#!/usr/bin/env python3
"""
Redis CVE-2025-49844 漏洞批量检测脚本
检测 Redis Lua脚本远程代码执行漏洞

受影响版本:
- Redis < 6.2.20
- 7.2.0 ≤ Redis < 7.2.11
- 7.4.0 ≤ Redis < 7.4.6
- 8.0.0 ≤ Redis < 8.0.4
- 8.2.0 ≤ Redis < 8.2.2

使用方法:
1. 命令行指定IP: python redis_cve_2025_49844_checker.py -t 172.17.10.7
2. 从文件读取IP列表: python redis_cve_2025_49844_checker.py -f targets.txt
3. 指定端口: python redis_cve_2025_49844_checker.py -t 172.17.10.7 -p 6379
4. 带密码认证: python redis_cve_2025_49844_checker.py -t 172.17.10.7 -a password123
"""

import socket
import argparse
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


class RedisVersionChecker:
    def __init__(self, timeout=5, passwords=None):
        self.timeout = timeout
        self.passwords = passwords or []  # 密码列表，用于尝试多个密码

    def parse_version(self, version_str):
        """解析版本号为元组，便于比较"""
        try:
            # 处理类似 "6.2.14" 或 "7.2.5" 的版本号
            match = re.match(r'(\d+)\.(\d+)\.(\d+)', version_str)
            if match:
                return tuple(map(int, match.groups()))
        except:
            pass
        return None

    def is_vulnerable(self, version_str):
        """
        检查版本是否受漏洞影响

        受影响版本:
        - Redis < 6.2.20
        - 7.2.0 ≤ Redis < 7.2.11
        - 7.4.0 ≤ Redis < 7.4.6
        - 8.0.0 ≤ Redis < 8.0.4
        - 8.2.0 ≤ Redis < 8.2.2
        """
        version = self.parse_version(version_str)
        if not version:
            return None, "无法解析版本号"

        major, minor, patch = version

        # Redis < 6.2.20 (包括所有 6.x 早期版本)
        if major < 6:
            return True, f"版本 {version_str} < 6.2.20"

        if major == 6:
            if minor < 2:
                return True, f"版本 {version_str} < 6.2.20"
            if minor == 2 and patch < 20:
                return True, f"版本 {version_str} < 6.2.20"
            return False, f"版本 {version_str} >= 6.2.20 (已修复)"

        # 7.0.x 和 7.1.x 不在受影响范围内（根据公告）
        if major == 7:
            if minor < 2:
                # 7.0.x, 7.1.x 需要确认，保守起见标记为需要检查
                return None, f"版本 {version_str} 不在明确的受影响范围内，建议人工确认"

            # 7.2.0 ≤ Redis < 7.2.11
            if minor == 2:
                if patch < 11:
                    return True, f"版本 {version_str} 在受影响范围 7.2.0-7.2.10"
                return False, f"版本 {version_str} >= 7.2.11 (已修复)"

            # 7.3.x 不在受影响范围
            if minor == 3:
                return None, f"版本 {version_str} 不在明确的受影响范围内，建议人工确认"

            # 7.4.0 ≤ Redis < 7.4.6
            if minor == 4:
                if patch < 6:
                    return True, f"版本 {version_str} 在受影响范围 7.4.0-7.4.5"
                return False, f"版本 {version_str} >= 7.4.6 (已修复)"

            return None, f"版本 {version_str} 不在明确的受影响范围内，建议人工确认"

        # 8.x 版本
        if major == 8:
            # 8.0.0 ≤ Redis < 8.0.4
            if minor == 0:
                if patch < 4:
                    return True, f"版本 {version_str} 在受影响范围 8.0.0-8.0.3"
                return False, f"版本 {version_str} >= 8.0.4 (已修复)"

            # 8.1.x 不在受影响范围
            if minor == 1:
                return None, f"版本 {version_str} 不在明确的受影响范围内，建议人工确认"

            # 8.2.0 ≤ Redis < 8.2.2
            if minor == 2:
                if patch < 2:
                    return True, f"版本 {version_str} 在受影响范围 8.2.0-8.2.1"
                return False, f"版本 {version_str} >= 8.2.2 (已修复)"

            # 8.3+ 应该是已修复的
            return False, f"版本 {version_str} > 8.2.2 (已修复)"

        # 更高版本
        if major > 8:
            return False, f"版本 {version_str} 较新，应已修复"

        return None, "无法确定漏洞状态"

    def _try_get_version(self, host, port, password=None):
        """
        尝试用指定密码获取Redis版本
        返回: (success, version_or_error, need_auth)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            # 如果提供了密码，先进行认证
            if password:
                auth_cmd = f"AUTH {password}\r\n"
                sock.send(auth_cmd.encode())
                auth_response = sock.recv(1024).decode('utf-8', errors='ignore')
                if '-ERR' in auth_response:
                    sock.close()
                    return (False, "密码错误", False)

            # 发送 INFO server 命令获取版本
            sock.send(b"INFO server\r\n")
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"redis_version" in response or b"-NOAUTH" in response:
                        break
                except socket.timeout:
                    break

            sock.close()
            response_str = response.decode('utf-8', errors='ignore')

            # 检查是否需要认证
            if '-NOAUTH' in response_str or 'Authentication required' in response_str.lower():
                return (False, "需要密码认证", True)

            # 解析版本号
            version_match = re.search(r'redis_version:(\S+)', response_str)
            if version_match:
                return (True, version_match.group(1), False)
            else:
                return (False, "无法获取版本信息", False)

        except socket.timeout:
            return (False, "连接超时", False)
        except ConnectionRefusedError:
            return (False, "连接被拒绝", False)
        except Exception as e:
            return (False, str(e), False)

    def check_redis(self, host, port=6379, password=None):
        """
        连接Redis并获取版本信息，支持多密码尝试
        返回: (host, port, status, version, vulnerable, message)
        """
        # 构建要尝试的密码列表
        passwords_to_try = []
        if password:
            passwords_to_try.append(password)
        passwords_to_try.extend(self.passwords)

        # 先尝试无密码连接
        success, result, need_auth = self._try_get_version(host, port, None)

        if success:
            vulnerable, message = self.is_vulnerable(result)
            return (host, port, "SUCCESS", result, vulnerable, message)

        if not need_auth:
            # 不是认证问题，直接返回错误
            if "连接超时" in result:
                return (host, port, "TIMEOUT", None, None, result)
            elif "连接被拒绝" in result:
                return (host, port, "REFUSED", None, None, result)
            else:
                return (host, port, "ERROR", None, None, result)

        # 需要认证，尝试密码列表
        if not passwords_to_try:
            return (host, port, "NEED_AUTH", None, None, "需要密码认证")

        for pwd in passwords_to_try:
            success, result, _ = self._try_get_version(host, port, pwd)
            if success:
                vulnerable, message = self.is_vulnerable(result)
                return (host, port, "SUCCESS", result, vulnerable, f"{message} (密码: {pwd[:2]}***)")

        return (host, port, "NEED_AUTH", None, None, f"需要密码认证(已尝试{len(passwords_to_try)}个密码)")


def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║     Redis CVE-2025-49844 漏洞批量检测工具                         ║
║     Redis Lua脚本远程代码执行漏洞                                 ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_result(result, verbose=False):
    """打印单个检测结果"""
    host, port, status, version, vulnerable, message = result

    if status == "SUCCESS":
        if vulnerable is True:
            print(f"[!] 漏洞存在  {host}:{port} - Redis {version} - {message}")
        elif vulnerable is False:
            print(f"[√] 安全      {host}:{port} - Redis {version} - {message}")
        else:
            print(f"[?] 待确认   {host}:{port} - Redis {version} - {message}")
    elif status == "NEED_AUTH":
        print(f"[*] 需认证   {host}:{port} - {message}")
    elif verbose:
        print(f"[-] 失败     {host}:{port} - {message}")


def main():
    parser = argparse.ArgumentParser(
        description='Redis CVE-2025-49844 漏洞批量检测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s -t 172.17.10.7
  %(prog)s -t 172.17.10.7 -p 6379 -a mypassword
  %(prog)s -f targets.txt
  %(prog)s -f targets.txt -o result.txt
  %(prog)s -t 172.17.10.0/24 -p 6379
        '''
    )

    parser.add_argument('-t', '--target', help='目标IP地址，支持单个IP或CIDR格式(如 172.17.10.0/24)')
    parser.add_argument('-f', '--file', help='包含目标IP列表的文件(每行一个IP，可选端口如: 172.17.10.7:6379)')
    parser.add_argument('-p', '--port', type=int, default=6379, help='Redis端口 (默认: 6379)')
    parser.add_argument('-a', '--auth', help='Redis认证密码')
    parser.add_argument('-A', '--authfile', help='密码字典文件(每行一个密码，用于尝试多个密码)')
    parser.add_argument('-o', '--output', help='输出结果到文件')
    parser.add_argument('-w', '--workers', type=int, default=20, help='并发线程数 (默认: 20)')
    parser.add_argument('-T', '--timeout', type=int, default=5, help='连接超时秒数 (默认: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细输出(包括失败的连接)')

    args = parser.parse_args()

    if not args.target and not args.file:
        parser.print_help()
        print("\n错误: 请指定目标 (-t) 或目标文件 (-f)")
        sys.exit(1)

    print_banner()

    # 收集目标
    targets = []

    if args.target:
        if '/' in args.target:
            # CIDR 格式
            try:
                import ipaddress
                network = ipaddress.ip_network(args.target, strict=False)
                for ip in network.hosts():
                    targets.append((str(ip), args.port))
            except Exception as e:
                print(f"解析CIDR格式失败: {e}")
                sys.exit(1)
        else:
            targets.append((args.target, args.port))

    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if ':' in line:
                        host, port = line.rsplit(':', 1)
                        targets.append((host, int(port)))
                    else:
                        targets.append((line, args.port))
        except FileNotFoundError:
            print(f"文件不存在: {args.file}")
            sys.exit(1)

    if not targets:
        print("没有有效的目标")
        sys.exit(1)

    # 加载密码字典
    passwords = []
    if args.authfile:
        try:
            with open(args.authfile, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        passwords.append(line)
            print(f"[*] 已加载 {len(passwords)} 个密码")
        except FileNotFoundError:
            print(f"密码字典文件不存在: {args.authfile}")
            sys.exit(1)

    print(f"[*] 开始检测 {len(targets)} 个目标...")
    print(f"[*] 并发线程: {args.workers}, 超时: {args.timeout}秒")
    print("-" * 70)

    checker = RedisVersionChecker(timeout=args.timeout, passwords=passwords)
    results = []

    vulnerable_count = 0
    safe_count = 0
    need_auth_count = 0
    uncertain_count = 0
    failed_count = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(checker.check_redis, host, port, args.auth): (host, port)
            for host, port in targets
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print_result(result, args.verbose)

            host, port, status, version, vulnerable, message = result
            if status == "SUCCESS":
                if vulnerable is True:
                    vulnerable_count += 1
                elif vulnerable is False:
                    safe_count += 1
                else:
                    uncertain_count += 1
            elif status == "NEED_AUTH":
                need_auth_count += 1
            else:
                failed_count += 1

    # 打印统计
    print("-" * 70)
    print(f"\n[*] 检测完成 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"    总计: {len(targets)}")
    print(f"    存在漏洞: {vulnerable_count}")
    print(f"    安全: {safe_count}")
    print(f"    需认证: {need_auth_count}")
    print(f"    待确认: {uncertain_count}")
    print(f"    失败: {failed_count}")

    # 输出到文件
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(f"Redis CVE-2025-49844 漏洞检测报告\n")
            f.write(f"检测时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")

            f.write("【存在漏洞的主机】\n")
            for r in results:
                if r[4] is True:
                    f.write(f"  {r[0]}:{r[1]} - Redis {r[3]} - {r[5]}\n")

            f.write("\n【需要密码认证的主机】\n")
            for r in results:
                if r[2] == "NEED_AUTH":
                    f.write(f"  {r[0]}:{r[1]}\n")

            f.write("\n【待人工确认的主机】\n")
            for r in results:
                if r[2] == "SUCCESS" and r[4] is None:
                    f.write(f"  {r[0]}:{r[1]} - Redis {r[3]} - {r[5]}\n")

            f.write("\n【安全的主机】\n")
            for r in results:
                if r[4] is False:
                    f.write(f"  {r[0]}:{r[1]} - Redis {r[3]}\n")

            f.write(f"\n\n统计:\n")
            f.write(f"  总计: {len(targets)}\n")
            f.write(f"  存在漏洞: {vulnerable_count}\n")
            f.write(f"  安全: {safe_count}\n")
            f.write(f"  需认证: {need_auth_count}\n")
            f.write(f"  待确认: {uncertain_count}\n")
            f.write(f"  失败: {failed_count}\n")

        print(f"\n[*] 结果已保存到: {args.output}")

    # 如果有漏洞主机，返回非零退出码
    if vulnerable_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
