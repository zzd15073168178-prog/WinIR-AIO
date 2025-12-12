#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络管理模块
处理网络连接、IP地理位置查询等功能
"""

import psutil
import urllib.request
import json
import socket
from utils import is_suspicious_port, is_local_ip, is_suspicious_process_name
from constants import IP_LOCATION_API, IP_LOCATION_TIMEOUT


class NetworkManager:
    """网络管理器"""
    
    def __init__(self):
        self.connections = []
        self.ip_cache = {}  # IP地理位置缓存
    
    def get_all_connections(self):
        """获取所有网络连接"""
        connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                # 获取进程信息
                proc_name = ""
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "Unknown"
                
                # 本地地址
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                
                # 远程地址
                remote_addr = ""
                remote_ip = ""
                remote_port = ""
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    remote_addr = f"{remote_ip}:{remote_port}"
                
                # 协议类型
                protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                
                # 判断是否可疑
                is_suspicious = self.is_suspicious_connection(
                    proc_name, remote_ip, remote_port, conn.status
                )
                
                connections.append({
                    'protocol': protocol,
                    'local_addr': local_addr,
                    'remote_addr': remote_addr,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'status': conn.status,
                    'pid': conn.pid or 0,
                    'process': proc_name,
                    'process_name': proc_name,  # 添加 process_name 键以保持一致性
                    'is_suspicious': is_suspicious
                })
            except Exception:
                continue
        
        self.connections = connections
        return connections
    
    def is_suspicious_connection(self, proc_name, remote_ip, remote_port, status):
        """判断连接是否可疑"""
        # 如果没有远程地址，不算可疑
        if not remote_ip or not remote_port:
            return False
        
        # 如果是本地连接，不算可疑
        if is_local_ip(remote_ip):
            return False
        
        # 如果状态是LISTEN，不算可疑
        if status == 'LISTEN':
            return False
        
        # 检查可疑进程名
        if is_suspicious_process_name(proc_name):
            return True
        
        # 检查可疑端口
        if is_suspicious_port(remote_port):
            return True
        
        return False
    
    def get_ip_location(self, ip, verbose=False):
        """查询IP地理位置 - 支持多个备选API"""
        # 检查缓存
        if ip in self.ip_cache:
            return self.ip_cache[ip]

        # 跳过本地IP
        if is_local_ip(ip):
            return "本地"

        result = None

        # API 列表 (按优先级排序)
        apis = [
            self._query_ip_api,      # ip-api.com - 免费,支持中文,每分钟45次
            self._query_ipinfo,       # ipinfo.io - 免费,稳定,每月5万次
            self._query_ipwhois,      # ipwhois.app - 免费,无限制
        ]

        for api_func in apis:
            try:
                result = api_func(ip)
                if result and result != "查询失败":
                    break
            except:
                continue

        if not result:
            result = "查询失败"

        # 缓存结果
        self.ip_cache[ip] = result
        return result

    def _query_ip_api(self, ip):
        """使用 ip-api.com 查询 (支持中文)"""
        try:
            url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
            with urllib.request.urlopen(url, timeout=3) as response:
                data = json.loads(response.read().decode())
                if data.get('status') == 'success':
                    loc = f"{data.get('country', '')} {data.get('regionName', '')} {data.get('city', '')}"
                    isp = data.get('isp', '')
                    return f"{loc} ({isp})" if isp else loc
        except:
            pass
        return None

    def _query_ipinfo(self, ip):
        """使用 ipinfo.io 查询 (稳定可靠)"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            req = urllib.request.Request(url, headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                if 'country' in data:
                    country = data.get('country', '')
                    region = data.get('region', '')
                    city = data.get('city', '')
                    org = data.get('org', '')
                    loc = f"{country} {region} {city}".strip()
                    return f"{loc} ({org})" if org else loc
        except:
            pass
        return None

    def _query_ipwhois(self, ip):
        """使用 ipwhois.app 查询 (无速率限制)"""
        try:
            url = f"https://ipwhois.app/json/{ip}"
            with urllib.request.urlopen(url, timeout=3) as response:
                data = json.loads(response.read().decode())
                if data.get('success', True):  # ipwhois 成功时没有 success 字段或为 true
                    country = data.get('country', '')
                    region = data.get('region', '')
                    city = data.get('city', '')
                    isp = data.get('isp', '')
                    loc = f"{country} {region} {city}".strip()
                    return f"{loc} ({isp})" if isp else loc
        except:
            pass
        return None
    
    def get_connection_by_pid(self, pid):
        """获取指定进程的连接"""
        return [conn for conn in self.connections if conn['pid'] == pid]
    
    def get_suspicious_connections(self):
        """获取所有可疑连接"""
        return [conn for conn in self.connections if conn['is_suspicious']]
    
    def resolve_hostname(self, ip):
        """反向DNS解析"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None

    # 常见端口到服务/进程的映射
    WELL_KNOWN_PORTS = {
        # Web 相关
        80: ('HTTP', '浏览器/Web服务'),
        443: ('HTTPS', '浏览器/Web服务'),
        8080: ('HTTP代理', 'Web代理/应用服务器'),
        8443: ('HTTPS代理', 'Web代理/应用服务器'),
        # 邮件
        25: ('SMTP', '邮件发送'),
        110: ('POP3', '邮件接收'),
        143: ('IMAP', '邮件接收'),
        465: ('SMTPS', '加密邮件发送'),
        587: ('SMTP提交', '邮件发送'),
        993: ('IMAPS', '加密邮件接收'),
        995: ('POP3S', '加密邮件接收'),
        # 文件传输
        21: ('FTP', '文件传输'),
        22: ('SSH/SFTP', '安全Shell/文件传输'),
        69: ('TFTP', '简单文件传输'),
        # 数据库
        1433: ('MSSQL', 'SQL Server数据库'),
        1521: ('Oracle', 'Oracle数据库'),
        3306: ('MySQL', 'MySQL数据库'),
        5432: ('PostgreSQL', 'PostgreSQL数据库'),
        6379: ('Redis', 'Redis缓存'),
        27017: ('MongoDB', 'MongoDB数据库'),
        # 远程桌面
        3389: ('RDP', '远程桌面'),
        5900: ('VNC', 'VNC远程桌面'),
        # 即时通讯/流媒体
        5222: ('XMPP', '即时通讯'),
        5223: ('XMPP SSL', '加密即时通讯'),
        1935: ('RTMP', '流媒体'),
        # DNS
        53: ('DNS', 'DNS解析'),
        # 其他常见
        123: ('NTP', '时间同步'),
        161: ('SNMP', '网络管理'),
        389: ('LDAP', '目录服务'),
        636: ('LDAPS', '加密目录服务'),
        445: ('SMB', 'Windows文件共享'),
        139: ('NetBIOS', 'Windows网络'),
        # 代理/VPN
        1080: ('SOCKS', 'SOCKS代理'),
        1194: ('OpenVPN', 'VPN'),
        500: ('IKE', 'IPSec VPN'),
        4500: ('NAT-T', 'IPSec NAT穿越'),
        # 常见应用
        9000: ('常见应用端口', 'PHP-FPM/SonarQube等'),
        9090: ('管理界面', 'Prometheus/Cockpit等'),
    }

    # TCP 状态解释
    TCP_STATE_INFO = {
        'ESTABLISHED': ('活跃连接', '连接已建立，正在传输数据'),
        'LISTEN': ('监听中', '等待传入连接'),
        'TIME_WAIT': ('等待关闭', '连接已关闭，等待超时（原进程可能已退出）'),
        'CLOSE_WAIT': ('等待关闭', '对端已关闭，等待本地关闭（进程可能已退出）'),
        'LAST_ACK': ('最后确认', '等待最终ACK（原进程可能已退出）'),
        'FIN_WAIT1': ('关闭中', '已发送FIN，等待确认'),
        'FIN_WAIT2': ('关闭中', '已收到FIN确认，等待对端FIN'),
        'CLOSING': ('同时关闭', '双方同时关闭连接'),
        'SYN_SENT': ('连接中', '已发送SYN，等待响应'),
        'SYN_RECV': ('连接中', '已收到SYN，等待确认'),
        'NONE': ('无状态', 'UDP连接或状态未知'),
    }

    def get_port_info(self, port):
        """获取端口信息"""
        if port in self.WELL_KNOWN_PORTS:
            return self.WELL_KNOWN_PORTS[port]
        return None

    def get_state_info(self, state):
        """获取TCP状态解释"""
        return self.TCP_STATE_INFO.get(state, ('未知状态', state))

    def infer_process_from_port(self, local_port, remote_port, status):
        """根据端口推断可能的进程类型"""
        # 优先检查远程端口（外联连接）
        if remote_port:
            info = self.get_port_info(remote_port)
            if info:
                return f"[推断] {info[1]}"

        # 检查本地端口（服务端）
        if local_port:
            info = self.get_port_info(local_port)
            if info:
                return f"[推断] {info[1]}"

        return None

    def get_connection_analysis(self, conn):
        """获取连接的详细分析"""
        analysis = {}

        # 状态分析
        state = conn.get('status', '')
        state_info = self.get_state_info(state)
        analysis['state_name'] = state_info[0]
        analysis['state_desc'] = state_info[1]

        # 进程是否已退出
        pid = conn.get('pid', 0)
        process = conn.get('process', '')
        if pid == 0 or process in ('Unknown', '', 'System'):
            analysis['process_exited'] = True
            analysis['process_hint'] = '原进程可能已退出，连接处于残留状态'

            # 尝试推断
            local_port = conn.get('local_addr', '').split(':')[-1] if ':' in conn.get('local_addr', '') else None
            remote_port = conn.get('remote_port')
            try:
                local_port = int(local_port) if local_port else None
            except:
                local_port = None

            inferred = self.infer_process_from_port(local_port, remote_port, state)
            if inferred:
                analysis['inferred_process'] = inferred
        else:
            analysis['process_exited'] = False

        # 端口信息
        remote_port = conn.get('remote_port')
        if remote_port:
            port_info = self.get_port_info(remote_port)
            if port_info:
                analysis['remote_service'] = port_info[0]
                analysis['remote_service_desc'] = port_info[1]

        return analysis
    
    def get_connection_stats(self):
        """获取连接统计信息"""
        stats = {
            'total': len(self.connections),
            'tcp': 0,
            'udp': 0,
            'established': 0,
            'listen': 0,
            'suspicious': 0
        }
        
        for conn in self.connections:
            if conn['protocol'] == 'TCP':
                stats['tcp'] += 1
            else:
                stats['udp'] += 1
            
            if conn['status'] == 'ESTABLISHED':
                stats['established'] += 1
            elif conn['status'] == 'LISTEN':
                stats['listen'] += 1
            
            if conn['is_suspicious']:
                stats['suspicious'] += 1
        
        return stats

