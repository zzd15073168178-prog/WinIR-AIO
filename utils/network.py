#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络操作模块
"""

from constants import SUSPICIOUS_PORTS


def is_suspicious_port(port):
    """判断端口是否可疑"""
    return int(port) in SUSPICIOUS_PORTS


def is_local_ip(ip):
    """判断是否为本地/保留IP (不需要查询地理位置)"""
    if not ip:
        return True

    # IPv4 私有/保留地址
    ipv4_local = (
        ip.startswith('127.') or        # 环回地址
        ip.startswith('192.168.') or    # 私有地址 C类
        ip.startswith('10.') or         # 私有地址 A类
        ip.startswith('172.16.') or     # 私有地址 B类
        ip.startswith('172.17.') or
        ip.startswith('172.18.') or
        ip.startswith('172.19.') or
        ip.startswith('172.2') or       # 172.20-29
        ip.startswith('172.30.') or
        ip.startswith('172.31.') or
        ip.startswith('169.254.') or    # 链路本地地址
        ip.startswith('198.18.') or     # IANA 基准测试保留
        ip.startswith('198.19.') or
        ip.startswith('100.64.') or     # 运营商级NAT
        ip == '0.0.0.0' or
        ip == '255.255.255.255'
    )

    # IPv6 本地/保留地址
    ipv6_local = (
        ip == '::1' or                  # 环回地址
        ip == '::' or                   # 未指定地址
        ip.startswith('fe80:') or       # 链路本地地址
        ip.startswith('fc') or          # 唯一本地地址 (ULA)
        ip.startswith('fd') or          # 唯一本地地址 (ULA)
        ip.startswith('::ffff:127.') or # IPv4映射的环回地址
        ip.startswith('::ffff:192.168.') or
        ip.startswith('::ffff:10.')
    )

    return ipv4_local or ipv6_local