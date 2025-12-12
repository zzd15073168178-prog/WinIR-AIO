#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threat Intelligence Module
公开威胁情报查询模块

支持的情报源 (全部免费):
- IP-API: 代理/VPN/托管检测
- AlienVault OTX: 开放威胁情报交换平台
- Feodo Tracker: 僵尸网络 C2 服务器
- URLhaus: 恶意软件分发IP

可选情报源 (需要API Key):
- AbuseIPDB: 滥用IP数据库
- VirusTotal: 恶意软件检测
"""

import requests
import time
import threading
from typing import Dict, Optional, Tuple, List, Set
from console_logger import console_log

# API Keys - 用户可以填写自己的 API Key
API_KEYS = {
    'abuseipdb': '',      # https://www.abuseipdb.com/ 注册获取
    'virustotal': '',     # https://www.virustotal.com/ 注册获取
}

QUERY_TIMEOUT = 5
_cache = {}
_cache_ttl = 3600

# 本地威胁黑名单缓存
_blacklist_cache = {
    'feodo_ips': set(),
    'urlhaus_ips': set(),
    'blocklist_ips': set(),
    'last_update': 0,
    'update_interval': 3600 * 6  # 6小时更新一次
}


def is_private_ip(ip: str) -> bool:
    """ 检查是否为私有/本地IP """
    if not ip:
        return True
    prefixes = ['10.', '127.', '192.168.', '172.16.', '172.17.', '172.18.',
                '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                '172.29.', '172.30.', '172.31.', '169.254.', '0.', '::']
    return any(ip.startswith(p) for p in prefixes) or ip in ['localhost', '::1']


# ============== 威胁情报黑名单源 ==============

def update_threat_blacklists(force: bool = False) -> bool:
    """更新威胁情报黑名单"""
    global _blacklist_cache
    
    now = time.time()
    if not force and (now - _blacklist_cache['last_update']) < _blacklist_cache['update_interval']:
        return True
    
    console_log("正在更新威胁情报黑名单...", "INFO")
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Feodo Tracker - 僵尸网络C2服务器
    try:
        r = requests.get('https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 
                        timeout=5, verify=False)
        if r.status_code == 200:
            ips = set()
            for line in r.text.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    ips.add(line)
            _blacklist_cache['feodo_ips'] = ips
            console_log(f"Feodo Tracker: 加载 {len(ips)} 个恶意IP", "INFO")
    except Exception as e:
        console_log(f"Feodo Tracker 更新失败 (跳过)", "WARNING")
    
    # URLhaus - 恶意软件分发IP (可选，如果失败就跳过)
    try:
        r = requests.get('https://urlhaus.abuse.ch/downloads/text_online/', 
                        timeout=5, verify=False)
        if r.status_code == 200:
            ips = set()
            import re
            for line in r.text.split('\n')[:1000]:  # 只取前1000行
                line = line.strip()
                if line and not line.startswith('#'):
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ips.add(ip_match.group(1))
            _blacklist_cache['urlhaus_ips'] = ips
            console_log(f"URLhaus: 加载 {len(ips)} 个恶意IP", "INFO")
    except Exception as e:
        console_log(f"URLhaus 更新失败 (跳过)", "WARNING")
    
    _blacklist_cache['last_update'] = now
    console_log("黑名单更新完成", "INFO")
    return True


def check_ip_in_blacklists(ip: str) -> List[str]:
    """检查IP是否在黑名单中"""
    if is_private_ip(ip):
        return []
    
    matches = []
    
    if ip in _blacklist_cache.get('feodo_ips', set()):
        matches.append('Feodo Tracker (僵尸网络C2)')
    
    if ip in _blacklist_cache.get('urlhaus_ips', set()):
        matches.append('URLhaus (恶意软件分发)')
    
    if ip in _blacklist_cache.get('blocklist_ips', set()):
        matches.append('Blocklist.de (攻击IP)')
    
    return matches


def query_ip_api(ip: str) -> Optional[Dict]:
    """ IP-API 查询 - 检测代理/VPN/托管 """
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,isp,org,country,city"
        r = requests.get(url, timeout=QUERY_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                risk = 0
                factors = []
                if data.get('proxy'):
                    risk += 2
                    factors.append('Proxy/VPN')
                if data.get('hosting'):
                    risk += 1
                    factors.append('Hosting/数据中心')
                return {
                    'source': 'IP-API',
                    'risk_score': min(risk, 4),
                    'factors': factors,
                    'country': data.get('country', ''),
                    'city': data.get('city', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', '')
                }
    except Exception as e:
        console_log(f"IP-API error: {e}", "ERROR")
    return None


def query_alienvault_otx(ip: str) -> Optional[Dict]:
    """
    AlienVault OTX 开放威胁情报查询 (完全免费)
    https://otx.alienvault.com/
    
    无需API Key即可使用基础查询功能
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        
        # AlienVault OTX 公开 API
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        
        if r.status_code == 200:
            data = r.json()
            
            # 获取威胁信息
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            pulses = data.get('pulse_info', {}).get('pulses', [])
            reputation = data.get('reputation', 0)
            
            # 计算风险分数
            risk = 0
            factors = []
            
            # 根据 pulse 数量判断风险
            if pulse_count > 0:
                if pulse_count >= 10:
                    risk = 4
                    factors.append(f'被{pulse_count}个威胁情报源收录')
                elif pulse_count >= 5:
                    risk = 3
                    factors.append(f'被{pulse_count}个威胁情报源收录')
                elif pulse_count >= 2:
                    risk = 2
                    factors.append(f'被{pulse_count}个威胁情报源收录')
                else:
                    risk = 1
                    factors.append(f'被{pulse_count}个威胁情报源收录')
                
                # 提取威胁标签
                tags = set()
                threat_types = set()
                for pulse in pulses[:5]:
                    pulse_tags = pulse.get('tags', [])
                    for tag in pulse_tags[:3]:
                        tags.add(tag)
                    # 检查威胁类型
                    name = pulse.get('name', '').lower()
                    if any(t in name for t in ['malware', 'trojan', 'botnet', 'c2', 'rat', 'backdoor']):
                        threat_types.add('恶意软件')
                        risk = max(risk, 4)
                    elif any(t in name for t in ['phishing', 'spam']):
                        threat_types.add('钓鱼/垃圾邮件')
                        risk = max(risk, 3)
                    elif any(t in name for t in ['miner', 'crypto']):
                        threat_types.add('挖矿')
                        risk = max(risk, 3)
                    elif any(t in name for t in ['scanner', 'scan', 'brute']):
                        threat_types.add('扫描/暴力破解')
                        risk = max(risk, 2)
                
                if tags:
                    factors.append(f'标签: {", ".join(list(tags)[:5])}')
                if threat_types:
                    factors.append(f'威胁类型: {", ".join(threat_types)}')
            
            # 信誉评分
            if reputation and reputation < 0:
                risk = max(risk, 3)
                factors.append(f'信誉评分: {reputation}')
            
            if risk > 0 or factors:
                return {
                    'source': 'AlienVault OTX',
                    'risk_score': risk,
                    'factors': factors,
                    'pulse_count': pulse_count,
                    'reputation': reputation
                }
                    
    except requests.exceptions.Timeout:
        console_log(f"AlienVault OTX查询超时: {ip}", "WARNING")
    except Exception as e:
        console_log(f"AlienVault OTX error: {e}", "ERROR")
    return None


def query_abuseipdb(ip: str) -> Optional[Dict]:
    """ AbuseIPDB 查询 - 滥用IP数据库 """
    api_key = API_KEYS.get('abuseipdb')
    if not api_key:
        return None
    
    try:
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        r = requests.get(url, headers=headers, timeout=QUERY_TIMEOUT)
        if r.status_code == 200:
            data = r.json().get('data', {})
            score = data.get('abuseConfidenceScore', 0)
            
            # 转换为0-4的风险等级
            if score >= 80:
                risk = 4
            elif score >= 50:
                risk = 3
            elif score >= 20:
                risk = 2
            elif score > 0:
                risk = 1
            else:
                risk = 0
            
            factors = []
            if score > 0:
                factors.append(f'被举报{data.get("totalReports", 0)}次')
            if data.get('isWhitelisted'):
                factors.append('白名单')
                risk = 0
            
            return {
                'source': 'AbuseIPDB',
                'risk_score': risk,
                'factors': factors,
                'abuse_score': score,
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode', ''),
                'isp': data.get('isp', ''),
                'usage_type': data.get('usageType', '')
            }
    except Exception as e:
        console_log(f"AbuseIPDB error: {e}", "ERROR")
    return None


def query_virustotal(ip: str) -> Optional[Dict]:
    """ VirusTotal 查询 - 恶意软件检测 """
    api_key = API_KEYS.get('virustotal')
    if not api_key:
        return None
    
    try:
        headers = {'x-apikey': api_key}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        r = requests.get(url, headers=headers, timeout=QUERY_TIMEOUT)
        if r.status_code == 200:
            data = r.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            # 转换为0-4的风险等级
            if malicious >= 5:
                risk = 4
            elif malicious >= 2:
                risk = 3
            elif malicious >= 1 or suspicious >= 2:
                risk = 2
            elif suspicious >= 1:
                risk = 1
            else:
                risk = 0
            
            factors = []
            if malicious > 0:
                factors.append(f'{malicious}个引擎检测为恶意')
            if suspicious > 0:
                factors.append(f'{suspicious}个引擎检测为可疑')
            
            return {
                'source': 'VirusTotal',
                'risk_score': risk,
                'factors': factors,
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': stats.get('harmless', 0)
            }
    except Exception as e:
        console_log(f"VirusTotal error: {e}", "ERROR")
    return None


def query_threat_intel(ip: str, use_cache: bool = True, deep_scan: bool = False) -> Dict:
    """
    查询IP威胁情报
    
    Args:
        ip: 要查询的IP地址
        use_cache: 是否使用缓存
        deep_scan: 是否进行深度扫描 (使用更多情报源)
    
    Returns:
        威胁情报结果字典
    """
    if is_private_ip(ip):
        return {
            'ip': ip, 
            'threat_level': 0, 
            'threat_text': '本地', 
            'sources': [], 
            'summary': '私有/本地IP',
            'blacklists': []
        }
    
    cache_key = f"{ip}_{deep_scan}"
    if use_cache and cache_key in _cache:
        cached = _cache[cache_key]
        if time.time() - cached['ts'] < _cache_ttl:
            return cached['data']
    
    results = []
    
    # 检查本地黑名单
    blacklist_matches = check_ip_in_blacklists(ip)
    
    # IP-API 查询 (免费)
    result = query_ip_api(ip)
    if result:
        results.append(result)
    
    # AlienVault OTX 威胁情报查询 (完全免费)
    otx_result = query_alienvault_otx(ip)
    if otx_result:
        results.append(otx_result)
    
    # 如果启用深度扫描，使用更多情报源
    if deep_scan:
        # AbuseIPDB
        abuse_result = query_abuseipdb(ip)
        if abuse_result:
            results.append(abuse_result)
        
        # VirusTotal
        vt_result = query_virustotal(ip)
        if vt_result:
            results.append(vt_result)
    
    # 计算最终风险等级
    if blacklist_matches:
        # 在黑名单中的IP直接标记为高风险
        final_risk = 4
    elif results:
        max_risk = max(r.get('risk_score', 0) for r in results)
        final_risk = max_risk
    else:
        final_risk = -1
    
    levels = {
        0: '安全', 
        1: '低风险', 
        2: '中风险', 
        3: '高风险', 
        4: '极高风险', 
        -1: '未知'
    }
    threat_text = levels.get(final_risk, '未知')
    
    # 生成摘要
    if blacklist_matches:
        summary = f'☢️ 在黑名单中: {', '.join(blacklist_matches)}'
    elif final_risk == -1:
        summary = '查询失败'
    elif final_risk == 0:
        summary = '未发现威胁'
    elif final_risk <= 1:
        summary = '低风险 - 正常流量'
    elif final_risk <= 2:
        summary = '中风险 - 建议关注'
    else:
        summary = '高风险 - 建议调查'
    
    # 汇总所有风险因素
    all_factors = []
    for r in results:
        all_factors.extend(r.get('factors', []))
    if blacklist_matches:
        all_factors.extend([f'黑名单: {m}' for m in blacklist_matches])
    
    data = {
        'ip': ip,
        'threat_level': final_risk,
        'threat_text': threat_text,
        'sources': results,
        'summary': summary,
        'blacklists': blacklist_matches,
        'factors': list(set(all_factors)),  # 去重
    }
    
    if use_cache:
        _cache[cache_key] = {'ts': time.time(), 'data': data}
    
    return data


def batch_query_ips(ips: List[str], deep_scan: bool = False, callback=None) -> Dict[str, Dict]:
    """
    批量查询IP威胁情报
    
    Args:
        ips: IP地址列表
        deep_scan: 是否进行深度扫描
        callback: 回调函数 callback(ip, result, progress)
    
    Returns:
        {ip: 威胁情报结果}
    """
    # 先更新黑名单 (静默失败)
    try:
        update_threat_blacklists()
    except Exception as e:
        console_log(f"更新黑名单失败: {e}", "WARNING")
    
    results = {}
    total = len(ips)
    queried = 0
    
    for i, ip in enumerate(ips):
        if is_private_ip(ip):
            continue
        
        try:
            console_log(f"正在查询: {ip} ({i+1}/{total})", "INFO")
            result = query_threat_intel(ip, use_cache=True, deep_scan=deep_scan)
            results[ip] = result
            queried += 1
            
            if callback:
                callback(ip, result, (i + 1) / total)
        except Exception as e:
            console_log(f"查询IP {ip} 失败: {e}", "ERROR")
            # 返回一个默认结果
            results[ip] = {
                'ip': ip,
                'threat_level': -1,
                'threat_text': '查询失败',
                'sources': [],
                'summary': str(e),
                'blacklists': [],
                'factors': []
            }
            if callback:
                callback(ip, results[ip], (i + 1) / total)
        
        # 避免请求过快触发限流
        time.sleep(0.3)
    
    console_log(f"批量查询完成: 共查询 {queried} 个IP", "INFO")
    return results


def get_threat_summary(results: Dict[str, Dict]) -> Dict:
    """获取威胁情报汇总"""
    summary = {
        'total': len(results),
        'safe': 0,
        'low': 0,
        'medium': 0,
        'high': 0,
        'critical': 0,
        'unknown': 0,
        'blacklisted': 0,
        'threats': []  # 威胁IP列表
    }
    
    for ip, data in results.items():
        level = data.get('threat_level', -1)
        if level == 0:
            summary['safe'] += 1
        elif level == 1:
            summary['low'] += 1
        elif level == 2:
            summary['medium'] += 1
        elif level == 3:
            summary['high'] += 1
            summary['threats'].append(data)
        elif level == 4:
            summary['critical'] += 1
            summary['threats'].append(data)
        else:
            summary['unknown'] += 1
        
        if data.get('blacklists'):
            summary['blacklisted'] += 1
    
    return summary


def get_threat_label(ip: str) -> Tuple[str, str]:
    """获取威胁标签和颜色"""
    if is_private_ip(ip):
        return ('本地', '#95A5A6')
    result = query_threat_intel(ip)
    level = result.get('threat_level', -1)
    colors = {
        0: '#2ECC71',   # 安全 - 绿色
        1: '#F1C40F',   # 低风险 - 黄色
        2: '#E67E22',   # 中风险 - 橙色
        3: '#E74C3C',   # 高风险 - 红色
        4: '#8E44AD',   # 极高风险 - 紫色
        -1: '#95A5A6'   # 未知 - 灰色
    }
    return (result.get('threat_text', '未知'), colors.get(level, '#95A5A6'))


def set_api_key(service: str, key: str):
    """设置API Key"""
    if service in API_KEYS:
        API_KEYS[service] = key
        console_log(f"{service} API Key 已设置", "INFO")


def get_available_sources() -> List[str]:
    """获取可用的情报源"""
    sources = ['IP-API', 'AlienVault OTX', 'Feodo Tracker', 'URLhaus']
    if API_KEYS.get('abuseipdb'):
        sources.append('AbuseIPDB')
    if API_KEYS.get('virustotal'):
        sources.append('VirusTotal')
    return sources

