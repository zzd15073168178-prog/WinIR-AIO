#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WMI持久化检测模块
"""

import subprocess


class WMIDetector:
    """WMI事件检测器"""
    
    def get_subscriptions(self):
        """获取WMI事件订阅"""
        subscriptions = []
        
        try:
            result = subprocess.run(
                ['wmic', '/namespace:\\\\root\\subscription', 'path', '__EventFilter', 'get', 'Name,Query', '/format:csv'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=20
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 3:
                            subscriptions.append({
                                'type': 'EventFilter',
                                'name': parts[1].strip(),
                                'query': parts[2].strip() if len(parts) > 2 else ''
                            })
        except subprocess.TimeoutExpired:
            print("[持久化检测] 获取WMI订阅超时")
        except Exception as e:
            print(f"[持久化检测] 获取WMI订阅失败: {e}")
        
        return subscriptions
    
    def get_consumers(self):
        """获取常见WMI事件消费者"""
        consumers = []
        consumer_types = [
            ('CommandLineEventConsumer', ['Name', 'CommandLineTemplate']),
            ('ActiveScriptEventConsumer', ['Name', 'ScriptFileName', 'ScriptText']),
            ('LogFileEventConsumer', ['Name', 'FileName', 'Text']),
            ('NTEventLogEventConsumer', ['Name', 'SourceName']),
        ]
        
        for consumer_type, fields in consumer_types:
            try:
                query_fields = ','.join(fields)
                result = subprocess.run(
                    ['wmic', '/namespace:\\\\root\\subscription', 'path', consumer_type, 'get', query_fields, '/format:csv'],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='ignore',
                    timeout=20
                )
                
                if result.returncode != 0:
                    continue
                
                lines = [line for line in result.stdout.strip().split('\n') if line.strip()]
                if len(lines) <= 1:
                    continue
                
                for line in lines[1:]:
                    parts = line.split(',')
                    if len(parts) < 2:
                        continue
                    
                    data = {}
                    for idx, field in enumerate(fields, start=1):
                        if idx < len(parts):
                            data[field] = parts[idx].strip('"')
                    entry_name = data.get('Name', f'{consumer_type}_unknown')
                    
                    consumers.append({
                        'type': consumer_type,
                        'name': entry_name,
                        'data': data
                    })
            except subprocess.TimeoutExpired:
                print(f"[持久化检测] 获取WMI消费者超时: {consumer_type}")
            except Exception as e:
                print(f"[持久化检测] 获取WMI消费者失败: {consumer_type}: {e}")
        
        return consumers
    
    def get_bindings(self):
        """获取Filter与Consumer的绑定关系"""
        bindings = []
        
        try:
            result = subprocess.run(
                ['wmic', '/namespace:\\\\root\\subscription', 'path', '__FilterToConsumerBinding', 'get', 'Filter,Consumer', '/format:csv'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=20
            )
            
            if result.returncode != 0:
                return bindings
            
            lines = [line for line in result.stdout.strip().split('\n') if line.strip()]
            if len(lines) <= 1:
                return bindings
            
            for line in lines[1:]:
                parts = line.split(',')
                if len(parts) < 3:
                    continue
                filter_name = parts[1].strip('"')
                consumer_name = parts[2].strip('"')
                bindings.append({
                    'filter': filter_name,
                    'consumer': consumer_name,
                    'binding': f"{filter_name}->{consumer_name}"
                })
        except subprocess.TimeoutExpired:
            print("[持久化检测] 获取WMI绑定超时")
        except Exception as e:
            print(f"[持久化检测] 获取WMI绑定失败: {e}")
        
        return bindings