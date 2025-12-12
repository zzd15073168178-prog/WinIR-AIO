#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows服务持久化检测模块
"""

import subprocess


class ServiceDetector:
    """Windows服务检测器"""
    
    def get_services(self):
        """获取所有Windows服务"""
        services = []
        
        try:
            result = subprocess.run(
                ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_service = {}
                
                for line in lines:
                    line = line.strip()
                    
                    if line.startswith('SERVICE_NAME:'):
                        if current_service:
                            details = self._get_service_details(current_service['name'])
                            current_service.update(details)
                            services.append(current_service)
                        current_service = {'name': line.split(':', 1)[1].strip()}
                    
                    elif line.startswith('DISPLAY_NAME:'):
                        current_service['display_name'] = line.split(':', 1)[1].strip()
                    
                    elif line.startswith('STATE'):
                        parts = line.split()
                        if len(parts) >= 3:
                            current_service['state'] = parts[3]
                
                if current_service:
                    details = self._get_service_details(current_service['name'])
                    current_service.update(details)
                    services.append(current_service)
        
        except subprocess.TimeoutExpired:
            print("[持久化检测] 获取服务列表超时")
        except Exception as e:
            print(f"[持久化检测] 获取服务列表失败: {e}")
        
        return services
    
    def _get_service_details(self, service_name):
        """获取服务的详细信息"""
        details = {
            'binary_path': '',
            'start_type': '',
            'service_type': ''
        }
        
        try:
            result = subprocess.run(
                ['sc', 'qc', service_name],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if 'BINARY_PATH_NAME' in line:
                        details['binary_path'] = line.split(':', 1)[1].strip()
                    elif 'START_TYPE' in line:
                        details['start_type'] = line.split(':', 1)[1].strip()
                    elif 'TYPE' in line and 'SERVICE_TYPE' in line:
                        details['service_type'] = line.split(':', 1)[1].strip()
        except Exception:
            pass
        
        return details