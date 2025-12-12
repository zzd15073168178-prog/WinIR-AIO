#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程管理模块
处理进程列表、进程树等功能
"""

import psutil
from utils import is_system_process, get_process_info, get_process_parent, get_process_children


class ProcessManager:
    """进程管理器"""
    
    def __init__(self):
        self.processes = []
        self.process_tree = {}
    
    def get_all_processes(self):
        """获取所有进程列表"""
        processes = []

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status', 'username']):
            try:
                info = proc.info

                # 获取用户名
                username = ""
                try:
                    username = info.get('username', '')
                except:
                    username = ""

                processes.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'cpu_percent': info['cpu_percent'] or 0.0,
                    'memory_mb': info['memory_info'].rss / 1024 / 1024 if info['memory_info'] else 0,
                    'status': info['status'],
                    'username': username,
                    'is_system': is_system_process(info['name'])
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.processes = processes
        return processes
    
    def get_process_tree(self):
        """构建进程树"""
        tree = {}
        
        # 首先获取所有进程
        all_procs = {}
        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                info = proc.info
                all_procs[info['pid']] = {
                    'pid': info['pid'],
                    'name': info['name'],
                    'ppid': info['ppid'],
                    'children': []
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # 构建父子关系
        for pid, proc_info in all_procs.items():
            ppid = proc_info['ppid']
            if ppid in all_procs:
                all_procs[ppid]['children'].append(pid)
        
        # 找出根进程（没有父进程或父进程不存在的）
        root_procs = []
        for pid, proc_info in all_procs.items():
            ppid = proc_info['ppid']
            if ppid == 0 or ppid not in all_procs:
                root_procs.append(pid)
        
        self.process_tree = {
            'all_procs': all_procs,
            'root_procs': root_procs
        }
        
        return self.process_tree
    
    def get_process_details(self, pid):
        """获取进程详细信息"""
        return get_process_info(pid)
    
    def kill_process(self, pid):
        """结束进程"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            return True, "进程已终止"
        except psutil.NoSuchProcess:
            return False, "进程不存在"
        except psutil.AccessDenied:
            return False, "权限不足，无法终止进程"
        except Exception as e:
            return False, f"终止进程失败: {str(e)}"
    
    def suspend_process(self, pid):
        """挂起进程"""
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            return True, "进程已挂起"
        except psutil.NoSuchProcess:
            return False, "进程不存在"
        except psutil.AccessDenied:
            return False, "权限不足，无法挂起进程"
        except Exception as e:
            return False, f"挂起进程失败: {str(e)}"
    
    def resume_process(self, pid):
        """恢复进程"""
        try:
            proc = psutil.Process(pid)
            proc.resume()
            return True, "进程已恢复"
        except psutil.NoSuchProcess:
            return False, "进程不存在"
        except psutil.AccessDenied:
            return False, "权限不足，无法恢复进程"
        except Exception as e:
            return False, f"恢复进程失败: {str(e)}"
    
    def get_process_connections(self, pid):
        """获取进程的网络连接"""
        try:
            proc = psutil.Process(pid)
            connections = []
            
            for conn in proc.connections(kind='inet'):
                connections.append({
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    'status': conn.status
                })
            
            return connections
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
    
    def get_process_threads(self, pid):
        """获取进程的线程信息"""
        try:
            proc = psutil.Process(pid)
            threads = []
            
            for thread in proc.threads():
                threads.append({
                    'id': thread.id,
                    'user_time': thread.user_time,
                    'system_time': thread.system_time
                })
            
            return threads
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
    
    def search_processes(self, keyword):
        """搜索进程"""
        if not keyword:
            return self.processes
        
        keyword_lower = keyword.lower()
        return [p for p in self.processes if keyword_lower in p['name'].lower() or keyword_lower in str(p['pid'])]

