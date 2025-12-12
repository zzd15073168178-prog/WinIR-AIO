#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用户账户审计管理器
检测本地用户、隐藏账户、登录历史、RDP会话等
"""

import subprocess
import re
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import winreg


class UserAuditManager:
    """用户账户审计管理器"""

    def __init__(self):
        self.users = []
        self.login_history = []
        self.rdp_sessions = []
        self.hidden_users = []
        self.groups = []

    # ==================== 用户枚举 ====================

    def get_local_users(self) -> List[Dict]:
        """获取本地用户列表"""
        self.users = []

        try:
            # 使用 net user 命令
            result = subprocess.run(
                ['net', 'user'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                user_line_started = False
                user_names = []

                for line in lines:
                    if '----' in line:
                        user_line_started = True
                        continue
                    if user_line_started and line.strip():
                        if '命令成功完成' in line or 'successfully' in line.lower():
                            break
                        # 用户名可能在同一行，空格分隔
                        names = line.split()
                        user_names.extend(names)

                # 获取每个用户的详细信息
                for name in user_names:
                    if name:
                        user_info = self._get_user_detail(name)
                        if user_info:
                            self.users.append(user_info)

        except Exception as e:
            print(f"[用户审计] 获取用户列表失败: {e}")

        return self.users

    def _get_user_detail(self, username: str) -> Optional[Dict]:
        """获取单个用户的详细信息"""
        try:
            result = subprocess.run(
                ['net', 'user', username],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode != 0:
                return None

            info = {
                'name': username,
                'full_name': '',
                'comment': '',
                'active': True,
                'password_expires': '',
                'last_logon': '',
                'password_changeable': '',
                'password_required': True,
                'groups': [],
                'is_hidden': username.endswith('$'),
                'is_admin': False,
                'account_expires': '',
                'sid': '',
                'risk_level': 'normal'
            }

            output = result.stdout

            # 解析输出
            patterns = {
                'full_name': r'全名\s+(.+)',
                'comment': r'注释\s+(.+)',
                'active': r'帐户启用\s+(\S+)',
                'last_logon': r'上次登录\s+(.+)',
                'password_expires': r'密码到期\s+(.+)',
                'account_expires': r'帐户到期\s+(.+)',
                'password_changeable': r'密码可更改\s+(.+)',
                'password_required': r'需要密码\s+(\S+)',
            }

            # 英文系统模式
            patterns_en = {
                'full_name': r'Full Name\s+(.+)',
                'comment': r'Comment\s+(.+)',
                'active': r'Account active\s+(\S+)',
                'last_logon': r'Last logon\s+(.+)',
                'password_expires': r'Password expires\s+(.+)',
                'account_expires': r'Account expires\s+(.+)',
            }

            for key, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if key == 'active':
                        info['active'] = value.lower() in ['yes', '是']
                    elif key == 'password_required':
                        info['password_required'] = value.lower() in ['yes', '是']
                    else:
                        info[key] = value

            # 尝试英文模式
            for key, pattern in patterns_en.items():
                if not info.get(key):
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        value = match.group(1).strip()
                        if key == 'active':
                            info['active'] = value.lower() == 'yes'
                        else:
                            info[key] = value

            # 获取用户所属组
            groups_match = re.search(r'本地组成员\s+(.+?)(?:\n\S|$)', output, re.DOTALL)
            if not groups_match:
                groups_match = re.search(r'Local Group Memberships\s+(.+?)(?:\n\S|$)', output, re.DOTALL)

            if groups_match:
                groups_str = groups_match.group(1)
                groups = [g.strip().replace('*', '') for g in groups_str.split() if g.strip() and g != '*']
                info['groups'] = groups

                # 检查是否为管理员
                admin_groups = ['administrators', '管理员', 'admin']
                for g in groups:
                    if any(ag in g.lower() for ag in admin_groups):
                        info['is_admin'] = True
                        break

            # 获取 SID
            info['sid'] = self._get_user_sid(username)

            # 风险评估
            info['risk_level'] = self._assess_user_risk(info)

            return info

        except Exception as e:
            print(f"[用户审计] 获取用户详情失败 {username}: {e}")
            return None

    def _get_user_sid(self, username: str) -> str:
        """获取用户 SID"""
        try:
            result = subprocess.run(
                ['wmic', 'useraccount', 'where', f'name="{username}"', 'get', 'sid'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.split('\n') if l.strip() and 'SID' not in l.upper()]
                if lines:
                    return lines[0]
        except:
            pass
        return ''

    def _assess_user_risk(self, user_info: Dict) -> str:
        """评估用户风险等级"""
        risks = []

        # 隐藏账户（以$结尾）
        if user_info['is_hidden']:
            return 'critical'

        # 管理员但非默认账户
        if user_info['is_admin'] and user_info['name'].lower() not in ['administrator', '管理员']:
            risks.append('high')

        # 账户已禁用但存在
        if not user_info['active']:
            risks.append('info')

        # 密码不过期
        if user_info['password_expires'] and '永不' in user_info['password_expires']:
            risks.append('warning')
        if user_info['password_expires'] and 'never' in user_info['password_expires'].lower():
            risks.append('warning')

        # 不需要密码
        if not user_info['password_required']:
            risks.append('high')

        if 'critical' in risks:
            return 'critical'
        elif 'high' in risks:
            return 'high'
        elif 'warning' in risks:
            return 'warning'
        elif 'info' in risks:
            return 'info'
        return 'normal'

    # ==================== 隐藏账户检测 ====================

    def detect_hidden_users(self) -> List[Dict]:
        """检测隐藏账户"""
        self.hidden_users = []

        # 方法1: 检测 $ 结尾的账户
        for user in self.users:
            if user['name'].endswith('$'):
                self.hidden_users.append({
                    'name': user['name'],
                    'method': '$ 后缀隐藏',
                    'detail': user,
                    'severity': 'critical'
                })

        # 方法2: 检测注册表中的隐藏账户
        try:
            reg_hidden = self._check_registry_hidden_users()
            self.hidden_users.extend(reg_hidden)
        except Exception as e:
            print(f"[用户审计] 注册表检测失败: {e}")

        # 方法3: 对比 net user 和 SAM 注册表
        try:
            sam_users = self._get_sam_users()
            net_users = {u['name'].lower() for u in self.users}

            for sam_user in sam_users:
                if sam_user.lower() not in net_users and not sam_user.endswith('$'):
                    self.hidden_users.append({
                        'name': sam_user,
                        'method': 'SAM 隐藏（不在 net user 中）',
                        'detail': {'name': sam_user},
                        'severity': 'critical'
                    })
        except Exception as e:
            print(f"[用户审计] SAM 检测失败: {e}")

        return self.hidden_users

    def _check_registry_hidden_users(self) -> List[Dict]:
        """检查注册表中的隐藏用户设置"""
        hidden = []

        # 检查 Winlogon 的 SpecialAccounts\UserList
        try:
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if value == 0:  # 值为0表示隐藏
                            hidden.append({
                                'name': name,
                                'method': 'SpecialAccounts\\UserList 隐藏',
                                'detail': {'registry_value': 0},
                                'severity': 'critical'
                            })
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[用户审计] 检查 SpecialAccounts 失败: {e}")

        return hidden

    def _get_sam_users(self) -> List[str]:
        """从 SAM 注册表获取用户列表"""
        users = []
        try:
            # 需要 SYSTEM 权限才能访问 SAM
            key_path = r"SAM\SAM\Domains\Account\Users\Names"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, i)
                        users.append(name)
                        i += 1
                    except OSError:
                        break
        except PermissionError:
            print("[用户审计] 需要 SYSTEM 权限访问 SAM")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[用户审计] 访问 SAM 失败: {e}")

        return users

    # ==================== 登录历史 ====================

    def get_login_history(self, days: int = 30) -> List[Dict]:
        """获取登录历史（从事件日志）"""
        self.login_history = []

        # 使用 wevtutil 查询安全日志
        # 事件 ID 4624 = 成功登录, 4625 = 失败登录, 4634 = 注销
        event_ids = ['4624', '4625']

        for event_id in event_ids:
            try:
                # 计算时间范围
                start_time = datetime.now() - timedelta(days=days)
                time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S')

                query = f"*[System[(EventID={event_id}) and TimeCreated[@SystemTime>='{time_str}']]]"

                result = subprocess.run(
                    ['wevtutil', 'qe', 'Security', '/q:' + query, '/f:text', '/c:100'],
                    capture_output=True,
                    text=True,
                    encoding='gbk',
                    errors='ignore',
                    timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

                if result.returncode == 0 and result.stdout.strip():
                    events = self._parse_login_events(result.stdout, event_id)
                    self.login_history.extend(events)

            except subprocess.TimeoutExpired:
                print(f"[用户审计] 查询事件 {event_id} 超时")
            except Exception as e:
                print(f"[用户审计] 获取登录历史失败: {e}")

        # 按时间排序
        self.login_history.sort(key=lambda x: x.get('time', ''), reverse=True)

        return self.login_history

    def _parse_login_events(self, output: str, event_id: str) -> List[Dict]:
        """解析登录事件"""
        events = []
        current_event = {}

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('Event['):
                if current_event:
                    events.append(current_event)
                current_event = {
                    'event_id': event_id,
                    'type': '成功登录' if event_id == '4624' else '登录失败',
                    'time': '',
                    'user': '',
                    'domain': '',
                    'source_ip': '',
                    'logon_type': '',
                    'logon_type_desc': '',
                    'process': '',
                    'workstation': ''
                }
            elif ':' in line:
                key, _, value = line.partition(':')
                key = key.strip()
                value = value.strip()

                if key in ['Date', '日期']:
                    current_event['time'] = value
                elif key in ['帐户名', 'Account Name', '目标用户名']:
                    if not current_event['user'] or current_event['user'] == '-':
                        current_event['user'] = value
                elif key in ['帐户域', 'Account Domain', '目标域']:
                    current_event['domain'] = value
                elif key in ['源网络地址', 'Source Network Address']:
                    current_event['source_ip'] = value
                elif key in ['登录类型', 'Logon Type']:
                    current_event['logon_type'] = value
                    current_event['logon_type_desc'] = self._get_logon_type_desc(value)
                elif key in ['工作站名', 'Workstation Name']:
                    current_event['workstation'] = value
                elif key in ['进程名', 'Process Name']:
                    current_event['process'] = value

        if current_event:
            events.append(current_event)

        # 过滤系统账户
        filtered = []
        for e in events:
            user = e.get('user', '').lower()
            if user and user not in ['-', 'system', '系统', 'anonymous logon', '$']:
                if not user.endswith('$'):  # 过滤计算机账户
                    filtered.append(e)

        return filtered

    def _get_logon_type_desc(self, logon_type: str) -> str:
        """获取登录类型描述"""
        types = {
            '2': '交互式登录（本地）',
            '3': '网络登录',
            '4': '批处理登录',
            '5': '服务登录',
            '7': '解锁登录',
            '8': '网络明文登录',
            '9': '新凭据登录',
            '10': 'RDP 远程登录',
            '11': '缓存交互式登录',
            '12': '缓存远程交互式',
            '13': '缓存解锁'
        }
        return types.get(logon_type, f'类型 {logon_type}')

    # ==================== RDP 会话 ====================

    def get_rdp_sessions(self) -> List[Dict]:
        """获取 RDP 会话信息"""
        self.rdp_sessions = []

        try:
            # 使用 quser / query user 命令
            result = subprocess.run(
                ['query', 'user'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # 跳过标题行
                    if line.strip():
                        session = self._parse_quser_line(line)
                        if session:
                            self.rdp_sessions.append(session)
        except FileNotFoundError:
            # query user 可能不可用
            pass
        except Exception as e:
            print(f"[用户审计] 获取 RDP 会话失败: {e}")

        # 从注册表获取 RDP 连接历史
        try:
            rdp_history = self._get_rdp_connection_history()
            self.rdp_sessions.extend(rdp_history)
        except Exception as e:
            print(f"[用户审计] 获取 RDP 历史失败: {e}")

        return self.rdp_sessions

    def _parse_quser_line(self, line: str) -> Optional[Dict]:
        """解析 quser 输出行"""
        try:
            # 格式: USERNAME  SESSIONNAME  ID  STATE  IDLE TIME  LOGON TIME
            parts = line.split()
            if len(parts) >= 4:
                username = parts[0].replace('>', '')  # 当前用户有 > 前缀

                # 判断字段位置（有些字段可能为空）
                if parts[1].isdigit():
                    session_name = ''
                    session_id = parts[1]
                    state = parts[2] if len(parts) > 2 else ''
                else:
                    session_name = parts[1]
                    session_id = parts[2] if len(parts) > 2 else ''
                    state = parts[3] if len(parts) > 3 else ''

                return {
                    'type': 'active_session',
                    'username': username,
                    'session_name': session_name,
                    'session_id': session_id,
                    'state': state,
                    'is_rdp': 'rdp' in session_name.lower() or 'tcp' in session_name.lower()
                }
        except Exception as e:
            print(f"[用户审计] 解析会话行失败: {e}")
        return None

    def _get_rdp_connection_history(self) -> List[Dict]:
        """获取 RDP 连接历史（从当前用户注册表）"""
        history = []

        try:
            # 出站 RDP 连接历史
            key_path = r"Software\Microsoft\Terminal Server Client\Servers"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                i = 0
                while True:
                    try:
                        server = winreg.EnumKey(key, i)
                        # 获取用户名提示
                        try:
                            with winreg.OpenKey(key, server) as server_key:
                                username, _ = winreg.QueryValueEx(server_key, "UsernameHint")
                        except:
                            username = ''

                        history.append({
                            'type': 'rdp_outbound',
                            'server': server,
                            'username': username,
                            'description': f'RDP 出站连接到 {server}'
                        })
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[用户审计] 获取 RDP 历史失败: {e}")

        return history

    # ==================== 组信息 ====================

    def get_local_groups(self) -> List[Dict]:
        """获取本地组列表"""
        self.groups = []

        try:
            result = subprocess.run(
                ['net', 'localgroup'],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.startswith('*'):
                        group_name = line[1:].strip()
                        members = self._get_group_members(group_name)

                        self.groups.append({
                            'name': group_name,
                            'members': members,
                            'member_count': len(members),
                            'is_privileged': self._is_privileged_group(group_name)
                        })
        except Exception as e:
            print(f"[用户审计] 获取组列表失败: {e}")

        return self.groups

    def _get_group_members(self, group_name: str) -> List[str]:
        """获取组成员"""
        members = []
        try:
            result = subprocess.run(
                ['net', 'localgroup', group_name],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                started = False
                for line in lines:
                    if '----' in line:
                        started = True
                        continue
                    if started and line.strip():
                        if '命令成功完成' in line or 'successfully' in line.lower():
                            break
                        members.append(line.strip())
        except:
            pass

        return members

    def _is_privileged_group(self, group_name: str) -> bool:
        """判断是否为特权组"""
        privileged = [
            'administrators', '管理员',
            'domain admins', '域管理员',
            'enterprise admins', '企业管理员',
            'backup operators', '备份操作员',
            'remote desktop users', '远程桌面用户',
            'power users', '超级用户'
        ]
        return any(p in group_name.lower() for p in privileged)

    # ==================== 汇总报告 ====================

    def get_audit_summary(self) -> Dict:
        """获取审计摘要"""
        summary = {
            'total_users': len(self.users),
            'active_users': len([u for u in self.users if u['active']]),
            'admin_users': len([u for u in self.users if u['is_admin']]),
            'hidden_users': len(self.hidden_users),
            'high_risk_users': len([u for u in self.users if u['risk_level'] in ['critical', 'high']]),
            'recent_logins': len(self.login_history),
            'failed_logins': len([l for l in self.login_history if l['event_id'] == '4625']),
            'rdp_logins': len([l for l in self.login_history if l.get('logon_type') == '10']),
            'active_sessions': len([s for s in self.rdp_sessions if s.get('type') == 'active_session']),
            'privileged_groups': len([g for g in self.groups if g['is_privileged']])
        }
        return summary

    def run_full_audit(self) -> Dict:
        """执行完整审计"""
        print("[用户审计] 开始完整审计...")

        print("[用户审计] 获取本地用户...")
        self.get_local_users()

        print("[用户审计] 检测隐藏账户...")
        self.detect_hidden_users()

        print("[用户审计] 获取登录历史...")
        self.get_login_history(days=7)

        print("[用户审计] 获取 RDP 会话...")
        self.get_rdp_sessions()

        print("[用户审计] 获取本地组...")
        self.get_local_groups()

        print("[用户审计] 审计完成")

        return {
            'users': self.users,
            'hidden_users': self.hidden_users,
            'login_history': self.login_history,
            'rdp_sessions': self.rdp_sessions,
            'groups': self.groups,
            'summary': self.get_audit_summary()
        }


# ==================== 测试代码 ====================

if __name__ == '__main__':
    print("=" * 60)
    print("用户账户审计测试")
    print("=" * 60)

    manager = UserAuditManager()

    # 获取用户
    print("\n[1] 本地用户:")
    users = manager.get_local_users()
    for u in users:
        status = "启用" if u['active'] else "禁用"
        admin = " [管理员]" if u['is_admin'] else ""
        hidden = " [隐藏!]" if u['is_hidden'] else ""
        risk = f" [{u['risk_level']}]" if u['risk_level'] != 'normal' else ""
        print(f"  - {u['name']}: {status}{admin}{hidden}{risk}")

    # 隐藏账户
    print("\n[2] 隐藏账户检测:")
    hidden = manager.detect_hidden_users()
    if hidden:
        for h in hidden:
            print(f"  - {h['name']}: {h['method']}")
    else:
        print("  未发现隐藏账户")

    # 登录历史
    print("\n[3] 最近登录 (7天):")
    history = manager.get_login_history(days=7)
    for h in history[:10]:
        print(f"  - {h['time']}: {h['user']} ({h['type']}) {h['logon_type_desc']}")

    # 汇总
    print("\n[4] 审计摘要:")
    summary = manager.get_audit_summary()
    for k, v in summary.items():
        print(f"  - {k}: {v}")
