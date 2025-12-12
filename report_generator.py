#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告生成模块
生成分析报告（HTML、JSON、文本格式）
"""

import json
import os
from datetime import datetime
from utils import ensure_directory, get_current_timestamp
from constants import REPORTS_DIR, HTML_REPORT_STYLE


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self):
        ensure_directory(REPORTS_DIR)
        self.report_data = {}
    
    def set_report_data(self, data):
        """设置报告数据"""
        self.report_data = data
    
    def generate_html_report(self, output_file=None):
        """生成HTML报告
        
        Args:
            output_file: 输出文件路径（可选）
        
        Returns:
            (success, message, file_path)
        """
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(REPORTS_DIR, f'report_{timestamp}.html')
        
        try:
            html_content = self._build_html_report()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return True, "HTML报告生成成功", output_file
            
        except Exception as e:
            return False, f"生成HTML报告失败: {str(e)}", None
    
    def generate_json_report(self, output_file=None):
        """生成JSON报告
        
        Args:
            output_file: 输出文件路径（可选）
        
        Returns:
            (success, message, file_path)
        """
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(REPORTS_DIR, f'report_{timestamp}.json')
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.report_data, f, ensure_ascii=False, indent=2)
            
            return True, "JSON报告生成成功", output_file
            
        except Exception as e:
            return False, f"生成JSON报告失败: {str(e)}", None
    
    def generate_text_report(self, output_file=None):
        """生成文本报告
        
        Args:
            output_file: 输出文件路径（可选）
        
        Returns:
            (success, message, file_path)
        """
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(REPORTS_DIR, f'report_{timestamp}.txt')
        
        try:
            text_content = self._build_text_report()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(text_content)
            
            return True, "文本报告生成成功", output_file
            
        except Exception as e:
            return False, f"生成文本报告失败: {str(e)}", None
    
    def _build_html_report(self):
        """构建HTML报告内容"""
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>恶意软件分析报告</title>
    {HTML_REPORT_STYLE}
</head>
<body>
    <h1>🔬 恶意软件分析报告</h1>
    
    <div class="info-box">
        <strong>生成时间：</strong>{get_current_timestamp()}<br>
        <strong>分析工具：</strong>Sysinternals Tools GUI
    </div>
    
    {self._build_summary_section()}
    {self._build_process_section()}
    {self._build_network_section()}
    {self._build_file_section()}
    {self._build_registry_section()}
    {self._build_persistence_section()}
    {self._build_iocs_section()}
    
</body>
</html>
"""
        return html
    
    def _build_summary_section(self):
        """构建摘要部分"""
        data = self.report_data.get('summary', {})
        
        return f"""
    <h2>📊 分析摘要</h2>
    <div class="summary">
        <div class="summary-item">
            <div class="summary-number">{data.get('file_operations', 0)}</div>
            <div class="summary-label">文件操作</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{data.get('registry_operations', 0)}</div>
            <div class="summary-label">注册表操作</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{data.get('network_connections', 0)}</div>
            <div class="summary-label">网络连接</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{data.get('persistence_mechanisms', 0)}</div>
            <div class="summary-label">持久化机制</div>
        </div>
    </div>
"""
    
    def _build_process_section(self):
        """构建进程信息部分"""
        processes = self.report_data.get('processes', [])
        
        if not processes:
            return "<h2>🔍 进程信息</h2>\n<p>无进程数据</p>\n"
        
        html = "<h2>🔍 进程信息</h2>\n<div class='data-table'>\n"
        html += "<table>\n<thead>\n<tr><th>PID</th><th>进程名</th><th>CPU%</th><th>内存(MB)</th><th>状态</th></tr>\n</thead>\n<tbody>\n"
        
        for proc in processes[:50]:  # 限制显示50个进程
            html += f"<tr><td>{proc.get('pid', 'N/A')}</td><td>{proc.get('name', 'N/A')}</td><td>{proc.get('cpu_percent', 'N/A')}</td><td>{proc.get('memory_mb', 'N/A')}</td><td>{proc.get('status', 'N/A')}</td></tr>\n"
        
        html += "</tbody>\n</table>\n</div>\n"
        
        if len(processes) > 50:
            html += f"<p>...以及其他 {len(processes) - 50} 个进程</p>\n"
        
        return html
    
    def _build_network_section(self):
        """构建网络活动部分"""
        network = self.report_data.get('network', [])
        
        if not network:
            return "<h2>🌐 网络活动</h2>\n<p>无网络数据</p>\n"
        
        html = "<h2>🌐 网络活动</h2>\n<div class='data-table'>\n"
        html += "<table>\n<thead>\n<tr><th>本地地址</th><th>远程地址</th><th>状态</th><th>PID</th></tr>\n</thead>\n<tbody>\n"
        
        for conn in network[:50]:  # 限制显示50个连接
            html += f"<tr><td>{conn.get('local_addr', 'N/A')}</td><td>{conn.get('remote_addr', 'N/A')}</td><td>{conn.get('status', 'N/A')}</td><td>{conn.get('pid', 'N/A')}</td></tr>\n"
        
        html += "</tbody>\n</table>\n</div>\n"
        
        if len(network) > 50:
            html += f"<p>...以及其他 {len(network) - 50} 个连接</p>\n"
        
        return html
    
    def _build_file_section(self):
        """构建文件活动部分"""
        files = self.report_data.get('files', [])
        
        if not files:
            return "<h2>📁 文件活动</h2>\n<p>无文件数据</p>\n"
        
        html = "<h2>📁 文件活动</h2>\n<div class='data-table'>\n"
        html += "<table>\n<thead>\n<tr><th>进程</th><th>操作</th><th>文件路径</th><th>结果</th></tr>\n</thead>\n<tbody>\n"
        
        for file_op in files[:50]:  # 限制显示50个文件操作
            html += f"<tr><td>{file_op.get('process', 'N/A')}</td><td>{file_op.get('operation', 'N/A')}</td><td>{file_op.get('path', 'N/A')}</td><td>{file_op.get('result', 'N/A')}</td></tr>\n"
        
        html += "</tbody>\n</table>\n</div>\n"
        
        if len(files) > 50:
            html += f"<p>...以及其他 {len(files) - 50} 个文件操作</p>\n"
        
        return html
    
    def _build_registry_section(self):
        """构建注册表活动部分"""
        registry = self.report_data.get('registry', [])
        
        if not registry:
            return "<h2>📝 注册表活动</h2>\n<p>无注册表数据</p>\n"
        
        html = "<h2>📝 注册表活动</h2>\n<div class='data-table'>\n"
        html += "<table>\n<thead>\n<tr><th>进程</th><th>操作</th><th>键路径</th><th>值</th></tr>\n</thead>\n<tbody>\n"
        
        for reg_op in registry[:50]:  # 限制显示50个注册表操作
            html += f"<tr><td>{reg_op.get('process', 'N/A')}</td><td>{reg_op.get('operation', 'N/A')}</td><td>{reg_op.get('key', 'N/A')}</td><td>{reg_op.get('value', 'N/A')}</td></tr>\n"
        
        html += "</tbody>\n</table>\n</div>\n"
        
        if len(registry) > 50:
            html += f"<p>...以及其他 {len(registry) - 50} 个注册表操作</p>\n"
        
        return html
    
    def _build_persistence_section(self):
        """构建持久化机制部分"""
        persistence = self.report_data.get('persistence', [])
        
        if not persistence:
            return "<h2>🔒 持久化机制</h2>\n<p>未检测到持久化机制</p>\n"
        
        html = "<h2>🔒 持久化机制</h2>\n<div class='alert alert-warning'>\n<p><strong>⚠️ 检测到以下持久化机制:</strong></p>\n<ul>\n"
        
        for mech in persistence:
            mech_type = mech.get('type', 'Unknown')
            location = mech.get('location', 'N/A')
            html += f"<li><strong>{mech_type}</strong>: {location}</li>\n"
        
        html += "</ul>\n</div>\n"
        
        return html
    
    def _build_iocs_section(self):
        """构建IOCs部分"""
        iocs = self.report_data.get('iocs', [])
        
        if not iocs:
            return "<h2>🚨 威胁指标 (IOCs)</h2>\n<p>未检测到威胁指标</p>\n"
        
        html = "<h2>🚨 威胁指标 (IOCs)</h2>\n<div class='alert alert-danger'>\n<p><strong>⚠️ 检测到以下威胁指标:</strong></p>\n<ul>\n"
        
        for ioc in iocs:
            ioc_type = ioc.get('type', 'Unknown')
            value = ioc.get('value', 'N/A')
            description = ioc.get('description', '')
            html += f"<li><strong>{ioc_type}</strong>: {value}"
            if description:
                html += f" - {description}"
            html += "</li>\n"
        
        html += "</ul>\n</div>\n"
        
        return html
    
    def _build_text_report(self):
        """构建文本报告内容"""
        text = f"""
{'='*80}
恶意软件分析报告
{'='*80}

生成时间: {get_current_timestamp()}
分析工具: Sysinternals Tools GUI

{'='*80}
分析摘要
{'='*80}

{self._build_text_summary()}

{'='*80}
详细信息
{'='*80}

{self._build_text_details()}

{'='*80}
报告结束
{'='*80}
"""
        return text
    
    def _build_text_summary(self):
        """构建文本摘要"""
        data = self.report_data.get('summary', {})
        return f"""
文件操作: {data.get('file_operations', 0)}
注册表操作: {data.get('registry_operations', 0)}
网络连接: {data.get('network_connections', 0)}
持久化机制: {data.get('persistence_mechanisms', 0)}
"""
    
    def _build_text_details(self):
        """构建文本详情"""
        details = []
        
        # 进程信息
        processes = self.report_data.get('processes', [])
        if processes:
            details.append("\n进程信息:")
            details.append("-" * 60)
            for proc in processes[:20]:  # 显示前20个
                details.append(f"PID: {proc.get('pid', 'N/A')}, Name: {proc.get('name', 'N/A')}, CPU: {proc.get('cpu_percent', 'N/A')}%, Memory: {proc.get('memory_mb', 'N/A')}MB")
        
        # 网络信息
        network = self.report_data.get('network', [])
        if network:
            details.append("\n网络连接:")
            details.append("-" * 60)
            for conn in network[:20]:  # 显示前20个
                details.append(f"Local: {conn.get('local_addr', 'N/A')} -> Remote: {conn.get('remote_addr', 'N/A')} [{conn.get('status', 'N/A')}]")
        
        # 文件操作
        files = self.report_data.get('files', [])
        if files:
            details.append("\n文件活动:")
            details.append("-" * 60)
            for file_op in files[:20]:  # 显示前20个
                details.append(f"{file_op.get('process', 'N/A')}: {file_op.get('operation', 'N/A')} -> {file_op.get('path', 'N/A')}")
        
        # 注册表操作
        registry = self.report_data.get('registry', [])
        if registry:
            details.append("\n注册表活动:")
            details.append("-" * 60)
            for reg_op in registry[:20]:  # 显示前20个
                details.append(f"{reg_op.get('process', 'N/A')}: {reg_op.get('operation', 'N/A')} -> {reg_op.get('key', 'N/A')}")
        
        # 持久化机制
        persistence = self.report_data.get('persistence', [])
        if persistence:
            details.append("\n持久化机制:")
            details.append("-" * 60)
            for mech in persistence:
                details.append(f"{mech.get('type', 'Unknown')}: {mech.get('location', 'N/A')}")
        
        # IOCs
        iocs = self.report_data.get('iocs', [])
        if iocs:
            details.append("\n威胁指标:")
            details.append("-" * 60)
            for ioc in iocs:
                details.append(f"{ioc.get('type', 'Unknown')}: {ioc.get('value', 'N/A')}")
        
        if not details:
            return "无详细信息"
        
        return "\n".join(details)

