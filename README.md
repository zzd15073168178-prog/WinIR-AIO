# 🛡️ Sysinternals Tools GUI

Windows 系统监控与恶意软件分析工具

---

## 🚀 快速开始

```
双击: 以管理员身份启动.bat
```

---

## ✨ 主要功能

- 📊 **进程管理** - 查看进程列表和进程树
- 🌐 **网络监控** - 监控网络连接，检测可疑连接
- 🔍 **DLL检测** - 检测DLL注入，右键查看详细信息、签名、属性
- 🗂️ **句柄查询** - 查询进程打开的句柄
- 💾 **进程转储** - 创建进程内存转储
- 📊 **Procmon监控** - 实时监控系统活动
- 🔬 **动态分析** - 恶意软件行为分析

---

## 📋 系统要求

- Windows 7/8/10/11
- Python 3.7+

### 安装

```bash
pip install -r requirements.txt
```

---

## 📁 项目结构

```
sysmon/
├── sysmon_gui_new.py          # 主程序
├── process_manager.py         # 进程管理
├── network_manager.py         # 网络管理
├── dll_manager.py             # DLL管理
├── handle_manager.py          # 句柄管理
├── dump_manager.py            # 转储管理
├── monitor_manager.py         # 监控管理
├── analysis_manager.py        # 分析管理
├── report_generator.py        # 报告生成
├── constants.py               # 常量配置
├── utils.py                   # 工具函数
├── Listdlls.exe               # Sysinternals工具
├── handle.exe                 # Sysinternals工具
├── procdump.exe               # Sysinternals工具
├── Procmon.exe                # Sysinternals工具
├── 启动.bat                   # 普通启动
├── 以管理员身份启动.bat       # 管理员启动
├── dumps/                     # 转储文件目录
├── procmon_logs/              # 监控日志目录
└── reports/                   # 分析报告目录
```

---

## 🎯 使用方法

### 基础功能（普通权限）
- 进程列表
- 进程树
- 网络连接

### 高级功能（管理员权限）
- DLL检测
- 句柄查询
- 进程转储
- Procmon监控
- 动态分析

---

## ⚠️ 注意事项

- 高级功能需要管理员权限
- 仅在虚拟机中分析恶意软件
- 定期清理日志文件

---

## 📚 文档

- `README_使用指南.md` - 详细使用指南
- `全面功能检查报告.md` - 系统检查报告

---

**技术栈**: Python + Tkinter + Sysinternals Tools  
**架构**: 模块化设计  
**用途**: 系统监控与恶意软件分析

