# WinIR-AIO - Windows Incident Response All-in-One Tool

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

## 📋 概述

WinIR-AIO 是一个综合性的 Windows 事件响应 GUI 工具，提供系统指纹识别、进程分析、持久化检测和日志分析等功能。该工具设计为单文件执行，自动管理外部依赖项，并优雅地处理 Windows 编码问题。

## ✨ 功能特性

- 🖥️ **系统概览** - 实时系统信息和状态监控
- 🔍 **进程分析** - 进程列表和数字签名验证
- 🌐 **网络监控** - TCP/UDP 连接监控
- 🔐 **持久化检测** - 使用 Autoruns 检测持久化机制
- 📝 **日志分析** - Windows 事件日志分析（登录事件等）
- 📥 **自动依赖管理** - 自动下载所需的 Sysinternals 工具
- 🎨 **现代 UI** - 基于 PySide6 的现代化深色主题界面

## 🚀 快速开始

### 系统要求

- Windows 10/11 或 Windows Server 2016+
- Python 3.10 或更高版本
- 管理员权限（推荐，以获得完整功能）

### 安装

1. **克隆或下载项目**
   ```bash
   git clone https://github.com/your-repo/WinIR-AIO.git
   cd WinIR-AIO
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **运行应用程序**
   ```bash
   python main.py
   ```

   首次运行时，应用程序会自动下载所需的 Sysinternals 工具。

### 以管理员身份运行

为了获得完整功能，建议以管理员身份运行：

1. 右键点击 `main.py` 或创建的快捷方式
2. 选择"以管理员身份运行"

## 📁 项目结构

```
WinIR_AIO/
├── main.py                 # 主入口点
├── requirements.txt        # Python 依赖
├── bin/                   # 下载的 Sysinternals 工具存储位置
├── assets/                # 图标和样式资源
├── logs/                  # 应用程序日志
├── src/
│   ├── config.py         # 配置和常量
│   ├── core/
│   │   ├── downloader.py # 工具下载器
│   │   ├── executor.py   # 命令执行器
│   │   └── parsers.py    # 输出解析器
│   ├── modules/          # 功能模块
│   │   ├── base_module.py
│   │   ├── dashboard.py
│   │   ├── process.py
│   │   ├── network.py
│   │   ├── persistence.py
│   │   └── logs.py
│   └── ui/              # UI 组件
│       ├── main_window.py
│       ├── startup_dialog.py
│       └── widgets/
└── README.md
```

## 🛠️ 技术栈

- **语言**: Python 3.10+
- **GUI 框架**: PySide6 (Qt for Python)
- **系统信息**: psutil, WMI, pywin32
- **外部工具**: Microsoft Sysinternals (自动下载)
  - autorunsc.exe - 启动项检测
  - sigcheck.exe - 数字签名验证
  - tcpview.exe - 网络连接查看

## 🔒 高级安全功能

### 时间戳反篡改检测 (v2.0.1)
WinIR-AIO 现在可以检测恶意软件常用的时间戳篡改技术（Timestomping）：

**检测方法**：
- 标准NTFS时间戳与$MFT记录比对
- Prefetch文件执行记录验证
- USN Journal变更日志分析
- 多源交叉验证

**异常模式识别**：
- 创建时间晚于修改时间
- 所有时间戳完全相同
- 未来时间戳
- 文件很旧但最近被访问
- Prefetch与文件时间戳不匹配
- MFT与标准时间戳差异

**使用方法**：
1. 在"持久化检测"模块中勾选"检测时间戳异常"
2. 刷新数据后查看第6列"时间戳状态"
3. 右键点击可疑项查看详细分析
4. 点击"📜 命令日志"按钮查看所有执行的系统命令

## 📖 使用指南

### 主界面

应用程序启动后，您会看到：
- **左侧导航栏** - 在不同模块间切换
- **主内容区** - 显示选中模块的内容
- **状态栏** - 显示当前状态和时间

### 模块功能

1. **系统概览**
   - 查看系统基本信息
   - CPU、内存、磁盘使用情况
   - 已安装的系统补丁

2. **进程分析**（开发中）
   - 列出所有运行中的进程
   - 验证进程数字签名
   - 识别可疑进程

3. **网络连接**（开发中）
   - 显示所有网络连接
   - 识别异常连接

4. **持久化检测**
   - 使用 autorunsc.exe 检测所有启动项
   - **时间戳反篡改检测** (v2.0.1新增)
     - 检测文件时间戳篡改（Timestomping）
     - 多源时间戳验证（NTFS、$MFT、Prefetch、USN Journal）
     - 自动识别7种常见异常模式
     - 右键菜单提供详细分析报告
   - 过滤微软签名项
   - 支持数据导出

5. **日志分析**
   - 分析 Windows 安全事件日志
   - 支持事件ID查询（4624登录成功、4625登录失败等）
   - JSON格式导出

### 导出数据

每个模块都支持数据导出：
1. 点击工具栏的"导出"按钮
2. 选择导出格式（CSV、JSON、HTML、TXT）
3. 选择保存位置

## ⚠️ 注意事项

1. **权限要求**: 某些功能需要管理员权限才能正常工作
2. **防病毒软件**: 某些防病毒软件可能会标记 Sysinternals 工具，请添加例外
3. **网络连接**: 首次运行需要网络连接以下载必要的工具
4. **编码问题**: 工具会自动处理中文 Windows 的编码问题

## 🤝 贡献

欢迎提交问题报告和功能建议！

## 📄 许可证

本项目采用 MIT 许可证。详见 LICENSE 文件。

## 🙏 致谢

- Microsoft Sysinternals 团队提供的优秀工具
- PySide6 和 Qt 项目
- psutil 和其他开源库的贡献者

## 📞 联系方式

如有问题或建议，请提交 Issue 或联系开发团队。

---

**注意**: 本工具仅供安全研究和事件响应使用。请遵守当地法律法规。
