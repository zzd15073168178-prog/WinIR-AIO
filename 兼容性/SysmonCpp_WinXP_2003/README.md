# Sysmon C++ 版本 - 编译说明

## 项目概述

这是 Sysmon 恶意软件分析工具的 C++ 重写版本，目标是支持 Windows Server 2003 及以上系统。

## 目录结构

```
SysmonCpp/
├── SysmonCpp.sln           # Visual Studio 解决方案
├── SysmonCore/             # 核心功能静态库
│   ├── include/
│   │   ├── targetver.h     # Windows 版本定义
│   │   ├── common.h        # 公共类型和工具函数
│   │   ├── process_manager.h
│   │   └── network_manager.h
│   ├── src/
│   │   ├── process_manager.cpp
│   │   └── network_manager.cpp
│   └── SysmonCore.vcxproj
├── SysmonGUI/              # GUI 可执行文件
│   ├── main.cpp            # 程序入口
│   ├── main_window.h/cpp   # 主窗口
│   ├── resource.h          # 资源定义
│   ├── SysmonGUI.manifest  # 应用清单
│   ├── tabs/
│   │   ├── base_tab.h/cpp      # Tab 基类
│   │   ├── process_tab.h/cpp   # 进程列表
│   │   └── network_tab.h/cpp   # 网络连接
│   └── SysmonGUI.vcxproj
└── Tools/                  # Sysinternals 工具 (需要手动复制)
```

## 编译要求

### 开发环境
- **Visual Studio 2019** 或 **Visual Studio 2022**
- **Windows SDK 10.0** 或更高版本

### 如需支持 Windows XP/Server 2003
需要安装 **Windows XP 工具集**：
1. 打开 Visual Studio Installer
2. 选择"修改"
3. 在"单个组件"中搜索 "XP"
4. 勾选 "C++ Windows XP Support for VS 20xx (v14x_xp)"
5. 安装后，修改项目属性中的"平台工具集"为 `v141_xp` 或 `v142_xp`

## 编译步骤

### 方法 1: 使用 Visual Studio IDE

1. 双击 `SysmonCpp.sln` 打开解决方案
2. 选择配置：
   - **Debug|Win32** - 32位调试版本
   - **Release|Win32** - 32位发布版本
   - **Debug|x64** - 64位调试版本
   - **Release|x64** - 64位发布版本
3. 菜单 → 生成 → 生成解决方案 (或按 F7)
4. 编译输出在 `bin\` 目录下

### 方法 2: 使用命令行

```batch
# 打开 Developer Command Prompt for VS 2022

# 编译 32 位 Release 版本
msbuild SysmonCpp.sln /p:Configuration=Release /p:Platform=Win32

# 编译 64 位 Release 版本
msbuild SysmonCpp.sln /p:Configuration=Release /p:Platform=x64
```

## 编译配置说明

### 关键编译选项

| 选项 | 值 | 说明 |
|------|-----|------|
| 字符集 | Unicode | 支持中文路径和文件名 |
| 运行时库 | /MT (静态链接) | 无需 VC Runtime |
| WINVER | 0x0501 | 目标 Windows XP/2003 |
| 子系统 | Windows | GUI 应用程序 |

### 链接的系统库

- `comctl32.lib` - Common Controls (ListView, Tab 等)
- `psapi.lib` - 进程状态 API
- `iphlpapi.lib` - IP Helper API (网络连接)
- `advapi32.lib` - 高级 API (安全、注册表)
- `shell32.lib` - Shell API
- `shlwapi.lib` - Shell 轻量级工具

## 功能列表

### 已实现 (P0 阶段)

- [x] 进程列表显示
- [x] 进程详情查看
- [x] 进程终止/挂起/恢复
- [x] 进程搜索和过滤
- [x] 可疑进程标记
- [x] 网络连接列表
- [x] 连接过滤 (协议/状态)
- [x] 可疑连接标记

### 待实现 (P1/P2 阶段)

- [ ] 进程树视图
- [ ] DLL 检测
- [ ] 句柄查询
- [ ] 内存扫描
- [ ] 持久化检测
- [ ] 事件日志分析
- [ ] Procmon 集成
- [ ] 报告生成

## 在旧系统上运行

### Windows Server 2003 / XP

1. 确保使用 XP 兼容工具集编译
2. 复制 `SysmonGUI.exe` 到目标系统
3. 以管理员身份运行

### 注意事项

- 某些功能在旧系统上可能受限（如 QueryFullProcessImageName）
- 程序会自动检测并使用兼容的 API
- 建议同时准备 32 位和 64 位版本

## 故障排除

### 编译错误

1. **找不到 Windows SDK**
   - 安装 Windows 10 SDK
   - 或在项目属性中修改 Windows SDK 版本

2. **链接错误 (LNK2019)**
   - 检查是否添加了所有必需的库
   - 确认 SysmonCore 项目先于 SysmonGUI 编译

### 运行错误

1. **程序无响应**
   - 确保以管理员身份运行
   - 检查是否有杀毒软件拦截

2. **部分功能不可用**
   - 某些功能需要特定权限
   - 检查 Windows 版本兼容性

## 后续开发

参考计划文件: `.claude/plans/recursive-launching-wadler.md`
