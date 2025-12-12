# Sysmon CLI - 应急响应命令行工具使用说明

## 概述

Sysmon CLI 是一个专为应急响应场景设计的命令行工具，无需 GUI 依赖，可在任何 Windows 终端环境下快速使用。

## 运行方式

```bash
python sysmon_cli.py [命令] [选项]
```

## 全局选项

| 选项 | 说明 |
|------|------|
| `--no-color` | 禁用彩色输出（用于重定向到文件或不支持 ANSI 的终端） |
| `-h, --help` | 显示帮助信息 |

---

## 命令详解

### 1. `ps` - 进程列表

列出系统中所有运行的进程。

```bash
python sysmon_cli.py ps [选项]
```

**选项：**
| 选项 | 说明 |
|------|------|
| `-f, --filter <名称>` | 按进程名过滤（不区分大小写） |

**示例：**
```bash
# 列出所有进程
python sysmon_cli.py ps

# 只显示包含 "chrome" 的进程
python sysmon_cli.py ps -f chrome

# 查找 python 相关进程
python sysmon_cli.py ps -f python
```

**输出字段：**
- PID: 进程 ID
- PPID: 父进程 ID
- 进程名: 可执行文件名
- 路径: 可执行文件完整路径

---

### 2. `net` - 网络连接

显示当前系统的网络连接状态。

```bash
python sysmon_cli.py net [选项]
```

**选项：**
| 选项 | 说明 |
|------|------|
| `-l, --listen` | 只显示监听状态的端口 |
| `-e, --established` | 只显示已建立的连接 |

**示例：**
```bash
# 显示所有网络连接
python sysmon_cli.py net

# 只查看正在监听的端口
python sysmon_cli.py net -l

# 只查看已建立的连接（可能是恶意外连）
python sysmon_cli.py net -e
```

**输出字段：**
- 协议: TCP/UDP
- 本地地址: 本地 IP:端口
- 远程地址: 远程 IP:端口
- 状态: LISTEN/ESTABLISHED/TIME_WAIT 等
- PID: 对应进程 ID
- 进程: 进程名称

**应急响应场景：**
- 查找可疑的外部连接
- 发现异常监听端口（如 4444、31337 等）
- 定位恶意软件的网络行为

---

### 3. `dll` - DLL 检测

检查指定进程加载的 DLL 模块，识别可疑的 DLL 注入。

```bash
python sysmon_cli.py dll --pid <进程ID>
```

**必需参数：**
| 参数 | 说明 |
|------|------|
| `--pid <PID>` | 目标进程的 PID |

**示例：**
```bash
# 检查 PID 为 1234 的进程的 DLL
python sysmon_cli.py dll --pid 1234

# 先找到目标进程，再检查其 DLL
python sysmon_cli.py ps -f notepad
python sysmon_cli.py dll --pid 5678
```

**输出说明：**
- 基址: DLL 在内存中的加载地址
- 大小: DLL 占用的内存大小
- 路径: DLL 文件路径
- **黄色标记**: 非系统目录的 DLL（可疑）

**可疑 DLL 特征：**
- 不在 `C:\Windows` 目录下
- 不在 `C:\Program Files` 目录下
- 无数字签名
- 名称随机或仿冒系统 DLL

---

### 4. `handles` - 句柄查询

查询进程打开的句柄（文件、注册表、互斥体等）。

```bash
python sysmon_cli.py handles --pid <进程ID> [选项]
```

**参数：**
| 参数 | 说明 |
|------|------|
| `--pid <PID>` | 目标进程的 PID（必需） |
| `-t, --type <类型>` | 过滤句柄类型 |

**常见句柄类型：**
- `File` - 文件句柄
- `Key` - 注册表键
- `Mutant` - 互斥体（常用于恶意软件单例检测）
- `Process` - 进程句柄
- `Thread` - 线程句柄
- `Section` - 内存映射

**示例：**
```bash
# 查看进程所有句柄
python sysmon_cli.py handles --pid 1234

# 只查看文件句柄
python sysmon_cli.py handles --pid 1234 -t File

# 查看互斥体（检测恶意软件标识）
python sysmon_cli.py handles --pid 1234 -t Mutant
```

**应急响应场景：**
- 查找恶意软件的互斥体标识
- 发现进程正在访问的敏感文件
- 检测进程注入行为

---

### 5. `dump` - 内存转储

将进程内存转储为文件，用于后续分析。

```bash
python sysmon_cli.py dump --pid <进程ID> [选项]
```

**参数：**
| 参数 | 说明 |
|------|------|
| `--pid <PID>` | 目标进程的 PID（必需） |
| `-t, --type <类型>` | 转储类型：`mini`（默认）或 `full` |

**转储类型说明：**
- `mini`: 小型转储，包含基本信息和堆栈，文件较小
- `full`: 完整转储，包含所有内存内容，文件较大

**示例：**
```bash
# 快速小型转储
python sysmon_cli.py dump --pid 1234

# 完整内存转储（用于深度分析）
python sysmon_cli.py dump --pid 1234 -t full
```

**输出：**
- 转储文件保存在 `dumps/` 目录
- 文件名格式: `dump_<PID>_<时间戳>.dmp`

**后续分析工具：**
- WinDbg
- Volatility
- strings（提取字符串）

---

### 6. `persist` - 持久化检测

扫描系统中的持久化机制，发现恶意软件的驻留方式。

```bash
python sysmon_cli.py persist
```

**检测范围：**
- 启动项（注册表 Run 键、启动文件夹）
- 服务（自动启动的服务）
- 计划任务
- 其他注册表持久化位置

**示例：**
```bash
python sysmon_cli.py persist
```

**输出说明：**
- 按类别分组显示
- 显示名称和对应的命令/路径
- 重点关注非系统路径的启动项

---

### 7. `scan` - 快速安全扫描

一键执行快速安全检查，适合应急响应初期快速排查。

```bash
python sysmon_cli.py scan
```

**检查内容：**
1. **可疑进程检测**
   - cmd.exe, powershell.exe（可能被利用）
   - wscript.exe, cscript.exe（脚本宿主）
   - mshta.exe（HTML 应用宿主）
   - certutil.exe, bitsadmin.exe（LOLBins）

2. **网络连接检查**
   - 大量外部连接告警
   - 排除内网地址（127.x, 192.168.x, 10.x）

3. **可疑端口检测**
   - 4444（Metasploit 默认）
   - 5555, 6666, 7777, 8888
   - 1234, 31337（常见后门端口）

**示例：**
```bash
python sysmon_cli.py scan
```

---

### 8. `export` - 导出报告

将系统状态导出为 JSON 格式报告，便于存档和分析。

```bash
python sysmon_cli.py export [选项]
```

**选项：**
| 选项 | 说明 |
|------|------|
| `-o, --output <文件名>` | 指定输出文件名 |

**示例：**
```bash
# 自动生成文件名
python sysmon_cli.py export

# 指定文件名
python sysmon_cli.py export -o incident_report.json
```

**报告内容：**
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "hostname": "DESKTOP-ABC123",
  "processes": [...],
  "network": [...],
  "persistence": [...]
}
```

---

## 应急响应工作流程

### 1. 初步排查
```bash
# 快速扫描发现异常
python sysmon_cli.py scan
```

### 2. 深入分析
```bash
# 查看可疑进程详情
python sysmon_cli.py ps -f <可疑进程名>

# 检查网络外连
python sysmon_cli.py net -e

# 查看监听端口
python sysmon_cli.py net -l
```

### 3. 取证收集
```bash
# 检查可疑进程的 DLL
python sysmon_cli.py dll --pid <PID>

# 查看进程句柄
python sysmon_cli.py handles --pid <PID>

# 转储进程内存
python sysmon_cli.py dump --pid <PID> -t full
```

### 4. 持久化检查
```bash
# 扫描持久化机制
python sysmon_cli.py persist
```

### 5. 导出报告
```bash
# 导出完整报告
python sysmon_cli.py export -o incident_$(date +%Y%m%d).json
```

---

## 注意事项

1. **权限要求**: 部分功能需要管理员权限运行
2. **依赖工具**: DLL 检测需要 `Listdlls.exe`，句柄查询需要 `handle.exe`
3. **性能影响**: 完整内存转储可能需要较长时间
4. **输出重定向**: 使用 `--no-color` 选项可将输出重定向到文件

```bash
# 将结果保存到文件
python sysmon_cli.py ps --no-color > processes.txt
python sysmon_cli.py net --no-color > network.txt
```

---

## 版本信息

- 版本: v1.0
- 类型: 功能优先版
- 适用场景: Windows 应急响应
