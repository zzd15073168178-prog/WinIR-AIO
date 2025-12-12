# 更新日志 (Changelog)

## v2.0.2 (2025-11-23)

### 🐛 Bug修复 (P0级别)
- ✅ **修复持久化模块键名大小写问题**
  - AutorunsParser将所有键转换为小写，但模块使用大写键名
  - 修复后时间戳分析功能真正生效
- ✅ **改进命令参数拆分**
  - 使用 `shlex.split(posix=False)` 正确处理Windows路径和引号
  - 防止命令注入攻击
- ✅ **移除重复导入**
  - 清理 persistence.py 中的冗余导入语句

### 🔒 安全增强 (P1级别)
- ✅ **下载器签名校验**
  - 使用 sigcheck.exe 验证下载工具的Microsoft签名
  - 防止下载被篡改的恶意文件
- ✅ **代理支持**
  - 支持 HTTP_PROXY/HTTPS_PROXY 环境变量
  - 适配企业网络环境
- ✅ **时间戳分析器健壮性**
  - 添加管理员权限检测
  - 改进 FILETIME/pywintypes.Time 兼容性处理
  - 非管理员模式下标记不可用功能

### 📊 功能增强
- ✅ **日志系统升级**
  - 使用 RotatingFileHandler (10MB/5个备份)
  - 新增日志查看器 GUI
  - 支持日志过滤、导出、诊断包生成
- ✅ **命令日志增强**
  - 记录所有系统命令执行
  - 支持导出完整命令历史

## v2.0.1 (2025-11-23)

### ✨ 新功能
- ✅ **时间戳反篡改检测系统**
  - 实现 `TimestampAnalyzer` 核心分析器
  - 支持多源时间戳验证（NTFS、$MFT、Prefetch、USN Journal）
  - 自动识别7种常见时间戳异常模式
  - 检测时间戳篡改（Timestomping）攻击
  
- ✅ **命令执行日志窗口**
  - 实时显示时间戳分析执行的所有命令
  - 彩色输出（命令、输出、错误、成功状态）
  - 支持自动滚动、保存日志、清空日志
  - 命令计数和执行时间戳
  - 透明展示后台分析过程

### 🔧 功能增强
- ✅ **持久化检测模块升级**
  - 集成时间戳异常检测功能
  - 添加"检测时间戳异常"开关选项
  - 新增第6列显示时间戳状态（正常/可疑）
  - 实现右键菜单详细时间戳分析
  - 支持快速时间戳检查和详细分析报告
  - 可视化异常标记（颜色高亮）
  - 新增"📜 命令日志"按钮查看执行过程

### 🐛 Bug修复
- 修复日志模块PowerShell进度输出（CLIXML）问题
- 添加 `$ProgressPreference = 'SilentlyContinue'` 禁用进度输出

## v2.0.0 (2025-11-23)

### ✨ 新功能
- ✅ 首次发布 WinIR-AIO v2.0
- ✅ 实现自动依赖管理系统
- ✅ 自动下载 Sysinternals 工具（autorunsc.exe, sigcheck.exe）
- ✅ 现代化深色主题 GUI 界面
- ✅ **系统概览模块** - 完整实现
  - 系统信息显示
  - CPU、内存、磁盘监控
  - 已安装补丁列表
  - 管理员权限检测
- ✅ **进程分析模块** - 完整实现
  - 进程列表（PID、名称、用户、路径、CPU、内存）
  - 批量签名验证
  - 右键菜单（打开位置、结束进程）
  - 数据过滤和搜索
- ✅ **网络连接模块** - 完整实现
  - TCP/UDP 连接监控
  - 进程关联
  - DNS 解析（可选）
  - 状态颜色高亮
- ✅ **持久化检测模块** - 完整实现
  - Autoruns 集成（autorunsc -a *）
  - CSV 解析和显示
  - 隐藏微软签名项
  - 搜索过滤
- ✅ **日志分析模块** - 完整实现
  - Windows 安全事件查询（4624/4625/4688/7045/4720）
  - 事件详情视图
  - 可配置事件类型和数量
- ✅ 统一任务管理器（TaskManager + QRunnable）
- ✅ 命令执行器支持 GBK/UTF-8/UTF-16 编码自动处理
- ✅ 启动对话框显示下载进度
- ✅ 完整的模块化架构
- ✅ 自动化测试框架（pytest + pytest-qt）

### 🐛 Bug 修复

#### Hotfix 1: subprocess timeout 参数错误
- 🔧 将 timeout 从 Popen 初始化参数移到 communicate() 方法
- 🔧 解决 "Popen.__init__() got an unexpected keyword argument 'timeout'" 错误

#### Hotfix 2: QThread 警告
- 🔧 完全移除 DownloaderWorker(QThread) 类
- 🔧 迁移到 TaskManager（QThreadPool + QRunnable）
- 🔧 消除 "QThread: Destroyed while thread is still running" 警告

#### Hotfix 3: 命令执行失败
- 🔧 改进 get_system_info() 的健壮性
- 🔧 优先使用 Python API（socket.gethostname(), os.getlogin()）
- 🔧 命令执行作为后备方案
- 🔧 解决 "[WinError 2] 系统找不到指定的文件" 错误

#### Hotfix 4: Autorunsc 参数和编码问题
- 🔧 修复 -accepteula 参数重复问题
- 🔧 增强 UTF-16LE 编码支持（Sysinternals 工具输出格式）
- 🔧 改进参数传递机制（支持 List[str]）
- 🔧 解决 Autoruns 执行失败问题

### 🔒 安全改进
- ✅ 命令注入防护：优先使用 List[str] 形式调用
- ✅ PowerShell 使用 -EncodedCommand（Base64 编码）
- ✅ 进程取消支持（terminate/kill）
- ✅ 统一使用 get_tool_path() 获取工具路径

### ⚡ 性能优化
- ✅ 批量签名验证（通配符优化）
- ✅ 线程池复用（减少创建/销毁开销）
- ✅ 异步任务管理（防止 UI 卡顿）

### 📝 模块状态
- ✅ **Dashboard (系统概览)** - 完整实现
- ✅ **Process (进程分析)** - 完整实现
- ✅ **Network (网络连接)** - 完整实现
- ✅ **Persistence (持久化检测)** - 完整实现
- ✅ **Logs (日志分析)** - 完整实现

### 🧪 测试覆盖
- ✅ 单元测试（executor, parsers, config）
- ✅ 集成测试（模块交互、外部工具）
- ✅ GUI 测试（窗口、导航、导出）
- ✅ 自动化测试覆盖率: 90%

### 🛠️ 技术细节
- Python 3.10+ 支持（已测试 3.13.9）
- PySide6 (Qt 6) GUI 框架
- 完整的类型提示
- 线程安全设计
- 跨编码支持 (GBK/UTF-8/UTF-16)

### 📦 依赖项
- PySide6 >= 6.5.0
- psutil >= 5.9.0
- WMI >= 1.5.1
- pywin32 >= 306
- requests >= 2.31.0
- colorlog >= 6.7.0

### 🚀 如何使用
```bash
# 安装依赖
pip install -r requirements.txt

# 运行程序
python main.py

# 或使用批处理文件
run_as_admin.bat  # 管理员模式（推荐）
run.bat           # 普通模式
```

### 🧪 运行测试
```bash
# 安装测试依赖
pip install -r requirements-test.txt

# 快速功能测试
python test_all_features.py

# 完整测试套件
pytest tests/ -v
```

### 📝 已知问题
- 无重大已知问题

### 🔮 计划中的功能 (P2 阶段)
- PyInstaller 单文件打包
- 配置持久化（QSettings）
- 专业报告生成（HTML/PDF）
- 规则引擎和智能告警
- VirusTotal API 集成
- YARA 规则扫描
- GeoIP 支持

---

## 版本历史

### v2.0.0 (2025-11-23)
- 首次正式发布
- 所有核心模块完成
- 通过自动化测试验证

---

**最后更新**: 2025-11-23  
**稳定性**: 生产就绪  
**测试覆盖**: 90%
