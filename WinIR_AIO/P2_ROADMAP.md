# P2 阶段路线图 - WinIR-AIO v2.0

## 当前状态

### ✅ 已完成 (P0 & P1)
- ✅ 核心框架和配置系统
- ✅ 统一任务管理器 (QThreadPool + QRunnable)
- ✅ 增强的命令执行器（list 调用、取消支持、UTF-16 解码）
- ✅ 工具自动下载系统
- ✅ 系统概览模块（完整）
- ✅ 进程分析模块（完整 - 列表、签名验证、右键菜单）
- ✅ 网络连接模块（完整 - TCP/UDP、进程关联）
- ✅ 持久化检测模块（完整 - Autoruns 集成）
- ✅ 日志分析模块（完整 - 安全事件查询）

---

## P2 阶段目标

将工具从"可用"提升到"专业交付"和"生产就绪"水平。

---

## P2-1: 配置持久化系统 ⏱️ 预计 30 分钟

### 目标
记住用户偏好设置，提升用户体验。

### 任务清单
- [ ] 创建 `src/core/settings.py`
- [ ] 实现 `SettingsManager` 类（基于 QSettings）
- [ ] 保存的配置项：
  - 窗口大小和位置
  - 上次使用的导出目录
  - "隐藏微软签名项" 状态
  - 日志查询默认事件类型和数量
  - 代理设置（如果启用）
  - 主题偏好（如果支持多主题）
- [ ] 在主窗口中添加"设置"对话框
- [ ] 启动时加载配置，关闭时保存

### 文件结构
```
src/core/settings.py        # 配置管理器
src/ui/settings_dialog.py   # 设置对话框 UI（可选）
```

### 示例代码
```python
from PySide6.QtCore import QSettings

class SettingsManager:
    def __init__(self):
        self.settings = QSettings("CyberSecurity", "WinIR-AIO")
    
    def get(self, key, default=None):
        return self.settings.value(key, default)
    
    def set(self, key, value):
        self.settings.setValue(key, value)
```

---

## P2-2: 完善导出功能 ⏱️ 预计 30 分钟

### 目标
统一所有模块的数据导出，支持多种格式。

### 任务清单
- [ ] 创建 `src/core/exporters.py`
- [ ] 实现通用导出器：
  - `CSVExporter` - 通用 CSV 导出
  - `JSONExporter` - JSON 格式
  - `HTMLExporter` - HTML 表格（带样式）
- [ ] 更新所有模块的 `export_data()` 方法
- [ ] 添加"导出所有模块"功能
- [ ] 支持导出选中项（而非全部数据）

### 文件结构
```
src/core/exporters.py       # 导出工具类
```

---

## P2-3: PyInstaller 打包 ⏱️ 预计 1-2 小时

### 目标
生成独立的 Windows 可执行文件（EXE），方便在目标机器上使用。

### 任务清单
- [ ] 创建 `build.spec` 文件
- [ ] 处理特殊依赖：
  - PySide6 的 DLL 和插件
  - pywin32 的 COM 组件
  - requests 的 CA 证书
- [ ] 打包资源文件（assets/）
- [ ] 确保 bin/ 目录在运行时可写（用于下载工具）
- [ ] 创建 `build.bat` 构建脚本
- [ ] 测试打包后的 EXE
- [ ] 解决路径相关问题（`sys._MEIPASS`）

### 文件结构
```
build.spec                  # PyInstaller 配置
build.bat                   # Windows 构建脚本
dist/WinIR-AIO.exe         # 输出文件
```

### build.spec 示例
```python
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('assets', 'assets'),
        ('bin', 'bin'),
    ],
    hiddenimports=[
        'win32timezone',
        'psutil',
        'wmi',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='WinIR-AIO',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI 应用
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico'  # 如果有图标
)
```

---

## P2-4: 综合报告生成器 ⏱️ 预计 1-2 小时

### 目标
生成专业的事件响应报告，便于归档和提交。

### 任务清单
- [ ] 创建 `src/core/report_generator.py`
- [ ] 实现"一键取证"功能：
  - 自动运行所有模块
  - 收集数据快照
  - 打包成压缩文件
- [ ] HTML 报告模板：
  - 系统指纹信息
  - 可疑进程列表（未签名、异常路径）
  - 异常网络连接
  - 高风险启动项
  - 关键安全事件汇总
- [ ] 支持 PDF 导出（使用 `weasyprint` 或 `reportlab`）
- [ ] 在主窗口添加"生成报告"菜单项

### 文件结构
```
src/core/report_generator.py    # 报告生成器
assets/report_template.html     # HTML 报告模板
```

### 功能设计
```python
class ReportGenerator:
    def generate_snapshot(self) -> Dict:
        """采集所有模块数据"""
        return {
            'system': dashboard_data,
            'processes': process_data,
            'network': network_data,
            'persistence': autoruns_data,
            'logs': event_logs
        }
    
    def generate_html_report(self, snapshot, output_file):
        """生成 HTML 报告"""
        # 使用 Jinja2 或简单的字符串替换
    
    def export_forensics_package(self, output_zip):
        """导出完整取证包"""
        # 包含所有原始数据、报告、日志
```

---

## P2-5: 规则引擎与智能告警 ⏱️ 预计 2-3 小时

### 目标
自动识别可疑行为和已知 IOC（入侵指标）。

### 任务清单
- [ ] 创建 `src/core/rules.py`
- [ ] 定义规则格式（YAML/JSON）
- [ ] 实现规则引擎：
  - 进程规则（路径、签名、命令行模式）
  - 网络规则（IP、端口、协议）
  - 持久化规则（可疑位置、未知发布者）
  - 日志规则（爆破检测、权限提升）
- [ ] UI 集成：
  - 高亮违反规则的条目（红色/橙色背景）
  - "告警面板"显示所有触发的规则
  - 支持导入自定义规则文件
- [ ] 内置基础规则库

### 文件结构
```
src/core/rules.py               # 规则引擎
rules/builtin_rules.yaml        # 内置规则
rules/custom_rules.yaml         # 用户自定义
```

### 规则示例
```yaml
- name: "Process in Temp Directory"
  type: process
  severity: high
  condition:
    path_contains:
      - "\\AppData\\Local\\Temp\\"
      - "\\Users\\Public\\"
  action: highlight_red

- name: "Unsigned Process"
  type: process
  severity: medium
  condition:
    verified: false
    exclude_paths:
      - "C:\\Windows\\System32\\"
  action: highlight_orange

- name: "Brute Force Attempt"
  type: log
  severity: critical
  condition:
    event_id: 4625
    count_threshold: 10
    time_window: 300  # 5 minutes
  action: alert
```

---

## P2-6: 高级功能（可选）⏱️ 预计 3-5 小时

### VirusTotal 集成
- [ ] 在设置中添加 API Key 配置
- [ ] 右键菜单：查询文件哈希
- [ ] 显示检测结果和威胁分数

### YARA 规则扫描（可选）
- [ ] 集成 `yara-python`
- [ ] 内存扫描支持
- [ ] 文件扫描支持
- [ ] 内置常见恶意软件规则

### GeoIP 支持
- [ ] 下载 GeoLite2 数据库（免费版）
- [ ] 在网络模块中显示远程 IP 的国家/城市
- [ ] 高亮非常见地区的连接

---

## P2-7: UI/UX 优化 ⏱️ 预计 1-2 小时

### 任务清单
- [ ] 表格右键菜单扩展：
  - 复制行/单元格
  - 复制路径
  - 复制哈希
  - 在资源管理器中打开
- [ ] 表格列自定义：
  - 显示/隐藏列
  - 列宽度持久化
  - 列顺序调整
- [ ] 全局搜索：
  - 跨模块搜索
  - 高亮匹配项
- [ ] 快捷操作：
  - 快速过滤器按钮
  - 常用查询保存

---

## P2-8: 日志系统增强 ⏱️ 预计 30 分钟

### 任务清单
- [ ] 创建 `src/core/logging_config.py`
- [ ] 使用 `RotatingFileHandler`：
  - 按大小滚动（10 MB）
  - 保留最近 5 个文件
- [ ] 分模块 logger
- [ ] UI 增加"查看日志"功能
- [ ] "导出诊断包"（日志 + 配置）
- [ ] 支持日志级别调整（DEBUG/INFO/WARNING）

### 文件结构
```
src/core/logging_config.py      # 日志配置
logs/winir_20251123_143000.log  # 当前日志
logs/winir_20251123_143000.log.1 # 滚动日志
```

---

## P2-9: 文档与交付 ⏱️ 预计 1 小时

### 任务清单
- [ ] 用户手册（`docs/USER_MANUAL.md`）
- [ ] 开发者文档（`docs/DEVELOPER.md`）
- [ ] API 文档（使用 Sphinx 或 MkDocs）
- [ ] 视频教程（可选）
- [ ] 发布说明（Release Notes）

---

## 建议实施顺序

### 阶段 1: 基础增强 (1-2 小时)
1. **P2-8**: 日志系统增强 - 优先解决可观测性
2. **P2-1**: 配置持久化 - 提升用户体验
3. **P2-2**: 完善导出功能 - 完善现有功能

### 阶段 2: 打包与分发 (2-3 小时)
4. **P2-3**: PyInstaller 打包 - 生成可分发的 EXE
5. **P2-4**: 报告生成器 - 专业化输出

### 阶段 3: 高级功能 (3-5 小时)
6. **P2-5**: 规则引擎 - 智能分析
7. **P2-6**: 高级功能（VT/YARA/GeoIP）- 可选
8. **P2-7**: UI/UX 优化 - 提升操作效率

### 阶段 4: 文档与发布 (1-2 小时)
9. **P2-9**: 文档与交付 - 完成交付物

---

## 快速实施建议

### 如果时间有限，优先做：
1. **P2-8**: 日志系统（30 分钟）- 解决调试问题
2. **P2-3**: PyInstaller 打包（1 小时）- 便于分发
3. **P2-4**: 简化版报告（30 分钟）- 满足基本需求

### 如果想做完整版：
按照"建议实施顺序"逐步完成所有任务。

---

## 成功标准

### P2 阶段完成后，WinIR-AIO 应该具备：
- ✅ 单文件 EXE 分发
- ✅ 配置持久化
- ✅ 完整的数据导出
- ✅ 专业报告生成
- ✅ 智能规则告警
- ✅ 完整的文档
- ✅ 生产环境可用的日志系统

---

## 当前可以开始的任务

由于核心功能已全部完成且测试通过，您现在可以：

### 选项 A: 立即使用当前版本
- 程序已完全可用
- 五大核心模块全部就绪
- 适合内部使用和测试

### 选项 B: 开始 P2 增强
- 从 P2-8（日志系统）开始
- 然后做 P2-1（配置）和 P2-2（导出）
- 最后做打包和报告

### 选项 C: 直接打包分发
- 跳到 P2-3（PyInstaller）
- 快速生成可分发版本
- 后续再补充其他功能

---

## 我的建议

建议您先**测试当前版本**的所有功能：

1. **系统概览** - 查看系统信息
2. **进程分析** - 刷新列表，尝试"验证签名"
3. **网络连接** - 查看 TCP/UDP 连接
4. **持久化检测** - 运行 Autoruns（注意：可能需要 30-60 秒）
5. **日志分析** - 查询安全事件（4624/4625）

如果一切正常，再决定是否需要 P2 功能。

---

您希望：
- **A**: 继续测试当前功能
- **B**: 开始 P2-8（日志系统）
- **C**: 开始 P2-3（打包）
- **D**: 其他具体需求

请告诉我您的选择！🚀

