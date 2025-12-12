# WinIR-AIO 自动化测试指南

## 概述

WinIR-AIO 使用 **pytest** 和 **pytest-qt** 提供全面的自动化测试，包括单元测试、集成测试和 GUI 测试。

## 快速开始

### 1. 安装测试依赖

```bash
pip install -r requirements-test.txt
```

### 2. 运行所有测试

**方法 A: 使用批处理脚本**
```bash
run_tests.bat
```

**方法 B: 使用 Python 脚本**
```bash
python run_tests.py
```

**方法 C: 直接使用 pytest**
```bash
pytest tests/ -v
```

## 测试类型

### 单元测试 (Unit Tests)
测试单个组件的功能，不依赖外部资源。

**运行单元测试**:
```bash
# 只运行单元测试
python run_tests.py unit

# 或
pytest tests/unit -v
```

**覆盖范围**:
- ✅ CommandRunner 命令执行
- ✅ 编码检测和转换
- ✅ CSV/JSON 解析器
- ✅ 配置管理
- ✅ 进程取消支持

### 集成测试 (Integration Tests)
测试模块间的交互和外部工具调用。

**运行集成测试**:
```bash
# 只运行集成测试
python run_tests.py integration

# 或
pytest tests/integration -v
```

**覆盖范围**:
- ✅ 进程数据采集
- ✅ 网络连接采集
- ✅ Autoruns 执行（需要 autorunsc.exe）
- ✅ 日志查询（需要管理员权限）
- ✅ 签名验证（需要 sigcheck.exe）
- ✅ TaskManager 任务执行

### GUI 测试 (GUI Tests)
测试用户界面组件和交互。

**运行 GUI 测试**:
```bash
# 只运行 GUI 测试
python run_tests.py gui

# 或
pytest tests/gui -v
```

**覆盖范围**:
- ✅ 主窗口创建
- ✅ 模块切换
- ✅ 侧边栏导航
- ✅ 导出功能
- ✅ 启动对话框

## 高级用法

### 按标记运行测试

```bash
# 只运行快速测试（排除 slow 标记）
pytest -m "not slow"

# 只运行需要管理员权限的测试
pytest -m requires_admin

# 只运行不需要网络的测试
pytest -m "not requires_network"
```

### 按关键字运行测试

```bash
# 运行所有包含 "executor" 的测试
pytest -k executor

# 运行所有包含 "parser" 的测试
pytest -k parser
```

### 生成覆盖率报告

```bash
# 生成 HTML 覆盖率报告
pytest --cov=src --cov-report=html

# 查看报告
start htmlcov/index.html  # Windows
```

### 并行执行测试

```bash
# 安装 pytest-xdist
pip install pytest-xdist

# 使用 4 个进程并行运行
pytest -n 4
```

## 测试标记说明

| 标记 | 说明 | 示例 |
|------|------|------|
| `unit` | 单元测试，快速，无外部依赖 | `@pytest.mark.unit` |
| `integration` | 集成测试，可能需要外部工具 | `@pytest.mark.integration` |
| `gui` | GUI 测试，需要 QApplication | `@pytest.mark.gui` |
| `slow` | 慢速测试（>5秒） | `@pytest.mark.slow` |
| `requires_admin` | 需要管理员权限 | `@pytest.mark.requires_admin` |
| `requires_network` | 需要网络连接 | `@pytest.mark.requires_network` |

## 测试结构

```
tests/
├── __init__.py
├── conftest.py              # 共享 fixtures
├── unit/                    # 单元测试
│   ├── test_config.py       # 配置测试
│   ├── test_executor.py     # 执行器测试
│   └── test_parsers.py      # 解析器测试
├── integration/             # 集成测试
│   └── test_modules.py      # 模块集成测试
└── gui/                     # GUI 测试
    └── test_main_window.py  # 主窗口测试
```

## 编写新测试

### 单元测试示例

```python
import pytest

class TestMyComponent:
    @pytest.mark.unit
    def test_basic_functionality(self):
        """Test basic functionality"""
        result = my_function()
        assert result == expected_value
```

### 集成测试示例

```python
@pytest.mark.integration
@pytest.mark.slow
def test_autorunsc_execution():
    """Test Autoruns execution"""
    from src.config import tool_exists
    
    if not tool_exists('autorunsc'):
        pytest.skip("autorunsc.exe not found")
    
    # Test logic here
```

### GUI 测试示例

```python
@pytest.mark.gui
def test_button_click(qtbot):
    """Test button click"""
    from PySide6.QtWidgets import QPushButton
    
    button = QPushButton("Click Me")
    qtbot.addWidget(button)
    
    clicked = []
    button.clicked.connect(lambda: clicked.append(True))
    
    # Simulate click
    qtbot.mouseClick(button, Qt.LeftButton)
    
    assert len(clicked) == 1
```

## 持续集成 (CI)

### GitHub Actions 示例

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install -r requirements-test.txt
      - run: pytest tests/unit -v
```

## 测试覆盖率目标

| 组件 | 当前覆盖率 | 目标覆盖率 |
|------|-----------|-----------|
| src/core/ | - | >80% |
| src/modules/ | - | >70% |
| src/ui/ | - | >60% |
| 总体 | - | >70% |

## 常见问题

### Q: 测试失败怎么办？
A: 查看详细输出，检查 `logs/test.log`，确保满足测试前置条件（如工具已下载、管理员权限等）。

### Q: GUI 测试失败？
A: GUI 测试可能对系统环境敏感，确保：
- 已安装 PySide6
- 系统支持图形界面
- 没有其他 QApplication 实例运行

### Q: 集成测试跳过？
A: 某些集成测试需要特定条件（如 Sysinternals 工具、管理员权限），跳过是正常的。

### Q: 如何调试失败的测试？
```bash
# 进入调试模式
pytest tests/unit/test_executor.py::TestCommandRunner::test_run_simple_command --pdb

# 显示 print 输出
pytest -s
```

## 最佳实践

1. **快速反馈**: 开发时先运行单元测试
   ```bash
   pytest tests/unit -v
   ```

2. **提交前**: 运行完整测试套件
   ```bash
   python run_tests.py
   ```

3. **性能测试**: 只运行快速测试
   ```bash
   pytest -m "not slow"
   ```

4. **特定模块**: 测试单个文件
   ```bash
   pytest tests/unit/test_executor.py -v
   ```

## 测试命令速查表

```bash
# 运行所有测试
pytest

# 只运行单元测试（快速）
pytest tests/unit

# 运行并生成覆盖率
pytest --cov=src --cov-report=html

# 只运行未标记为 slow 的测试
pytest -m "not slow"

# 运行特定测试
pytest tests/unit/test_executor.py::TestCommandRunner::test_run_simple_command

# 显示详细输出
pytest -v -s

# 失败时进入调试器
pytest --pdb

# 并行运行（需要 pytest-xdist）
pytest -n auto
```

## 贡献测试

如果您添加了新功能，请同时添加测试：

1. 在 `tests/unit/` 中添加单元测试
2. 在 `tests/integration/` 中添加集成测试（如果涉及多个组件）
3. 在 `tests/gui/` 中添加 GUI 测试（如果是 UI 功能）
4. 确保测试通过: `pytest tests/`

---

**文档版本**: v1.0  
**最后更新**: 2025-11-23

