// main_window.h - 主窗口
#pragma once

#include "../SysmonCore/include/common.h"
#include "../SysmonCore/include/process_manager.h"
#include "../SysmonCore/include/network_manager.h"
#include "../SysmonCore/include/dll_manager.h"
#include "../SysmonCore/include/handle_manager.h"
#include "../SysmonCore/include/memory_scanner.h"
#include "../SysmonCore/include/hash_manager.h"
#include "../SysmonCore/include/persistence_detector.h"
#include "../SysmonCore/include/eventlog_manager.h"
#include "../SysmonCore/include/dump_manager.h"
#include "../SysmonCore/include/monitor_manager.h"
#include "../SysmonCore/include/security_manager.h"
#include "../SysmonCore/include/file_locker.h"
#include "../SysmonCore/include/yara_scanner.h"
#include "../SysmonCore/include/report_generator.h"
#include "resource.h"
#include <commctrl.h>

// 前向声明
class BaseTab;
class ProcessTab;
class NetworkTab;
class DllTab;
class HandleTab;
class MemoryScannerTab;
class HashTab;
class PersistenceTab;
class EventLogTab;
class DumpTab;
class MonitorTab;
class SecurityTab;
class FileLockerTab;
class YaraTab;
class ReportTab;

class MainWindow {
public:
    MainWindow(HINSTANCE hInstance);
    ~MainWindow();

    // 创建并显示主窗口
    bool Create(int nCmdShow);

    // 消息循环
    int Run();

    // 获取实例
    static MainWindow* GetInstance() { return s_instance; }

    // 获取窗口句柄
    HWND GetHwnd() const { return m_hWnd; }
    HINSTANCE GetHInstance() const { return m_hInstance; }

    // 获取管理器
    ProcessManager* GetProcessManager() { return &m_processManager; }
    NetworkManager* GetNetworkManager() { return &m_networkManager; }
    DLLManager* GetDLLManager() { return &m_dllManager; }
    HandleManager* GetHandleManager() { return &m_handleManager; }
    MemoryScanner* GetMemoryScanner() { return &m_memoryScanner; }
    HashManager* GetHashManager() { return &m_hashManager; }
    PersistenceDetector* GetPersistenceDetector() { return &m_persistenceDetector; }
    EventLogManager* GetEventLogManager() { return &m_eventLogManager; }
    DumpManager* GetDumpManager() { return &m_dumpManager; }
    MonitorManager* GetMonitorManager() { return &m_monitorManager; }
    SecurityManager* GetSecurityManager() { return &m_securityManager; }
    FileLocker* GetFileLocker() { return &m_fileLocker; }
    YaraScanner* GetYaraScanner() { return &m_yaraScanner; }
    ReportGenerator* GetReportGenerator() { return &m_reportGenerator; }

    // 状态栏更新
    void SetStatusText(const tstring& text, int part = 0);

    // 日志输出
    void Log(const tstring& message);

private:
    // 窗口类注册
    bool RegisterWindowClass();

    // 创建控件
    void CreateControls();
    void CreateTabControl();
    void CreateStatusBar();
    void CreateTabs();

    // 窗口过程
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);

    // 消息处理
    void OnCreate();
    void OnSize(int width, int height);
    void OnDestroy();
    void OnCommand(WORD id, WORD code, HWND hCtrl);
    void OnNotify(LPNMHDR pnmh);
    void OnTabSelChange();

    // 刷新当前标签页
    void RefreshCurrentTab();

    // 检查管理员权限
    bool CheckAdminPrivilege();

private:
    static MainWindow* s_instance;

    HINSTANCE m_hInstance;
    HWND m_hWnd;
    HWND m_hTabCtrl;
    HWND m_hStatusBar;

    // Tab 页
    std::vector<BaseTab*> m_tabs;
    int m_currentTab;

    // 核心管理器 - P1 阶段
    ProcessManager m_processManager;
    NetworkManager m_networkManager;
    DLLManager m_dllManager;
    HandleManager m_handleManager;
    MemoryScanner m_memoryScanner;
    HashManager m_hashManager;
    PersistenceDetector m_persistenceDetector;
    EventLogManager m_eventLogManager;

    // 核心管理器 - P2 阶段
    DumpManager m_dumpManager;
    MonitorManager m_monitorManager;
    SecurityManager m_securityManager;
    FileLocker m_fileLocker;
    YaraScanner m_yaraScanner;
    ReportGenerator m_reportGenerator;

    // 窗口尺寸
    int m_width;
    int m_height;

    // 日志缓冲
    std::vector<tstring> m_logBuffer;

    // 常量
    static const TCHAR* WINDOW_CLASS;
    static const TCHAR* WINDOW_TITLE;
    static const int DEFAULT_WIDTH = 1400;
    static const int DEFAULT_HEIGHT = 900;
};
