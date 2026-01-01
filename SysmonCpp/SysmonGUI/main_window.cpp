// main_window.cpp - 主窗口实现
#include "main_window.h"
#include "tabs/base_tab.h"
#include "tabs/process_tab.h"
#include "tabs/network_tab.h"
#include "tabs/dll_tab.h"
#include "tabs/handle_tab.h"
#include "tabs/memory_scanner_tab.h"
#include "tabs/hash_tab.h"
#include "tabs/persistence_tab.h"
#include "tabs/eventlog_tab.h"
#include "tabs/dump_tab.h"
#include "tabs/monitor_tab.h"
#include "tabs/security_tab.h"
#include "tabs/file_locker_tab.h"
#include "tabs/yara_tab.h"
#include "tabs/report_tab.h"
#include <tchar.h>
#include <shellapi.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

// 启用视觉样式
#pragma comment(linker,"\"/manifestdependency:type='win32' \
    name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
    processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ============================================================================
// 静态成员初始化
// ============================================================================

MainWindow* MainWindow::s_instance = NULL;
const TCHAR* MainWindow::WINDOW_CLASS = TEXT("SysmonGUIClass");
const TCHAR* MainWindow::WINDOW_TITLE = TEXT("Sysmon 恶意软件分析工具 v1.0");

// ============================================================================
// 构造函数和析构函数
// ============================================================================

MainWindow::MainWindow(HINSTANCE hInstance)
    : m_hInstance(hInstance)
    , m_hWnd(NULL)
    , m_hTabCtrl(NULL)
    , m_hStatusBar(NULL)
    , m_currentTab(0)
    , m_width(DEFAULT_WIDTH)
    , m_height(DEFAULT_HEIGHT)
{
    s_instance = this;
}

MainWindow::~MainWindow()
{
    // 清理 Tab 页
    for (auto tab : m_tabs) {
        delete tab;
    }
    m_tabs.clear();

    s_instance = NULL;
}

// ============================================================================
// 创建窗口
// ============================================================================

bool MainWindow::Create(int nCmdShow)
{
    // 初始化 Common Controls
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES |
        ICC_TAB_CLASSES | ICC_BAR_CLASSES | ICC_TREEVIEW_CLASSES |
        ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    // 注册窗口类
    if (!RegisterWindowClass()) {
        return false;
    }

    // 计算窗口位置 (居中)
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int x = (screenWidth - m_width) / 2;
    int y = (screenHeight - m_height) / 2;

    // 创建主窗口
    m_hWnd = CreateWindowEx(
        0,
        WINDOW_CLASS,
        WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        x, y, m_width, m_height,
        NULL, NULL, m_hInstance, this);

    if (!m_hWnd) {
        return false;
    }

    // 检查管理员权限
    if (!CheckAdminPrivilege()) {
        MessageBox(m_hWnd,
            TEXT("警告: 程序未以管理员身份运行!\n\n部分功能可能无法正常使用，建议以管理员身份重新启动。"),
            TEXT("权限提示"),
            MB_ICONWARNING | MB_OK);
    }

    ShowWindow(m_hWnd, nCmdShow);
    UpdateWindow(m_hWnd);

    return true;
}

// ============================================================================
// 注册窗口类
// ============================================================================

bool MainWindow::RegisterWindowClass()
{
    WNDCLASSEX wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = sizeof(LONG_PTR);
    wcex.hInstance = m_hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = WINDOW_CLASS;
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    return RegisterClassEx(&wcex) != 0;
}

// ============================================================================
// 窗口过程
// ============================================================================

LRESULT CALLBACK MainWindow::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    MainWindow* pThis = NULL;

    if (msg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (MainWindow*)pCreate->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
        pThis->m_hWnd = hWnd;
    } else {
        pThis = (MainWindow*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    if (pThis) {
        return pThis->HandleMessage(msg, wParam, lParam);
    }

    return DefWindowProc(hWnd, msg, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        OnCreate();
        return 0;

    case WM_SIZE:
        OnSize(LOWORD(lParam), HIWORD(lParam));
        return 0;

    case WM_DESTROY:
        OnDestroy();
        return 0;

    case WM_COMMAND:
        OnCommand(LOWORD(wParam), HIWORD(wParam), (HWND)lParam);
        return 0;

    case WM_NOTIFY:
        OnNotify((LPNMHDR)lParam);
        return 0;

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 800;
        mmi->ptMinTrackSize.y = 600;
        return 0;
    }

    default:
        return DefWindowProc(m_hWnd, msg, wParam, lParam);
    }
}

// ============================================================================
// WM_CREATE 处理
// ============================================================================

void MainWindow::OnCreate()
{
    CreateControls();

    // 设置初始状态
    SetStatusText(TEXT("就绪"));

    // 刷新第一个标签页
    if (!m_tabs.empty()) {
        m_tabs[0]->Refresh();
    }
}

// ============================================================================
// 创建控件
// ============================================================================

void MainWindow::CreateControls()
{
    CreateStatusBar();
    CreateTabControl();
    CreateTabs();
}

// ============================================================================
// 创建状态栏
// ============================================================================

void MainWindow::CreateStatusBar()
{
    m_hStatusBar = CreateWindowEx(
        0,
        STATUSCLASSNAME,
        NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        m_hWnd,
        (HMENU)IDC_STATUSBAR,
        m_hInstance,
        NULL);

    // 设置状态栏分区
    if (m_hStatusBar) {
        int parts[] = { 300, 500, -1 };
        SendMessage(m_hStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
    }
}

// ============================================================================
// 创建 Tab 控件
// ============================================================================

void MainWindow::CreateTabControl()
{
    RECT rcClient;
    GetClientRect(m_hWnd, &rcClient);

    // 获取状态栏高度
    RECT rcStatus;
    GetWindowRect(m_hStatusBar, &rcStatus);
    int statusHeight = rcStatus.bottom - rcStatus.top;

    m_hTabCtrl = CreateWindowEx(
        0,
        WC_TABCONTROL,
        NULL,
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_TABS,
        0, 0,
        rcClient.right,
        rcClient.bottom - statusHeight,
        m_hWnd,
        (HMENU)IDC_TAB_MAIN,
        m_hInstance,
        NULL);

    // 设置字体
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(m_hTabCtrl, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 添加 Tab 页标签
    TCITEM tie;
    tie.mask = TCIF_TEXT;

    const TCHAR* tabNames[] = {
        TEXT("进程列表"),
        TEXT("网络连接"),
        TEXT("DLL检测"),
        TEXT("句柄查询"),
        TEXT("内存扫描"),
        TEXT("哈希计算"),
        TEXT("持久化检测"),
        TEXT("事件日志"),
        TEXT("内存转储"),
        TEXT("进程监控"),
        TEXT("自启动项"),
        TEXT("文件锁定"),
        TEXT("YARA扫描"),
        TEXT("报告生成"),
    };

    for (int i = 0; i < sizeof(tabNames) / sizeof(tabNames[0]); i++) {
        tie.pszText = (LPTSTR)tabNames[i];
        TabCtrl_InsertItem(m_hTabCtrl, i, &tie);
    }
}

// ============================================================================
// 创建 Tab 页内容
// ============================================================================

void MainWindow::CreateTabs()
{
    // 获取 Tab 控件的显示区域
    RECT rcTab;
    GetClientRect(m_hTabCtrl, &rcTab);

    // 重要：TabCtrl_AdjustRect 计算内容区域（排除标签头）
    // 参数 FALSE 表示从窗口矩形计算显示区域
    TabCtrl_AdjustRect(m_hTabCtrl, FALSE, &rcTab);

    // 调试：如果 top 值不正确，使用默认的 Tab 标签高度
    // Windows Tab 控件的标签头高度通常是 20-25 像素
    if (rcTab.top < 4) {
        // Tab 控件可能还没有正确初始化，手动设置偏移
        rcTab.left = 4;
        rcTab.top = 26;  // Tab 标签头高度 + 边距

        RECT rcClient;
        GetClientRect(m_hTabCtrl, &rcClient);
        rcTab.right = rcClient.right - 4;
        rcTab.bottom = rcClient.bottom - 4;
    }

    // 创建进程 Tab
    ProcessTab* processTab = new ProcessTab(m_hTabCtrl, &m_processManager);
    processTab->Create(rcTab);
    m_tabs.push_back(processTab);

    // 创建网络 Tab
    NetworkTab* networkTab = new NetworkTab(m_hTabCtrl, &m_networkManager);
    networkTab->Create(rcTab);
    m_tabs.push_back(networkTab);

    // 创建 DLL Tab
    DllTab* dllTab = new DllTab(m_hTabCtrl, &m_dllManager);
    dllTab->Create(rcTab);
    m_tabs.push_back(dllTab);

    // 创建句柄 Tab
    HandleTab* handleTab = new HandleTab(m_hTabCtrl, &m_handleManager);
    handleTab->Create(rcTab);
    m_tabs.push_back(handleTab);

    // 创建内存扫描 Tab
    MemoryScannerTab* memoryTab = new MemoryScannerTab(m_hTabCtrl, &m_memoryScanner);
    memoryTab->Create(rcTab);
    m_tabs.push_back(memoryTab);

    // 创建哈希计算 Tab
    HashTab* hashTab = new HashTab(m_hTabCtrl, &m_hashManager);
    hashTab->Create(rcTab);
    m_tabs.push_back(hashTab);

    // 创建持久化检测 Tab
    PersistenceTab* persistenceTab = new PersistenceTab(m_hTabCtrl, &m_persistenceDetector);
    persistenceTab->Create(rcTab);
    m_tabs.push_back(persistenceTab);

    // 创建事件日志 Tab
    EventLogTab* eventLogTab = new EventLogTab(m_hTabCtrl, &m_eventLogManager);
    eventLogTab->Create(rcTab);
    m_tabs.push_back(eventLogTab);

    // P2 阶段 Tab 页

    // 创建内存转储 Tab
    DumpTab* dumpTab = new DumpTab(m_hTabCtrl, &m_dumpManager, &m_processManager);
    dumpTab->Create(rcTab);
    m_tabs.push_back(dumpTab);

    // 创建进程监控 Tab
    MonitorTab* monitorTab = new MonitorTab(m_hTabCtrl, &m_monitorManager, &m_processManager);
    monitorTab->Create(rcTab);
    m_tabs.push_back(monitorTab);

    // 创建自启动项检测 Tab
    SecurityTab* securityTab = new SecurityTab(m_hTabCtrl, &m_securityManager);
    securityTab->Create(rcTab);
    m_tabs.push_back(securityTab);

    // 创建文件锁定分析 Tab
    FileLockerTab* fileLockerTab = new FileLockerTab(m_hTabCtrl, &m_fileLocker, &m_processManager);
    fileLockerTab->Create(rcTab);
    m_tabs.push_back(fileLockerTab);

    // 创建 YARA 扫描 Tab
    YaraTab* yaraTab = new YaraTab(m_hTabCtrl, &m_yaraScanner, &m_processManager);
    yaraTab->Create(rcTab);
    m_tabs.push_back(yaraTab);

    // 创建报告生成 Tab
    ReportTab* reportTab = new ReportTab(m_hTabCtrl, &m_reportGenerator,
        &m_processManager, &m_networkManager, &m_persistenceDetector, &m_eventLogManager);
    reportTab->Create(rcTab);
    m_tabs.push_back(reportTab);

    // 显示第一个 Tab，隐藏其他
    for (size_t i = 0; i < m_tabs.size(); i++) {
        m_tabs[i]->Show(i == 0);
    }
}

// ============================================================================
// WM_SIZE 处理
// ============================================================================

void MainWindow::OnSize(int width, int height)
{
    m_width = width;
    m_height = height;

    // 获取状态栏高度
    int statusHeight = 0;
    if (m_hStatusBar) {
        // 调整状态栏
        SendMessage(m_hStatusBar, WM_SIZE, 0, 0);

        RECT rcStatus;
        GetWindowRect(m_hStatusBar, &rcStatus);
        statusHeight = rcStatus.bottom - rcStatus.top;
    }

    // 调整 Tab 控件
    if (m_hTabCtrl) {
        MoveWindow(m_hTabCtrl, 0, 0, width, height - statusHeight, TRUE);

        // 调整 Tab 页内容
        RECT rcTab;
        GetClientRect(m_hTabCtrl, &rcTab);
        TabCtrl_AdjustRect(m_hTabCtrl, FALSE, &rcTab);

        // 安全检查：确保 top 值正确（给标签头留出空间）
        if (rcTab.top < 4) {
            rcTab.left = 4;
            rcTab.top = 26;
            rcTab.right = width - 4;
            rcTab.bottom = height - statusHeight - 4;
        }

        for (auto tab : m_tabs) {
            tab->Resize(rcTab);
        }
    }
}

// ============================================================================
// WM_DESTROY 处理
// ============================================================================

void MainWindow::OnDestroy()
{
    PostQuitMessage(0);
}

// ============================================================================
// WM_COMMAND 处理
// ============================================================================

void MainWindow::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDM_FILE_EXIT:
        DestroyWindow(m_hWnd);
        break;

    case IDM_VIEW_REFRESH:
    case IDC_BTN_REFRESH:
        RefreshCurrentTab();
        break;

    case IDM_HELP_ABOUT:
        MessageBox(m_hWnd,
            TEXT("Sysmon 恶意软件分析工具 v2.0\n\n")
            TEXT("基于 Win32 API 开发\n")
            TEXT("支持 Windows Server 2003 及以上系统\n\n")
            TEXT("功能:\n")
            TEXT("- 进程监控与管理\n")
            TEXT("- 网络连接分析\n")
            TEXT("- DLL 注入检测\n")
            TEXT("- 句柄查询\n")
            TEXT("- 内存扫描\n")
            TEXT("- 文件哈希计算\n")
            TEXT("- 持久化机制检测\n")
            TEXT("- 事件日志分析\n")
            TEXT("- 内存转储 (Procdump)\n")
            TEXT("- 进程活动监控 (Procmon)\n")
            TEXT("- 自启动项检测 (Autoruns)\n")
            TEXT("- 文件锁定分析\n")
            TEXT("- YARA 规则扫描\n")
            TEXT("- 报告生成 (HTML/JSON/CSV)"),
            TEXT("关于"),
            MB_ICONINFORMATION | MB_OK);
        break;
    }

    // 转发到当前 Tab 处理
    if (m_currentTab >= 0 && m_currentTab < (int)m_tabs.size()) {
        m_tabs[m_currentTab]->OnCommand(id, code, hCtrl);
    }
}

// ============================================================================
// WM_NOTIFY 处理
// ============================================================================

void MainWindow::OnNotify(LPNMHDR pnmh)
{
    if (pnmh->idFrom == IDC_TAB_MAIN) {
        if (pnmh->code == TCN_SELCHANGE) {
            OnTabSelChange();
        }
    }

    // 转发到当前 Tab 处理
    if (m_currentTab >= 0 && m_currentTab < (int)m_tabs.size()) {
        m_tabs[m_currentTab]->OnNotify(pnmh);
    }
}

// ============================================================================
// Tab 切换处理
// ============================================================================

void MainWindow::OnTabSelChange()
{
    int newTab = TabCtrl_GetCurSel(m_hTabCtrl);

    if (newTab != m_currentTab) {
        // 隐藏当前 Tab
        if (m_currentTab >= 0 && m_currentTab < (int)m_tabs.size()) {
            m_tabs[m_currentTab]->Show(false);
        }

        // 显示新 Tab
        m_currentTab = newTab;
        if (m_currentTab >= 0 && m_currentTab < (int)m_tabs.size()) {
            m_tabs[m_currentTab]->Show(true);
            m_tabs[m_currentTab]->Refresh();
        }
    }
}

// ============================================================================
// 刷新当前 Tab
// ============================================================================

void MainWindow::RefreshCurrentTab()
{
    if (m_currentTab >= 0 && m_currentTab < (int)m_tabs.size()) {
        SetStatusText(TEXT("正在刷新..."));
        m_tabs[m_currentTab]->Refresh();
        SetStatusText(TEXT("就绪"));
    }
}

// ============================================================================
// 状态栏更新
// ============================================================================

void MainWindow::SetStatusText(const tstring& text, int part)
{
    if (m_hStatusBar) {
        SendMessage(m_hStatusBar, SB_SETTEXT, part, (LPARAM)text.c_str());
    }
}

// ============================================================================
// 日志输出
// ============================================================================

void MainWindow::Log(const tstring& message)
{
    // 获取当前时间
    SYSTEMTIME st;
    GetLocalTime(&st);

    TCHAR buffer[1024];
    _stprintf_s(buffer, TEXT("[%02d:%02d:%02d] %s"),
        st.wHour, st.wMinute, st.wSecond, message.c_str());

    m_logBuffer.push_back(buffer);

    // 限制日志大小
    while (m_logBuffer.size() > 1000) {
        m_logBuffer.erase(m_logBuffer.begin());
    }
}

// ============================================================================
// 消息循环
// ============================================================================

int MainWindow::Run()
{
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

// ============================================================================
// 检查管理员权限
// ============================================================================

bool MainWindow::CheckAdminPrivilege()
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin != FALSE;
}
