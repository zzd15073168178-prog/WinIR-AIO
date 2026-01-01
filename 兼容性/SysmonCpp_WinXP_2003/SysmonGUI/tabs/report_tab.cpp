// report_tab.cpp - 报告生成标签页实现
#include "report_tab.h"
#include <commctrl.h>
#include <strsafe.h>
#include <shellapi.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

ReportTab::ReportTab(HWND hParentTab, ReportGenerator* pReportGen,
                     ProcessManager* pProcMgr, NetworkManager* pNetMgr,
                     PersistenceDetector* pPersistence, EventLogManager* pEventLog)
    : BaseTab(hParentTab)
    , m_pReportGenerator(pReportGen)
    , m_pProcessManager(pProcMgr)
    , m_pNetworkManager(pNetMgr)
    , m_pPersistenceDetector(pPersistence)
    , m_pEventLogManager(pEventLog)
    , m_hComboFormat(NULL)
    , m_hEditTitle(NULL)
    , m_hEditAuthor(NULL)
    , m_hCheckSummary(NULL)
    , m_hCheckProcesses(NULL)
    , m_hCheckNetwork(NULL)
    , m_hCheckPersistence(NULL)
    , m_hCheckEvents(NULL)
    , m_hCheckSuspicious(NULL)
    , m_hEditOutput(NULL)
{
}

ReportTab::~ReportTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool ReportTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) {
        return false;
    }

    CreateToolbar();
    CreateSectionCheckboxes();

    // 创建输出区域（显示生成的报告路径）
    CreateWindowEx(0, TEXT("STATIC"), TEXT("输出日志:"),
        WS_CHILD | WS_VISIBLE,
        5, 140, 80, 20,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditOutput = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
        5, 165, rc.right - rc.left - 10, 100,
        m_hWnd, (HMENU)IDC_EDIT_OUTPUT, GetModuleHandle(NULL), NULL);

    // 创建 ListView 显示报告历史
    RECT listRect = rc;
    listRect.top = 275;

    m_hListView = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEW,
        NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
        listRect.left, listRect.top,
        listRect.right - listRect.left,
        listRect.bottom - listRect.top,
        m_hWnd,
        (HMENU)IDC_LISTVIEW,
        GetModuleHandle(NULL),
        NULL);

    if (!m_hListView) {
        return false;
    }

    ListView_SetExtendedListViewStyle(m_hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    AddColumn(COL_TIME, TEXT("生成时间"), 150);
    AddColumn(COL_FORMAT, TEXT("格式"), 80);
    AddColumn(COL_PATH, TEXT("文件路径"), 500);
    AddColumn(COL_SIZE, TEXT("大小"), 100);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void ReportTab::CreateToolbar()
{
    // 第一行：报告标题和作者
    CreateWindowEx(0, TEXT("STATIC"), TEXT("标题:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditTitle = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT("系统安全分析报告"),
        WS_CHILD | WS_VISIBLE,
        50, 5, 250, 25,
        m_hWnd, (HMENU)IDC_EDIT_TITLE, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("STATIC"), TEXT("作者:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        320, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditAuthor = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT("Sysmon 分析工具"),
        WS_CHILD | WS_VISIBLE,
        365, 5, 200, 25,
        m_hWnd, (HMENU)IDC_EDIT_AUTHOR, GetModuleHandle(NULL), NULL);

    // 格式选择
    CreateWindowEx(0, TEXT("STATIC"), TEXT("格式:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        585, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hComboFormat = CreateWindowEx(0, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        630, 5, 100, 100,
        m_hWnd, (HMENU)IDC_COMBO_FORMAT, GetModuleHandle(NULL), NULL);

    SendMessage(m_hComboFormat, CB_ADDSTRING, 0, (LPARAM)TEXT("HTML"));
    SendMessage(m_hComboFormat, CB_ADDSTRING, 0, (LPARAM)TEXT("JSON"));
    SendMessage(m_hComboFormat, CB_ADDSTRING, 0, (LPARAM)TEXT("CSV"));
    SendMessage(m_hComboFormat, CB_ADDSTRING, 0, (LPARAM)TEXT("Text"));
    SendMessage(m_hComboFormat, CB_SETCURSEL, 0, 0);

    // 第二行：按钮
    CreateWindowEx(0, TEXT("BUTTON"), TEXT("生成报告"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        5, 38, 100, 30,
        m_hWnd, (HMENU)IDC_BTN_GENERATE, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("预览报告"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        115, 38, 90, 30,
        m_hWnd, (HMENU)IDC_BTN_PREVIEW, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("打开报告目录"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        215, 38, 110, 30,
        m_hWnd, (HMENU)IDC_BTN_OPENFOLDER, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 创建报告内容复选框
// ============================================================================

void ReportTab::CreateSectionCheckboxes()
{
    CreateWindowEx(0, TEXT("STATIC"), TEXT("报告内容:"),
        WS_CHILD | WS_VISIBLE,
        5, 78, 80, 20,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hCheckSummary = CreateWindowEx(0, TEXT("BUTTON"), TEXT("摘要"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        90, 75, 70, 25,
        m_hWnd, (HMENU)IDC_CHECK_SUMMARY, GetModuleHandle(NULL), NULL);
    SendMessage(m_hCheckSummary, BM_SETCHECK, BST_CHECKED, 0);

    m_hCheckProcesses = CreateWindowEx(0, TEXT("BUTTON"), TEXT("进程"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        170, 75, 70, 25,
        m_hWnd, (HMENU)IDC_CHECK_PROCESSES, GetModuleHandle(NULL), NULL);
    SendMessage(m_hCheckProcesses, BM_SETCHECK, BST_CHECKED, 0);

    m_hCheckNetwork = CreateWindowEx(0, TEXT("BUTTON"), TEXT("网络"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        250, 75, 70, 25,
        m_hWnd, (HMENU)IDC_CHECK_NETWORK, GetModuleHandle(NULL), NULL);
    SendMessage(m_hCheckNetwork, BM_SETCHECK, BST_CHECKED, 0);

    m_hCheckPersistence = CreateWindowEx(0, TEXT("BUTTON"), TEXT("持久化"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        330, 75, 80, 25,
        m_hWnd, (HMENU)IDC_CHECK_PERSISTENCE, GetModuleHandle(NULL), NULL);
    SendMessage(m_hCheckPersistence, BM_SETCHECK, BST_CHECKED, 0);

    m_hCheckEvents = CreateWindowEx(0, TEXT("BUTTON"), TEXT("事件日志"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        420, 75, 90, 25,
        m_hWnd, (HMENU)IDC_CHECK_EVENTS, GetModuleHandle(NULL), NULL);

    m_hCheckSuspicious = CreateWindowEx(0, TEXT("BUTTON"), TEXT("高亮可疑项"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        520, 75, 100, 25,
        m_hWnd, (HMENU)IDC_CHECK_SUSPICIOUS, GetModuleHandle(NULL), NULL);
    SendMessage(m_hCheckSuspicious, BM_SETCHECK, BST_CHECKED, 0);

    // 分隔线
    CreateWindowEx(0, TEXT("STATIC"), TEXT(""),
        WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        5, 105, 800, 2,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 刷新
// ============================================================================

void ReportTab::Refresh()
{
    SetStatusText(TEXT("就绪"));
}

// ============================================================================
// 收集数据
// ============================================================================

void ReportTab::CollectData()
{
    if (!m_pReportGenerator) {
        return;
    }

    tstring output;

    // 收集进程数据
    if (m_pProcessManager &&
        SendMessage(m_hCheckProcesses, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        output += TEXT("收集进程数据...\r\n");
        SetWindowText(m_hEditOutput, output.c_str());

        std::vector<ProcessInfo> processes = m_pProcessManager->GetAllProcesses();
        m_pReportGenerator->AddProcesses(processes);

        TCHAR szMsg[64];
        StringCchPrintf(szMsg, 64, TEXT("  - 进程数: %d\r\n"), (int)processes.size());
        output += szMsg;
        SetWindowText(m_hEditOutput, output.c_str());
    }

    // 收集网络数据
    if (m_pNetworkManager &&
        SendMessage(m_hCheckNetwork, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        output += TEXT("收集网络连接数据...\r\n");
        SetWindowText(m_hEditOutput, output.c_str());

        std::vector<NetworkConnection> connections = m_pNetworkManager->GetAllConnections();
        m_pReportGenerator->AddConnections(connections);

        TCHAR szMsg[64];
        StringCchPrintf(szMsg, 64, TEXT("  - 连接数: %d\r\n"), (int)connections.size());
        output += szMsg;
        SetWindowText(m_hEditOutput, output.c_str());
    }

    // 收集持久化数据
    if (m_pPersistenceDetector &&
        SendMessage(m_hCheckPersistence, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        output += TEXT("收集持久化配置数据...\r\n");
        SetWindowText(m_hEditOutput, output.c_str());

        std::vector<PersistenceItem> items = m_pPersistenceDetector->GetAllPersistenceItems();
        m_pReportGenerator->AddPersistenceItems(items);

        TCHAR szMsg[64];
        StringCchPrintf(szMsg, 64, TEXT("  - 持久化项: %d\r\n"), (int)items.size());
        output += szMsg;
        SetWindowText(m_hEditOutput, output.c_str());
    }

    // 收集事件日志
    if (m_pEventLogManager &&
        SendMessage(m_hCheckEvents, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        output += TEXT("收集事件日志数据...\r\n");
        SetWindowText(m_hEditOutput, output.c_str());

        std::vector<EventLogEntry> events = m_pEventLogManager->GetSuspiciousEvents(24);
        m_pReportGenerator->AddEvents(events);

        TCHAR szMsg[64];
        StringCchPrintf(szMsg, 64, TEXT("  - 事件数: %d\r\n"), (int)events.size());
        output += szMsg;
        SetWindowText(m_hEditOutput, output.c_str());
    }
}

// ============================================================================
// 生成报告
// ============================================================================

void ReportTab::GenerateReport()
{
    if (!m_pReportGenerator) {
        return;
    }

    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    SetStatusText(TEXT("正在生成报告..."));

    // 清空输出
    SetWindowText(m_hEditOutput, TEXT("开始生成报告...\r\n"));

    // 配置报告
    ReportConfig config;

    // 获取标题和作者
    TCHAR szTitle[256], szAuthor[256];
    GetWindowText(m_hEditTitle, szTitle, 256);
    GetWindowText(m_hEditAuthor, szAuthor, 256);
    config.title = szTitle;
    config.author = szAuthor;

    // 获取格式
    int formatIndex = (int)SendMessage(m_hComboFormat, CB_GETCURSEL, 0, 0);
    switch (formatIndex) {
    case 0: config.format = REPORT_HTML; break;
    case 1: config.format = REPORT_JSON; break;
    case 2: config.format = REPORT_CSV; break;
    case 3: config.format = REPORT_TEXT; break;
    default: config.format = REPORT_HTML; break;
    }

    // 获取报告节
    config.sections = 0;
    if (SendMessage(m_hCheckSummary, BM_GETCHECK, 0, 0) == BST_CHECKED)
        config.sections |= SECTION_SUMMARY;
    if (SendMessage(m_hCheckProcesses, BM_GETCHECK, 0, 0) == BST_CHECKED)
        config.sections |= SECTION_PROCESSES;
    if (SendMessage(m_hCheckNetwork, BM_GETCHECK, 0, 0) == BST_CHECKED)
        config.sections |= SECTION_NETWORK;
    if (SendMessage(m_hCheckPersistence, BM_GETCHECK, 0, 0) == BST_CHECKED)
        config.sections |= SECTION_PERSISTENCE;
    if (SendMessage(m_hCheckEvents, BM_GETCHECK, 0, 0) == BST_CHECKED)
        config.sections |= SECTION_EVENTS;

    config.includeTimestamp = true;
    config.highlightSuspicious =
        (SendMessage(m_hCheckSuspicious, BM_GETCHECK, 0, 0) == BST_CHECKED);

    m_pReportGenerator->SetConfig(config);

    // 收集数据
    CollectData();

    // 生成报告
    tstring output;
    GetWindowText(m_hEditOutput, (LPTSTR)output.c_str(), 4096);  // 获取当前输出
    TCHAR szBuffer[4096];
    GetWindowText(m_hEditOutput, szBuffer, 4096);
    output = szBuffer;
    output += TEXT("\r\n生成报告文件...\r\n");
    SetWindowText(m_hEditOutput, output.c_str());

    if (m_pReportGenerator->GenerateReport()) {
        tstring reportPath = m_pReportGenerator->GetLastReportPath();

        output += TEXT("报告生成成功!\r\n");
        output += TEXT("文件路径: ") + reportPath + TEXT("\r\n");
        SetWindowText(m_hEditOutput, output.c_str());

        // 添加到历史列表
        m_reportHistory.push_back(reportPath);

        // 更新 ListView
        SYSTEMTIME st;
        GetLocalTime(&st);
        TCHAR szTime[64];
        StringCchPrintf(szTime, 64, TEXT("%04d-%02d-%02d %02d:%02d:%02d"),
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        int index = ListView_GetItemCount(m_hListView);
        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = index;
        lvi.iSubItem = COL_TIME;
        lvi.pszText = szTime;
        ListView_InsertItem(m_hListView, &lvi);

        // 格式
        const TCHAR* formats[] = { TEXT("HTML"), TEXT("JSON"), TEXT("CSV"), TEXT("Text") };
        ListView_SetItemText(m_hListView, index, COL_FORMAT, (LPTSTR)formats[formatIndex]);

        // 路径
        ListView_SetItemText(m_hListView, index, COL_PATH, (LPTSTR)reportPath.c_str());

        // 大小
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesEx(reportPath.c_str(), GetFileExInfoStandard, &fad)) {
            TCHAR szSize[32];
            ULONGLONG size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
            if (size >= 1024 * 1024) {
                StringCchPrintf(szSize, 32, TEXT("%.2f MB"), (double)size / (1024.0 * 1024.0));
            }
            else if (size >= 1024) {
                StringCchPrintf(szSize, 32, TEXT("%.2f KB"), (double)size / 1024.0);
            }
            else {
                StringCchPrintf(szSize, 32, TEXT("%llu B"), size);
            }
            ListView_SetItemText(m_hListView, index, COL_SIZE, szSize);
        }

        SetStatusText(TEXT("报告生成成功"));
    }
    else {
        output += TEXT("报告生成失败!\r\n");
        SetWindowText(m_hEditOutput, output.c_str());
        SetStatusText(TEXT("报告生成失败"));
    }

    SetCursor(hOldCursor);
}

// ============================================================================
// 预览报告
// ============================================================================

void ReportTab::PreviewReport()
{
    int sel = ListView_GetNextItem(m_hListView, -1, LVNI_SELECTED);
    tstring path;

    if (sel >= 0 && sel < (int)m_reportHistory.size()) {
        path = m_reportHistory[sel];
    }
    else if (m_pReportGenerator) {
        path = m_pReportGenerator->GetLastReportPath();
    }

    if (path.empty()) {
        MessageBox(m_hWnd, TEXT("没有可预览的报告"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    // 检查文件是否存在
    if (GetFileAttributes(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBox(m_hWnd, TEXT("报告文件不存在"), TEXT("错误"), MB_ICONERROR);
        return;
    }

    // 使用默认程序打开
    ShellExecute(m_hWnd, TEXT("open"), path.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

// ============================================================================
// 打开报告目录
// ============================================================================

void ReportTab::OpenReportFolder()
{
    if (m_pReportGenerator) {
        tstring dir = m_pReportGenerator->GetOutputDirectory();
        ShellExecute(m_hWnd, TEXT("explore"), dir.c_str(), NULL, NULL, SW_SHOWNORMAL);
    }
}

// ============================================================================
// 命令处理
// ============================================================================

void ReportTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_GENERATE:
        GenerateReport();
        break;

    case IDC_BTN_PREVIEW:
        PreviewReport();
        break;

    case IDC_BTN_OPENFOLDER:
        OpenReportFolder();
        break;
    }
}
