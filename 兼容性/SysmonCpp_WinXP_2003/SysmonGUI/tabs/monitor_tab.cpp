// monitor_tab.cpp - 进程监控标签页实现
#include "monitor_tab.h"
#include <commctrl.h>
#include <strsafe.h>
#include <commdlg.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

MonitorTab::MonitorTab(HWND hParentTab, MonitorManager* pMonitorMgr, ProcessManager* pProcMgr)
    : BaseTab(hParentTab)
    , m_pMonitorManager(pMonitorMgr)
    , m_pProcessManager(pProcMgr)
    , m_hComboProcess(NULL)
    , m_hCheckRegistry(NULL)
    , m_hCheckFile(NULL)
    , m_hCheckNetwork(NULL)
    , m_hCheckProcess(NULL)
    , m_hBtnStart(NULL)
    , m_hBtnStop(NULL)
    , m_hBtnLoad(NULL)
    , m_hEditFilter(NULL)
    , m_isMonitoring(false)
{
}

MonitorTab::~MonitorTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool MonitorTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) {
        return false;
    }

    CreateToolbar();

    // 创建 ListView
    RECT listRect = rc;
    listRect.top = 70;  // 工具栏区域更大

    m_hListView = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEW,
        NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
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

    AddColumn(COL_TIME, TEXT("时间"), 140);
    AddColumn(COL_PROCESS, TEXT("进程"), 150);
    AddColumn(COL_PID, TEXT("PID"), 70);
    AddColumn(COL_OPERATION, TEXT("操作"), 120);
    AddColumn(COL_PATH, TEXT("路径"), 400);
    AddColumn(COL_RESULT, TEXT("结果"), 100);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void MonitorTab::CreateToolbar()
{
    // 第一行：进程选择和过滤器
    CreateWindowEx(0, TEXT("STATIC"), TEXT("进程:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hComboProcess = CreateWindowEx(0, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        50, 5, 150, 200,
        m_hWnd, (HMENU)IDC_COMBO_PROCESS, GetModuleHandle(NULL), NULL);

    SendMessage(m_hComboProcess, CB_ADDSTRING, 0, (LPARAM)TEXT("(所有进程)"));
    SendMessage(m_hComboProcess, CB_SETCURSEL, 0, 0);

    // 过滤器输入
    CreateWindowEx(0, TEXT("STATIC"), TEXT("过滤:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        210, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditFilter = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE,
        255, 5, 200, 25,
        m_hWnd, (HMENU)IDC_EDIT_FILTER, GetModuleHandle(NULL), NULL);

    // 控制按钮
    m_hBtnStart = CreateWindowEx(0, TEXT("BUTTON"), TEXT("开始监控"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        470, 5, 90, 25,
        m_hWnd, (HMENU)IDC_BTN_START, GetModuleHandle(NULL), NULL);

    m_hBtnStop = CreateWindowEx(0, TEXT("BUTTON"), TEXT("停止"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        570, 5, 60, 25,
        m_hWnd, (HMENU)IDC_BTN_STOP, GetModuleHandle(NULL), NULL);
    EnableWindow(m_hBtnStop, FALSE);

    m_hBtnLoad = CreateWindowEx(0, TEXT("BUTTON"), TEXT("加载日志"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        640, 5, 80, 25,
        m_hWnd, (HMENU)IDC_BTN_LOAD, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("清空"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        730, 5, 60, 25,
        m_hWnd, (HMENU)IDC_BTN_CLEAR, GetModuleHandle(NULL), NULL);

    // 第二行：事件类型复选框
    m_hCheckRegistry = CreateWindowEx(0, TEXT("BUTTON"), TEXT("注册表"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        5, 35, 80, 25,
        m_hWnd, (HMENU)IDC_CHECK_REGISTRY, GetModuleHandle(NULL), NULL);
    SendMessage(m_hCheckRegistry, BM_SETCHECK, BST_CHECKED, 0);

    m_hCheckFile = CreateWindowEx(0, TEXT("BUTTON"), TEXT("文件系统"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        95, 35, 90, 25,
        m_hWnd, (HMENU)IDC_CHECK_FILE, GetModuleHandle(NULL), NULL);
    SendMessage(m_hCheckFile, BM_SETCHECK, BST_CHECKED, 0);

    m_hCheckNetwork = CreateWindowEx(0, TEXT("BUTTON"), TEXT("网络"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        195, 35, 70, 25,
        m_hWnd, (HMENU)IDC_CHECK_NETWORK, GetModuleHandle(NULL), NULL);
    SendMessage(m_hCheckNetwork, BM_SETCHECK, BST_CHECKED, 0);

    m_hCheckProcess = CreateWindowEx(0, TEXT("BUTTON"), TEXT("进程"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        275, 35, 70, 25,
        m_hWnd, (HMENU)IDC_CHECK_PROCESS, GetModuleHandle(NULL), NULL);
    SendMessage(m_hCheckProcess, BM_SETCHECK, BST_CHECKED, 0);
}

// ============================================================================
// 刷新
// ============================================================================

void MonitorTab::Refresh()
{
    // 刷新进程列表到 ComboBox
    SendMessage(m_hComboProcess, CB_RESETCONTENT, 0, 0);
    SendMessage(m_hComboProcess, CB_ADDSTRING, 0, (LPARAM)TEXT("(所有进程)"));

    if (m_pProcessManager) {
        std::vector<ProcessInfo> processes = m_pProcessManager->GetAllProcesses();
        for (const auto& proc : processes) {
            tstring item = proc.name + TEXT(" (") + std::to_wstring(proc.pid) + TEXT(")");
            SendMessage(m_hComboProcess, CB_ADDSTRING, 0, (LPARAM)item.c_str());
        }
    }

    SendMessage(m_hComboProcess, CB_SETCURSEL, 0, 0);

    SetStatusText(TEXT("就绪"));
}

// ============================================================================
// 开始监控
// ============================================================================

void MonitorTab::StartMonitoring()
{
    if (!m_pMonitorManager) {
        return;
    }

    if (!m_pMonitorManager->IsProcmonAvailable()) {
        MessageBox(m_hWnd,
            TEXT("Procmon.exe 未找到，请将其放置在 Tools 目录下"),
            TEXT("错误"), MB_ICONERROR);
        return;
    }

    // 配置监控选项
    MonitorConfig config;
    config.captureRegistry = (SendMessage(m_hCheckRegistry, BM_GETCHECK, 0, 0) == BST_CHECKED);
    config.captureFileSystem = (SendMessage(m_hCheckFile, BM_GETCHECK, 0, 0) == BST_CHECKED);
    config.captureNetwork = (SendMessage(m_hCheckNetwork, BM_GETCHECK, 0, 0) == BST_CHECKED);
    config.captureProcess = (SendMessage(m_hCheckProcess, BM_GETCHECK, 0, 0) == BST_CHECKED);

    // 获取选中的进程
    TCHAR szProcess[256];
    int sel = (int)SendMessage(m_hComboProcess, CB_GETCURSEL, 0, 0);
    if (sel > 0) {
        SendMessage(m_hComboProcess, CB_GETLBTEXT, sel, (LPARAM)szProcess);
        config.filterProcessName = szProcess;
        // 提取进程名（去掉 PID 部分）
        tstring name = szProcess;
        size_t pos = name.rfind(TEXT(" ("));
        if (pos != tstring::npos) {
            config.filterProcessName = name.substr(0, pos);
        }
    }

    m_pMonitorManager->SetConfig(config);

    if (m_pMonitorManager->StartMonitoring()) {
        m_isMonitoring = true;
        EnableWindow(m_hBtnStart, FALSE);
        EnableWindow(m_hBtnStop, TRUE);
        SetStatusText(TEXT("正在监控..."));
    }
    else {
        MessageBox(m_hWnd, TEXT("启动监控失败"), TEXT("错误"), MB_ICONERROR);
    }
}

// ============================================================================
// 停止监控
// ============================================================================

void MonitorTab::StopMonitoring()
{
    if (!m_pMonitorManager || !m_isMonitoring) {
        return;
    }

    SetStatusText(TEXT("正在停止监控并解析数据..."));
    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));

    tstring logFile = m_pMonitorManager->StopMonitoring();

    if (!logFile.empty()) {
        m_events = m_pMonitorManager->GetEvents();
        ApplyFilter();
    }

    SetCursor(hOldCursor);

    m_isMonitoring = false;
    EnableWindow(m_hBtnStart, TRUE);
    EnableWindow(m_hBtnStop, FALSE);

    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("监控完成，捕获 %d 个事件"), (int)m_events.size());
    SetStatusText(szStatus);
}

// ============================================================================
// 加载日志文件
// ============================================================================

void MonitorTab::LoadLogFile()
{
    if (!m_pMonitorManager) {
        return;
    }

    OPENFILENAME ofn = { 0 };
    TCHAR szFile[MAX_PATH] = TEXT("");

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hWnd;
    ofn.lpstrFilter = TEXT("CSV 文件 (*.csv)\0*.csv\0PML 文件 (*.pml)\0*.pml\0所有文件 (*.*)\0*.*\0");
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = TEXT("选择 Procmon 日志文件");

    if (GetOpenFileName(&ofn)) {
        HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
        SetStatusText(TEXT("正在解析日志文件..."));

        // 检查是否是 CSV 文件
        tstring filePath = szFile;
        if (filePath.length() > 4) {
            tstring ext = filePath.substr(filePath.length() - 4);
            for (auto& c : ext) c = (TCHAR)tolower(c);

            if (ext == TEXT(".csv")) {
                m_events = m_pMonitorManager->ParseCSVFile(filePath);
            }
            else if (ext == TEXT(".pml")) {
                m_events = m_pMonitorManager->ParsePMLFile(filePath);
            }
        }

        ApplyFilter();

        SetCursor(hOldCursor);

        TCHAR szStatus[128];
        StringCchPrintf(szStatus, 128, TEXT("已加载 %d 个事件"), (int)m_events.size());
        SetStatusText(szStatus);
    }
}

// ============================================================================
// 清空结果
// ============================================================================

void MonitorTab::ClearResults()
{
    m_events.clear();
    ListView_DeleteAllItems(m_hListView);
    SetStatusText(TEXT("已清空"));
}

// ============================================================================
// 应用过滤器并更新 ListView
// ============================================================================

void MonitorTab::ApplyFilter()
{
    ListView_DeleteAllItems(m_hListView);

    // 获取过滤文本
    TCHAR szFilter[256] = TEXT("");
    GetWindowText(m_hEditFilter, szFilter, 256);
    tstring filter = szFilter;
    for (auto& c : filter) c = (TCHAR)tolower(c);

    // 获取事件类型过滤
    bool showRegistry = (SendMessage(m_hCheckRegistry, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool showFile = (SendMessage(m_hCheckFile, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool showNetwork = (SendMessage(m_hCheckNetwork, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool showProcess = (SendMessage(m_hCheckProcess, BM_GETCHECK, 0, 0) == BST_CHECKED);

    int displayIndex = 0;
    for (size_t i = 0; i < m_events.size(); i++) {
        const ProcmonEvent& event = m_events[i];

        // 事件类型过滤
        bool show = false;
        switch (event.eventType) {
        case PROCMON_REGISTRY:
            show = showRegistry;
            break;
        case PROCMON_FILESYSTEM:
            show = showFile;
            break;
        case PROCMON_NETWORK:
            show = showNetwork;
            break;
        case PROCMON_PROCESS:
            show = showProcess;
            break;
        default:
            show = true;
            break;
        }

        if (!show) continue;

        // 文本过滤
        if (!filter.empty()) {
            tstring pathLower = event.path;
            tstring procLower = event.processName;
            tstring opLower = event.operation;
            for (auto& c : pathLower) c = (TCHAR)tolower(c);
            for (auto& c : procLower) c = (TCHAR)tolower(c);
            for (auto& c : opLower) c = (TCHAR)tolower(c);

            if (pathLower.find(filter) == tstring::npos &&
                procLower.find(filter) == tstring::npos &&
                opLower.find(filter) == tstring::npos) {
                continue;
            }
        }

        // 添加到 ListView
        tstring timeStr = FormatTimestamp(event.timestamp);

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = displayIndex;
        lvi.iSubItem = COL_TIME;
        lvi.pszText = (LPTSTR)timeStr.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        ListView_SetItemText(m_hListView, displayIndex, COL_PROCESS,
            (LPTSTR)event.processName.c_str());

        TCHAR szPid[16];
        StringCchPrintf(szPid, 16, TEXT("%lu"), event.pid);
        ListView_SetItemText(m_hListView, displayIndex, COL_PID, szPid);

        ListView_SetItemText(m_hListView, displayIndex, COL_OPERATION,
            (LPTSTR)event.operation.c_str());

        ListView_SetItemText(m_hListView, displayIndex, COL_PATH,
            (LPTSTR)event.path.c_str());

        ListView_SetItemText(m_hListView, displayIndex, COL_RESULT,
            (LPTSTR)event.result.c_str());

        displayIndex++;
    }
}

// ============================================================================
// 格式化时间戳
// ============================================================================

tstring MonitorTab::FormatTimestamp(ULONGLONG timestamp)
{
    // timestamp 是 FILETIME 格式
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)(timestamp & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(timestamp >> 32);

    SYSTEMTIME st;
    FILETIME localFt;
    FileTimeToLocalFileTime(&ft, &localFt);
    FileTimeToSystemTime(&localFt, &st);

    TCHAR szTime[64];
    StringCchPrintf(szTime, 64, TEXT("%02d:%02d:%02d.%03d"),
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    return szTime;
}

// ============================================================================
// 命令处理
// ============================================================================

void MonitorTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_START:
        StartMonitoring();
        break;

    case IDC_BTN_STOP:
        StopMonitoring();
        break;

    case IDC_BTN_LOAD:
        LoadLogFile();
        break;

    case IDC_BTN_CLEAR:
        ClearResults();
        break;

    case IDC_CHECK_REGISTRY:
    case IDC_CHECK_FILE:
    case IDC_CHECK_NETWORK:
    case IDC_CHECK_PROCESS:
        if (code == BN_CLICKED && !m_events.empty()) {
            ApplyFilter();
        }
        break;

    case IDC_EDIT_FILTER:
        if (code == EN_CHANGE && !m_events.empty()) {
            ApplyFilter();
        }
        break;
    }
}
