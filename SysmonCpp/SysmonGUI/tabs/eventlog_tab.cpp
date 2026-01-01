// eventlog_tab.cpp - 事件日志标签页实现
#include "eventlog_tab.h"
#include <commctrl.h>
#include <strsafe.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

EventLogTab::EventLogTab(HWND hParentTab, EventLogManager* pManager)
    : BaseTab(hParentTab)
    , m_pManager(pManager)
    , m_hComboLog(NULL)
    , m_hComboPreset(NULL)
    , m_hEditHours(NULL)
    , m_hBtnQuery(NULL)
{
}

EventLogTab::~EventLogTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool EventLogTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) {
        return false;
    }

    // 创建工具栏区域
    CreateToolbar();

    // 创建 ListView
    RECT listRect = rc;
    listRect.top = 35;

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

    // 设置扩展样式
    ListView_SetExtendedListViewStyle(m_hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    // 添加列
    AddColumn(COL_TIME, TEXT("时间"), 140);
    AddColumn(COL_LEVEL, TEXT("级别"), 80);
    AddColumn(COL_SOURCE, TEXT("来源"), 150);
    AddColumn(COL_EVENTID, TEXT("事件ID"), 70);
    AddColumn(COL_USER, TEXT("用户"), 120);
    AddColumn(COL_MESSAGE, TEXT("消息"), 500);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void EventLogTab::CreateToolbar()
{
    // 日志类型
    CreateWindowEx(0, TEXT("STATIC"), TEXT("日志:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hComboLog = CreateWindowEx(0, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        50, 5, 90, 200,
        m_hWnd, (HMENU)IDC_COMBO_FILTER, GetModuleHandle(NULL), NULL);

    SendMessage(m_hComboLog, CB_ADDSTRING, 0, (LPARAM)TEXT("Security"));
    SendMessage(m_hComboLog, CB_ADDSTRING, 0, (LPARAM)TEXT("System"));
    SendMessage(m_hComboLog, CB_ADDSTRING, 0, (LPARAM)TEXT("Application"));
    SendMessage(m_hComboLog, CB_SETCURSEL, 0, 0);

    // 预设查询
    CreateWindowEx(0, TEXT("STATIC"), TEXT("预设:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        150, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hComboPreset = CreateWindowEx(0, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        195, 5, 130, 200,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    SendMessage(m_hComboPreset, CB_ADDSTRING, 0, (LPARAM)TEXT("全部事件"));
    SendMessage(m_hComboPreset, CB_ADDSTRING, 0, (LPARAM)TEXT("登录事件"));
    SendMessage(m_hComboPreset, CB_ADDSTRING, 0, (LPARAM)TEXT("进程创建"));
    SendMessage(m_hComboPreset, CB_ADDSTRING, 0, (LPARAM)TEXT("服务安装"));
    SendMessage(m_hComboPreset, CB_ADDSTRING, 0, (LPARAM)TEXT("可疑事件"));
    SendMessage(m_hComboPreset, CB_SETCURSEL, 0, 0);

    // 时间范围
    CreateWindowEx(0, TEXT("STATIC"), TEXT("小时:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        335, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditHours = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT("24"),
        WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_CENTER,
        380, 5, 50, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    // 查询按钮
    m_hBtnQuery = CreateWindowEx(0, TEXT("BUTTON"), TEXT("查询"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        440, 5, 70, 25,
        m_hWnd, (HMENU)IDC_BTN_REFRESH, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 刷新数据
// ============================================================================

void EventLogTab::Refresh()
{
    QueryEvents();
}

// ============================================================================
// 查询事件
// ============================================================================

void EventLogTab::QueryEvents()
{
    if (!m_pManager) {
        return;
    }

    // 设置等待光标
    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));

    // 获取参数
    TCHAR szHours[16];
    GetWindowText(m_hEditHours, szHours, 16);
    DWORD hours = _ttol(szHours);
    if (hours == 0) hours = 24;

    int logIndex = (int)SendMessage(m_hComboLog, CB_GETCURSEL, 0, 0);
    int presetIndex = (int)SendMessage(m_hComboPreset, CB_GETCURSEL, 0, 0);

    m_events.clear();

    // 根据预设查询
    switch (presetIndex) {
    case 0: // 全部事件
        switch (logIndex) {
        case 0:
            m_events = m_pManager->QuerySecurityLog(hours, 1000);
            break;
        case 1:
            m_events = m_pManager->QuerySystemLog(hours, 1000);
            break;
        case 2:
            m_events = m_pManager->QueryApplicationLog(hours, 1000);
            break;
        }
        break;

    case 1: // 登录事件
        m_events = m_pManager->GetLoginEvents(hours);
        break;

    case 2: // 进程创建
        m_events = m_pManager->GetProcessCreationEvents(hours);
        break;

    case 3: // 服务安装
        m_events = m_pManager->GetServiceInstallEvents(hours);
        break;

    case 4: // 可疑事件
        m_events = m_pManager->GetSuspiciousEvents(hours);
        break;
    }

    // 更新 ListView
    ListView_DeleteAllItems(m_hListView);

    for (size_t i = 0; i < m_events.size(); i++) {
        const EventLogEntry& event = m_events[i];

        // 时间
        tstring timeStr = FormatFileTime(event.timeGenerated);

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = COL_TIME;
        lvi.pszText = (LPTSTR)timeStr.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        // 级别
        ListView_SetItemText(m_hListView, (int)i, COL_LEVEL,
            (LPTSTR)event.level.c_str());

        // 来源
        ListView_SetItemText(m_hListView, (int)i, COL_SOURCE,
            (LPTSTR)event.source.c_str());

        // 事件 ID
        TCHAR szEventId[16];
        StringCchPrintf(szEventId, 16, TEXT("%lu"), event.eventId);
        ListView_SetItemText(m_hListView, (int)i, COL_EVENTID, szEventId);

        // 用户
        ListView_SetItemText(m_hListView, (int)i, COL_USER,
            (LPTSTR)event.username.c_str());

        // 消息 (截断长消息)
        tstring msg = event.message;
        if (msg.length() > 200) {
            msg = msg.substr(0, 200) + TEXT("...");
        }
        ListView_SetItemText(m_hListView, (int)i, COL_MESSAGE,
            (LPTSTR)msg.c_str());
    }

    // 更新状态栏
    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("查询完成: %d 条事件 (最近 %lu 小时)"),
        (int)m_events.size(), hours);
    SetStatusText(szStatus);

    // 恢复光标
    SetCursor(hOldCursor);
}

// ============================================================================
// 格式化时间
// ============================================================================

tstring EventLogTab::FormatFileTime(const FILETIME& ft)
{
    SYSTEMTIME st;
    FILETIME localFt;

    FileTimeToLocalFileTime(&ft, &localFt);
    FileTimeToSystemTime(&localFt, &st);

    TCHAR szTime[64];
    StringCchPrintf(szTime, 64, TEXT("%04d-%02d-%02d %02d:%02d:%02d"),
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return szTime;
}

// ============================================================================
// 命令处理
// ============================================================================

void EventLogTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_REFRESH:
        QueryEvents();
        break;

    case IDC_COMBO_FILTER:
        if (code == CBN_SELCHANGE) {
            // 日志类型改变时，重置预设为"全部事件"
            SendMessage(m_hComboPreset, CB_SETCURSEL, 0, 0);
        }
        break;
    }
}
