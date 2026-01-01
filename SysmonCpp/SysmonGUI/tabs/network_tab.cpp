// network_tab.cpp - 网络连接标签页实现
#include "network_tab.h"
#include <tchar.h>
#include <algorithm>

// 控件 ID
#define IDC_BTN_REFRESH_NET     7001
#define IDC_COMBO_PROTOCOL      7002
#define IDC_COMBO_STATE         7003
#define IDC_EDIT_SEARCH_NET     7004
#define IDC_BTN_SEARCH_NET      7005
#define IDC_CHK_SUSPICIOUS_NET  7006

// ============================================================================
// 构造函数和析构函数
// ============================================================================

NetworkTab::NetworkTab(HWND hParentTab, NetworkManager* pManager)
    : BaseTab(hParentTab, TEXT("网络连接"))
    , m_pManager(pManager)
    , m_hBtnRefresh(NULL)
    , m_hComboProtocol(NULL)
    , m_hComboState(NULL)
    , m_hEditSearch(NULL)
    , m_hBtnSearch(NULL)
    , m_hChkSuspicious(NULL)
    , m_showSuspiciousOnly(false)
{
}

NetworkTab::~NetworkTab()
{
}

// ============================================================================
// 创建
// ============================================================================

bool NetworkTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) {
        return false;
    }

    // 创建工具栏
    CreateToolbar();

    // 创建 ListView
    std::vector<tstring> columns = {
        TEXT("协议"),
        TEXT("本地地址"),
        TEXT("本地端口"),
        TEXT("远程地址"),
        TEXT("远程端口"),
        TEXT("状态"),
        TEXT("PID"),
        TEXT("进程名")
    };

    std::vector<int> widths = { 60, 120, 80, 120, 80, 100, 60, 150 };

    CreateListView(rc, columns, widths);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void NetworkTab::CreateToolbar()
{
    int y = 5;
    int h = 25;
    int x = 10;

    // 刷新按钮
    m_hBtnRefresh = AddButton(x, y, 60, h, IDC_BTN_REFRESH_NET, TEXT("刷新"));
    x += 70;

    // 分隔
    x += 10;

    // 协议过滤
    AddLabel(x, y + 3, 40, h, TEXT("协议:"));
    x += 45;

    m_hComboProtocol = AddComboBox(x, y, 80, h * 5, IDC_COMBO_PROTOCOL);
    SendMessage(m_hComboProtocol, CB_ADDSTRING, 0, (LPARAM)TEXT("全部"));
    SendMessage(m_hComboProtocol, CB_ADDSTRING, 0, (LPARAM)TEXT("TCP"));
    SendMessage(m_hComboProtocol, CB_ADDSTRING, 0, (LPARAM)TEXT("UDP"));
    SendMessage(m_hComboProtocol, CB_SETCURSEL, 0, 0);
    x += 90;

    // 状态过滤
    AddLabel(x, y + 3, 40, h, TEXT("状态:"));
    x += 45;

    m_hComboState = AddComboBox(x, y, 120, h * 10, IDC_COMBO_STATE);
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)TEXT("全部"));
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)TEXT("ESTABLISHED"));
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)TEXT("LISTEN"));
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)TEXT("TIME_WAIT"));
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)TEXT("CLOSE_WAIT"));
    SendMessage(m_hComboState, CB_ADDSTRING, 0, (LPARAM)TEXT("SYN_SENT"));
    SendMessage(m_hComboState, CB_SETCURSEL, 0, 0);
    x += 130;

    // 分隔
    x += 10;

    // 搜索框
    AddLabel(x, y + 3, 40, h, TEXT("搜索:"));
    x += 45;

    m_hEditSearch = AddEdit(x, y, 120, h, IDC_EDIT_SEARCH_NET);
    x += 125;

    m_hBtnSearch = AddButton(x, y, 50, h, IDC_BTN_SEARCH_NET, TEXT("查找"));
    x += 60;

    // 分隔
    x += 10;

    // 只显示可疑
    m_hChkSuspicious = CreateWindowEx(
        0,
        TEXT("BUTTON"),
        TEXT("只显示可疑"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        x, y + 3, 100, h,
        m_hWnd,
        (HMENU)IDC_CHK_SUSPICIOUS_NET,
        GetModuleHandle(NULL),
        NULL);

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(m_hChkSuspicious, WM_SETFONT, (WPARAM)hFont, TRUE);
}

// ============================================================================
// 刷新
// ============================================================================

void NetworkTab::Refresh()
{
    // 获取网络连接
    m_connections = m_pManager->GetAllConnections();

    // 更新显示
    FilterConnections();
}

// ============================================================================
// 过滤连接
// ============================================================================

void NetworkTab::FilterConnections()
{
    ClearListView();

    // 获取过滤条件
    TCHAR buffer[256];

    // 协议
    int protocolSel = (int)SendMessage(m_hComboProtocol, CB_GETCURSEL, 0, 0);
    if (protocolSel > 0) {
        SendMessage(m_hComboProtocol, CB_GETLBTEXT, protocolSel, (LPARAM)buffer);
        m_filterProtocol = buffer;
    } else {
        m_filterProtocol.clear();
    }

    // 状态
    int stateSel = (int)SendMessage(m_hComboState, CB_GETCURSEL, 0, 0);
    if (stateSel > 0) {
        SendMessage(m_hComboState, CB_GETLBTEXT, stateSel, (LPARAM)buffer);
        m_filterState = buffer;
    } else {
        m_filterState.clear();
    }

    // 搜索关键字
    GetWindowText(m_hEditSearch, buffer, 256);
    m_searchKeyword = buffer;

    // 可疑过滤
    m_showSuspiciousOnly = (SendMessage(m_hChkSuspicious, BM_GETCHECK, 0, 0) == BST_CHECKED);

    int displayCount = 0;
    int suspiciousCount = 0;
    int establishedCount = 0;
    int listenCount = 0;

    for (const auto& conn : m_connections) {
        // 统计
        if (conn.isSuspicious) suspiciousCount++;
        if (conn.state == TEXT("ESTABLISHED")) establishedCount++;
        if (conn.state == TEXT("LISTEN")) listenCount++;

        // 应用过滤
        bool show = true;

        // 协议过滤
        if (!m_filterProtocol.empty() && conn.protocol != m_filterProtocol) {
            show = false;
        }

        // 状态过滤
        if (!m_filterState.empty() && conn.state != m_filterState) {
            show = false;
        }

        // 搜索过滤
        if (show && !m_searchKeyword.empty()) {
            bool match = false;

            if (conn.localAddr.find(m_searchKeyword) != tstring::npos) match = true;
            else if (conn.remoteAddr.find(m_searchKeyword) != tstring::npos) match = true;
            else if (conn.processName.find(m_searchKeyword) != tstring::npos) match = true;
            else {
                TCHAR pidStr[32];
                _stprintf_s(pidStr, TEXT("%u"), conn.pid);
                if (_tcsstr(pidStr, m_searchKeyword.c_str()) != NULL) match = true;
            }

            if (!match) show = false;
        }

        // 可疑过滤
        if (show && m_showSuspiciousOnly && !conn.isSuspicious) {
            show = false;
        }

        if (show) {
            std::vector<tstring> values;

            // 协议
            values.push_back(conn.protocol);

            // 本地地址
            values.push_back(conn.localAddr);

            // 本地端口
            TCHAR portStr[32];
            _stprintf_s(portStr, TEXT("%u"), conn.localPort);
            values.push_back(portStr);

            // 远程地址
            values.push_back(conn.remoteAddr);

            // 远程端口
            _stprintf_s(portStr, TEXT("%u"), conn.remotePort);
            values.push_back(portStr);

            // 状态
            values.push_back(conn.state);

            // PID
            _stprintf_s(portStr, TEXT("%u"), conn.pid);
            values.push_back(portStr);

            // 进程名
            tstring procName = conn.processName;
            if (conn.isSuspicious) {
                procName = TEXT("[!] ") + procName;
            }
            values.push_back(procName);

            AddListViewItem(values);
            displayCount++;
        }
    }

    // 更新状态栏
    TCHAR statusText[256];
    _stprintf_s(statusText, TEXT("连接总数: %d | 显示: %d | ESTABLISHED: %d | LISTEN: %d | 可疑: %d"),
        (int)m_connections.size(), displayCount, establishedCount, listenCount, suspiciousCount);

    HWND hMainWnd = GetParent(GetParent(m_hWnd));
    HWND hStatusBar = GetDlgItem(hMainWnd, IDC_STATUSBAR);
    if (hStatusBar) {
        SendMessage(hStatusBar, SB_SETTEXT, 1, (LPARAM)statusText);
    }
}

// ============================================================================
// 命令处理
// ============================================================================

void NetworkTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_REFRESH_NET:
        Refresh();
        break;

    case IDC_BTN_SEARCH_NET:
        FilterConnections();
        break;

    case IDC_COMBO_PROTOCOL:
    case IDC_COMBO_STATE:
        if (code == CBN_SELCHANGE) {
            FilterConnections();
        }
        break;

    case IDC_CHK_SUSPICIOUS_NET:
        FilterConnections();
        break;
    }
}

// ============================================================================
// 右键菜单
// ============================================================================

void NetworkTab::ShowContextMenu(int x, int y)
{
    int sel = GetSelectedItem();
    if (sel < 0) return;

    HMENU hMenu = CreatePopupMenu();

    AppendMenu(hMenu, MF_STRING, 8001, TEXT("复制本地地址"));
    AppendMenu(hMenu, MF_STRING, 8002, TEXT("复制远程地址"));
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, 8003, TEXT("查看进程"));
    AppendMenu(hMenu, MF_STRING, 8004, TEXT("终止连接"));

    TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON,
        x, y, 0, m_hWnd, NULL);

    DestroyMenu(hMenu);
}

// ============================================================================
// 排序
// ============================================================================

void NetworkTab::SortListView(int column)
{
    BaseTab::SortListView(column);

    auto compareFunc = [this, column](const NetworkConnection& a, const NetworkConnection& b) -> bool {
        switch (column) {
        case COL_PROTOCOL:
            return m_sortAscending ? (a.protocol < b.protocol) : (a.protocol > b.protocol);
        case COL_LOCAL_ADDR:
            return m_sortAscending ? (a.localAddr < b.localAddr) : (a.localAddr > b.localAddr);
        case COL_LOCAL_PORT:
            return m_sortAscending ? (a.localPort < b.localPort) : (a.localPort > b.localPort);
        case COL_REMOTE_ADDR:
            return m_sortAscending ? (a.remoteAddr < b.remoteAddr) : (a.remoteAddr > b.remoteAddr);
        case COL_REMOTE_PORT:
            return m_sortAscending ? (a.remotePort < b.remotePort) : (a.remotePort > b.remotePort);
        case COL_STATE:
            return m_sortAscending ? (a.state < b.state) : (a.state > b.state);
        case COL_PID:
            return m_sortAscending ? (a.pid < b.pid) : (a.pid > b.pid);
        case COL_PROCESS:
            return m_sortAscending ? (a.processName < b.processName) : (a.processName > b.processName);
        default:
            return false;
        }
    };

    std::sort(m_connections.begin(), m_connections.end(), compareFunc);
    FilterConnections();
}
