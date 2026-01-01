// handle_tab.cpp - 句柄查询标签页实现
#include "handle_tab.h"
#include <commctrl.h>
#include <strsafe.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

HandleTab::HandleTab(HWND hParentTab, HandleManager* pManager)
    : BaseTab(hParentTab)
    , m_pManager(pManager)
    , m_currentPid(0)
    , m_hEditPid(NULL)
    , m_hBtnScan(NULL)
    , m_hComboType(NULL)
{
}

HandleTab::~HandleTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool HandleTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) {
        return false;
    }

    // 创建工具栏区域
    CreateToolbar();

    // 创建 ListView
    RECT listRect = rc;
    listRect.top = 35; // 工具栏高度

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
    AddColumn(COL_HANDLE, TEXT("句柄值"), 100);
    AddColumn(COL_TYPE, TEXT("类型"), 120);
    AddColumn(COL_NAME, TEXT("名称"), 500);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void HandleTab::CreateToolbar()
{
    // PID 标签
    CreateWindowEx(0, TEXT("STATIC"), TEXT("进程 PID:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 70, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    // PID 输入框
    m_hEditPid = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE | ES_NUMBER,
        80, 5, 100, 25,
        m_hWnd, (HMENU)IDC_EDIT_SEARCH, GetModuleHandle(NULL), NULL);

    // 类型过滤标签
    CreateWindowEx(0, TEXT("STATIC"), TEXT("类型:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        190, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    // 类型过滤下拉框
    m_hComboType = CreateWindowEx(0, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        235, 5, 120, 200,
        m_hWnd, (HMENU)IDC_COMBO_FILTER, GetModuleHandle(NULL), NULL);

    // 添加类型选项
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("全部"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("File"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("Key"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("Event"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("Mutant"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("Section"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("Directory"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("Process"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("Thread"));
    SendMessage(m_hComboType, CB_SETCURSEL, 0, 0);

    // 扫描按钮
    m_hBtnScan = CreateWindowEx(0, TEXT("BUTTON"), TEXT("查询句柄"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        365, 5, 90, 25,
        m_hWnd, (HMENU)IDC_BTN_REFRESH, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 刷新数据
// ============================================================================

void HandleTab::Refresh()
{
    if (m_currentPid == 0) {
        return;
    }

    ScanProcess();
}

// ============================================================================
// 扫描进程句柄
// ============================================================================

void HandleTab::ScanProcess()
{
    if (!m_pManager) {
        return;
    }

    // 获取 PID
    TCHAR szPid[32];
    GetWindowText(m_hEditPid, szPid, 32);
    m_currentPid = _ttol(szPid);

    if (m_currentPid == 0) {
        MessageBox(m_hWnd, TEXT("请输入有效的进程 PID"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    // 设置等待光标
    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));

    // 枚举句柄
    m_handles = m_pManager->GetProcessHandles(m_currentPid);

    // 应用过滤并显示
    FilterHandles();

    // 恢复光标
    SetCursor(hOldCursor);
}

// ============================================================================
// 过滤句柄
// ============================================================================

void HandleTab::FilterHandles()
{
    ListView_DeleteAllItems(m_hListView);

    // 获取过滤类型
    int filterIndex = (int)SendMessage(m_hComboType, CB_GETCURSEL, 0, 0);
    TCHAR filterType[64] = { 0 };
    if (filterIndex > 0) {
        SendMessage(m_hComboType, CB_GETLBTEXT, filterIndex, (LPARAM)filterType);
    }

    int itemIndex = 0;
    for (size_t i = 0; i < m_handles.size(); i++) {
        const HandleInfo& handle = m_handles[i];

        // 应用类型过滤
        if (filterIndex > 0 && handle.type != filterType) {
            continue;
        }

        // 句柄值
        TCHAR szHandle[32];
        StringCchPrintf(szHandle, 32, TEXT("0x%04X"), (DWORD)(DWORD_PTR)handle.handleValue);

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = itemIndex;
        lvi.iSubItem = COL_HANDLE;
        lvi.pszText = szHandle;
        ListView_InsertItem(m_hListView, &lvi);

        // 类型
        ListView_SetItemText(m_hListView, itemIndex, COL_TYPE,
            (LPTSTR)handle.type.c_str());

        // 名称
        ListView_SetItemText(m_hListView, itemIndex, COL_NAME,
            (LPTSTR)handle.name.c_str());

        itemIndex++;
    }

    // 更新状态栏
    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("PID %lu: 共 %d 个句柄 (显示 %d 个)"),
        m_currentPid, (int)m_handles.size(), itemIndex);
    SetStatusText(szStatus);
}

// ============================================================================
// 命令处理
// ============================================================================

void HandleTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_REFRESH:
        ScanProcess();
        break;

    case IDC_COMBO_FILTER:
        if (code == CBN_SELCHANGE) {
            FilterHandles();
        }
        break;
    }
}
