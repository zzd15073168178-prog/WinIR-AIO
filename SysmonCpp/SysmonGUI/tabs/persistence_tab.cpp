// persistence_tab.cpp - 持久化检测标签页实现
#include "persistence_tab.h"
#include <commctrl.h>
#include <strsafe.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

PersistenceTab::PersistenceTab(HWND hParentTab, PersistenceDetector* pDetector)
    : BaseTab(hParentTab)
    , m_pDetector(pDetector)
    , m_hComboCategory(NULL)
    , m_hChkSuspiciousOnly(NULL)
    , m_hBtnScan(NULL)
{
}

PersistenceTab::~PersistenceTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool PersistenceTab::Create(const RECT& rc)
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
    AddColumn(COL_TYPE, TEXT("类型"), 100);
    AddColumn(COL_NAME, TEXT("名称"), 180);
    AddColumn(COL_VALUE, TEXT("值"), 300);
    AddColumn(COL_PATH, TEXT("路径"), 350);
    AddColumn(COL_SUSPICIOUS, TEXT("可疑"), 60);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void PersistenceTab::CreateToolbar()
{
    // 类别过滤
    CreateWindowEx(0, TEXT("STATIC"), TEXT("类别:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 45, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hComboCategory = CreateWindowEx(0, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        55, 5, 130, 200,
        m_hWnd, (HMENU)IDC_COMBO_FILTER, GetModuleHandle(NULL), NULL);

    SendMessage(m_hComboCategory, CB_ADDSTRING, 0, (LPARAM)TEXT("全部"));
    SendMessage(m_hComboCategory, CB_ADDSTRING, 0, (LPARAM)TEXT("注册表启动项"));
    SendMessage(m_hComboCategory, CB_ADDSTRING, 0, (LPARAM)TEXT("服务"));
    SendMessage(m_hComboCategory, CB_ADDSTRING, 0, (LPARAM)TEXT("计划任务"));
    SendMessage(m_hComboCategory, CB_ADDSTRING, 0, (LPARAM)TEXT("启动文件夹"));
    SendMessage(m_hComboCategory, CB_ADDSTRING, 0, (LPARAM)TEXT("浏览器扩展"));
    SendMessage(m_hComboCategory, CB_ADDSTRING, 0, (LPARAM)TEXT("WMI"));
    SendMessage(m_hComboCategory, CB_SETCURSEL, 0, 0);

    // 可疑项过滤
    m_hChkSuspiciousOnly = CreateWindowEx(0, TEXT("BUTTON"), TEXT("仅显示可疑项"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        195, 5, 110, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    // 扫描按钮
    m_hBtnScan = CreateWindowEx(0, TEXT("BUTTON"), TEXT("全面扫描"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        315, 5, 90, 25,
        m_hWnd, (HMENU)IDC_BTN_REFRESH, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 刷新数据
// ============================================================================

void PersistenceTab::Refresh()
{
    ScanPersistence();
}

// ============================================================================
// 扫描持久化项
// ============================================================================

void PersistenceTab::ScanPersistence()
{
    if (!m_pDetector) {
        return;
    }

    // 设置等待光标
    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));

    m_items.clear();

    // 获取类别过滤
    int catIndex = (int)SendMessage(m_hComboCategory, CB_GETCURSEL, 0, 0);

    // 根据类别扫描
    if (catIndex == 0 || catIndex == 1) {
        auto items = m_pDetector->GetRegistryRunKeys();
        m_items.insert(m_items.end(), items.begin(), items.end());
    }

    if (catIndex == 0 || catIndex == 2) {
        auto items = m_pDetector->GetServices();
        m_items.insert(m_items.end(), items.begin(), items.end());
    }

    if (catIndex == 0 || catIndex == 3) {
        auto items = m_pDetector->GetScheduledTasks();
        m_items.insert(m_items.end(), items.begin(), items.end());
    }

    if (catIndex == 0 || catIndex == 4) {
        auto items = m_pDetector->GetStartupFolder();
        m_items.insert(m_items.end(), items.begin(), items.end());
    }

    if (catIndex == 0 || catIndex == 5) {
        auto items = m_pDetector->GetWinlogon();
        m_items.insert(m_items.end(), items.begin(), items.end());
    }

    if (catIndex == 0 || catIndex == 6) {
        auto items = m_pDetector->GetAppInit();
        m_items.insert(m_items.end(), items.begin(), items.end());
    }

    // 显示结果
    FilterResults();

    // 恢复光标
    SetCursor(hOldCursor);
}

// ============================================================================
// 过滤结果
// ============================================================================

void PersistenceTab::FilterResults()
{
    ListView_DeleteAllItems(m_hListView);

    bool suspiciousOnly = (SendMessage(m_hChkSuspiciousOnly, BM_GETCHECK, 0, 0) == BST_CHECKED);

    int itemIndex = 0;
    int suspiciousCount = 0;

    for (size_t i = 0; i < m_items.size(); i++) {
        const PersistenceItem& item = m_items[i];

        // 可疑项过滤
        if (suspiciousOnly && !item.isSuspicious) {
            continue;
        }

        if (item.isSuspicious) {
            suspiciousCount++;
        }

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = itemIndex;
        lvi.iSubItem = COL_TYPE;
        lvi.pszText = (LPTSTR)item.category.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        // 名称
        ListView_SetItemText(m_hListView, itemIndex, COL_NAME,
            (LPTSTR)item.name.c_str());

        // 值
        ListView_SetItemText(m_hListView, itemIndex, COL_VALUE,
            (LPTSTR)item.value.c_str());

        // 路径
        ListView_SetItemText(m_hListView, itemIndex, COL_PATH,
            (LPTSTR)item.location.c_str());

        // 可疑标记
        ListView_SetItemText(m_hListView, itemIndex, COL_SUSPICIOUS,
            item.isSuspicious ? (LPTSTR)TEXT("是") : (LPTSTR)TEXT("否"));

        itemIndex++;
    }

    // 更新状态栏
    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("共 %d 项持久化配置 (可疑: %d 项, 显示: %d 项)"),
        (int)m_items.size(), suspiciousCount, itemIndex);
    SetStatusText(szStatus);
}

// ============================================================================
// 命令处理
// ============================================================================

void PersistenceTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_REFRESH:
        ScanPersistence();
        break;

    case IDC_COMBO_FILTER:
        if (code == CBN_SELCHANGE) {
            ScanPersistence();
        }
        break;
    }

    // 处理复选框
    if (hCtrl == m_hChkSuspiciousOnly && code == BN_CLICKED) {
        FilterResults();
    }
}
