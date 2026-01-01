// memory_scanner_tab.cpp - 内存扫描标签页实现
#include "memory_scanner_tab.h"
#include <commctrl.h>
#include <strsafe.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

MemoryScannerTab::MemoryScannerTab(HWND hParentTab, MemoryScanner* pScanner)
    : BaseTab(hParentTab)
    , m_pScanner(pScanner)
    , m_currentPid(0)
    , m_hEditPid(NULL)
    , m_hEditPattern(NULL)
    , m_hBtnScan(NULL)
    , m_hChkStrings(NULL)
    , m_hChkIPs(NULL)
    , m_hChkURLs(NULL)
{
}

MemoryScannerTab::~MemoryScannerTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool MemoryScannerTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) {
        return false;
    }

    // 创建工具栏区域
    CreateToolbar();

    // 创建 ListView
    RECT listRect = rc;
    listRect.top = 70; // 工具栏高度 (两行)

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
    AddColumn(COL_ADDRESS, TEXT("地址"), 120);
    AddColumn(COL_TYPE, TEXT("类型"), 100);
    AddColumn(COL_VALUE, TEXT("值"), 250);
    AddColumn(COL_CONTEXT, TEXT("上下文"), 400);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void MemoryScannerTab::CreateToolbar()
{
    // 第一行：PID 和自定义模式
    CreateWindowEx(0, TEXT("STATIC"), TEXT("进程 PID:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 70, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditPid = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE | ES_NUMBER,
        80, 5, 80, 25,
        m_hWnd, (HMENU)IDC_EDIT_SEARCH, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("STATIC"), TEXT("自定义模式:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        170, 5, 80, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditPattern = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE,
        255, 5, 200, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hBtnScan = CreateWindowEx(0, TEXT("BUTTON"), TEXT("开始扫描"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        465, 5, 90, 25,
        m_hWnd, (HMENU)IDC_BTN_REFRESH, GetModuleHandle(NULL), NULL);

    // 第二行：预设扫描选项
    m_hChkStrings = CreateWindowEx(0, TEXT("BUTTON"), TEXT("扫描字符串"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        5, 35, 100, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(m_hChkStrings, BM_SETCHECK, BST_CHECKED, 0);

    m_hChkIPs = CreateWindowEx(0, TEXT("BUTTON"), TEXT("IP 地址"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        115, 35, 80, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(m_hChkIPs, BM_SETCHECK, BST_CHECKED, 0);

    m_hChkURLs = CreateWindowEx(0, TEXT("BUTTON"), TEXT("URL/路径"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        205, 35, 90, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(m_hChkURLs, BM_SETCHECK, BST_CHECKED, 0);
}

// ============================================================================
// 刷新数据
// ============================================================================

void MemoryScannerTab::Refresh()
{
    if (m_currentPid != 0) {
        ScanMemory();
    }
}

// ============================================================================
// 扫描内存
// ============================================================================

void MemoryScannerTab::ScanMemory()
{
    if (!m_pScanner) {
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

    ListView_DeleteAllItems(m_hListView);
    m_results.clear();

    // 检查扫描选项
    bool scanStrings = (SendMessage(m_hChkStrings, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool scanIPs = (SendMessage(m_hChkIPs, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool scanURLs = (SendMessage(m_hChkURLs, BM_GETCHECK, 0, 0) == BST_CHECKED);

    // 获取自定义模式
    TCHAR szPattern[256] = { 0 };
    GetWindowText(m_hEditPattern, szPattern, 256);

    // 执行扫描
    if (szPattern[0] != 0) {
        // 自定义模式扫描
        ScanPattern customPattern;
        customPattern.name = TEXT("自定义");
        customPattern.pattern = szPattern;
        customPattern.category = TEXT("Custom");
        customPattern.isRegex = false;
        auto results = m_pScanner->ScanProcessForPattern(m_currentPid, customPattern);
        m_results.insert(m_results.end(), results.begin(), results.end());
    }
    else {
        // 使用内置模式扫描进程
        auto results = m_pScanner->ScanProcess(m_currentPid);

        // 根据选项过滤
        for (const auto& result : results) {
            bool include = false;
            if (scanStrings) include = true;
            if (scanIPs && result.category == TEXT("IP")) include = true;
            if (scanURLs && (result.category == TEXT("URL") || result.category == TEXT("Path"))) include = true;

            if (include) {
                m_results.push_back(result);
            }
        }
    }

    // 显示结果
    for (size_t i = 0; i < m_results.size(); i++) {
        const MemoryScanResult& result = m_results[i];

        // 地址
        TCHAR szAddr[32];
        StringCchPrintf(szAddr, 32, TEXT("0x%p"), result.address);

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = COL_ADDRESS;
        lvi.pszText = szAddr;
        ListView_InsertItem(m_hListView, &lvi);

        // 类型 (使用 category)
        ListView_SetItemText(m_hListView, (int)i, COL_TYPE,
            (LPTSTR)result.category.c_str());

        // 值 (使用 matchedContent)
        ListView_SetItemText(m_hListView, (int)i, COL_VALUE,
            (LPTSTR)result.matchedContent.c_str());

        // 上下文 (使用 pattern)
        ListView_SetItemText(m_hListView, (int)i, COL_CONTEXT,
            (LPTSTR)result.pattern.c_str());
    }

    // 更新状态栏
    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("PID %lu: 找到 %d 个匹配项"),
        m_currentPid, (int)m_results.size());
    SetStatusText(szStatus);

    // 恢复光标
    SetCursor(hOldCursor);
}

// ============================================================================
// 命令处理
// ============================================================================

void MemoryScannerTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_REFRESH:
        ScanMemory();
        break;
    }
}
