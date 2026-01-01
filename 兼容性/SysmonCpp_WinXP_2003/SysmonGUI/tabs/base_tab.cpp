// base_tab.cpp - Tab 页基类实现
#include "base_tab.h"
#include <tchar.h>
#include <windowsx.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

BaseTab::BaseTab(HWND hParentTab, const tstring& title)
    : m_hParentTab(hParentTab)
    , m_hWnd(NULL)
    , m_hListView(NULL)
    , m_hToolbar(NULL)
    , m_hSearchEdit(NULL)
    , m_title(title)
    , m_sortColumn(-1)
    , m_sortAscending(true)
{
}

BaseTab::~BaseTab()
{
    if (m_hWnd && IsWindow(m_hWnd)) {
        DestroyWindow(m_hWnd);
    }
}

// ============================================================================
// 创建 Tab 内容窗口
// ============================================================================

bool BaseTab::Create(const RECT& rc)
{
    // 注册窗口类
    static bool classRegistered = false;
    if (!classRegistered) {
        WNDCLASSEX wcex;
        wcex.cbSize = sizeof(WNDCLASSEX);
        wcex.style = CS_HREDRAW | CS_VREDRAW;
        wcex.lpfnWndProc = TabWndProc;
        wcex.cbClsExtra = 0;
        wcex.cbWndExtra = sizeof(LONG_PTR);
        wcex.hInstance = GetModuleHandle(NULL);
        wcex.hIcon = NULL;
        wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
        wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wcex.lpszMenuName = NULL;
        wcex.lpszClassName = TEXT("SysmonTabClass");
        wcex.hIconSm = NULL;
        RegisterClassEx(&wcex);
        classRegistered = true;
    }

    // 创建窗口 - 使用 rc 中的坐标（相对于父窗口 Tab 控件）
    // rc.left 和 rc.top 是 Tab 内容区域的起始位置（排除标签头）
    m_hWnd = CreateWindowEx(
        0,
        TEXT("SysmonTabClass"),
        m_title.c_str(),
        WS_CHILD | WS_CLIPCHILDREN,
        rc.left, rc.top,
        rc.right - rc.left, rc.bottom - rc.top,
        m_hParentTab,
        NULL,
        GetModuleHandle(NULL),
        this);

    return m_hWnd != NULL;
}

// ============================================================================
// 窗口过程
// ============================================================================

LRESULT CALLBACK BaseTab::TabWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    BaseTab* pThis = NULL;

    if (msg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (BaseTab*)pCreate->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
        pThis->m_hWnd = hWnd;
    } else {
        pThis = (BaseTab*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    if (pThis) {
        return pThis->HandleMessage(msg, wParam, lParam);
    }

    return DefWindowProc(hWnd, msg, wParam, lParam);
}

LRESULT BaseTab::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_SIZE:
    {
        RECT rc;
        GetClientRect(m_hWnd, &rc);
        Resize(rc);
        return 0;
    }

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->hwndFrom == m_hListView) {
            switch (pnmh->code) {
            case LVN_COLUMNCLICK:
            {
                LPNMLISTVIEW pnmlv = (LPNMLISTVIEW)lParam;
                SortListView(pnmlv->iSubItem);
                break;
            }
            case NM_RCLICK:
            {
                POINT pt;
                GetCursorPos(&pt);
                ShowContextMenu(pt.x, pt.y);
                break;
            }
            case NM_DBLCLK:
            {
                // 双击处理 - 子类可重写
                break;
            }
            }
        }
        break;
    }

    case WM_CONTEXTMENU:
        if ((HWND)wParam == m_hListView) {
            ShowContextMenu(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            return 0;
        }
        break;
    }

    return DefWindowProc(m_hWnd, msg, wParam, lParam);
}

// ============================================================================
// 显示/隐藏
// ============================================================================

void BaseTab::Show(bool bShow)
{
    if (m_hWnd) {
        ShowWindow(m_hWnd, bShow ? SW_SHOW : SW_HIDE);
    }
}

// ============================================================================
// 调整大小
// ============================================================================

void BaseTab::Resize(const RECT& rc)
{
    if (m_hWnd) {
        MoveWindow(m_hWnd, rc.left, rc.top,
            rc.right - rc.left, rc.bottom - rc.top, TRUE);
    }

    // 调整 ListView
    if (m_hListView) {
        RECT rcClient;
        GetClientRect(m_hWnd, &rcClient);

        int toolbarHeight = 35;
        MoveWindow(m_hListView, 0, toolbarHeight,
            rcClient.right, rcClient.bottom - toolbarHeight, TRUE);
    }
}

// ============================================================================
// 创建 ListView
// ============================================================================

HWND BaseTab::CreateListView(const RECT& rc, const std::vector<tstring>& columns,
    const std::vector<int>& widths)
{
    int toolbarHeight = 35;

    m_hListView = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEW,
        NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
        0, toolbarHeight,
        rc.right - rc.left, rc.bottom - rc.top - toolbarHeight,
        m_hWnd,
        (HMENU)IDC_LISTVIEW,
        GetModuleHandle(NULL),
        NULL);

    if (!m_hListView) {
        return NULL;
    }

    // 设置扩展样式
    ListView_SetExtendedListViewStyle(m_hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);

    // 添加列
    LVCOLUMN lvc;
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    for (size_t i = 0; i < columns.size(); i++) {
        lvc.iSubItem = (int)i;
        lvc.pszText = (LPTSTR)columns[i].c_str();
        lvc.cx = (i < widths.size()) ? widths[i] : 100;
        ListView_InsertColumn(m_hListView, (int)i, &lvc);
    }

    return m_hListView;
}

// ============================================================================
// 创建工具栏区域
// ============================================================================

void BaseTab::CreateToolbarArea(int height)
{
    // 工具栏使用窗口顶部区域
    // 具体控件由子类添加
}

// ============================================================================
// 添加工具栏控件
// ============================================================================

HWND BaseTab::AddButton(int x, int y, int width, int height, WORD id, const tstring& text)
{
    HWND hButton = CreateWindowEx(
        0,
        TEXT("BUTTON"),
        text.c_str(),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, y, width, height,
        m_hWnd,
        (HMENU)(UINT_PTR)id,
        GetModuleHandle(NULL),
        NULL);

    // 设置字体
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(hButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    return hButton;
}

HWND BaseTab::AddEdit(int x, int y, int width, int height, WORD id)
{
    HWND hEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        TEXT("EDIT"),
        NULL,
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        x, y, width, height,
        m_hWnd,
        (HMENU)(UINT_PTR)id,
        GetModuleHandle(NULL),
        NULL);

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    return hEdit;
}

HWND BaseTab::AddComboBox(int x, int y, int width, int height, WORD id)
{
    HWND hCombo = CreateWindowEx(
        0,
        TEXT("COMBOBOX"),
        NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        x, y, width, height,
        m_hWnd,
        (HMENU)(UINT_PTR)id,
        GetModuleHandle(NULL),
        NULL);

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(hCombo, WM_SETFONT, (WPARAM)hFont, TRUE);

    return hCombo;
}

HWND BaseTab::AddLabel(int x, int y, int width, int height, const tstring& text)
{
    HWND hLabel = CreateWindowEx(
        0,
        TEXT("STATIC"),
        text.c_str(),
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        x, y, width, height,
        m_hWnd,
        NULL,
        GetModuleHandle(NULL),
        NULL);

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    return hLabel;
}

// ============================================================================
// ListView 操作
// ============================================================================

void BaseTab::AddColumn(int index, const tstring& text, int width)
{
    if (!m_hListView) return;

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.iSubItem = index;
    lvc.pszText = (LPTSTR)text.c_str();
    lvc.cx = width;
    ListView_InsertColumn(m_hListView, index, &lvc);
}

void BaseTab::ClearListView()
{
    if (m_hListView) {
        ListView_DeleteAllItems(m_hListView);
    }
}

int BaseTab::AddListViewItem(const std::vector<tstring>& values)
{
    if (!m_hListView || values.empty()) {
        return -1;
    }

    LVITEM lvi;
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(m_hListView);
    lvi.iSubItem = 0;
    lvi.pszText = (LPTSTR)values[0].c_str();

    int index = ListView_InsertItem(m_hListView, &lvi);

    // 设置子项
    for (size_t i = 1; i < values.size(); i++) {
        ListView_SetItemText(m_hListView, index, (int)i, (LPTSTR)values[i].c_str());
    }

    return index;
}

void BaseTab::SetListViewItemText(int item, int subItem, const tstring& text)
{
    if (m_hListView) {
        ListView_SetItemText(m_hListView, item, subItem, (LPTSTR)text.c_str());
    }
}

void BaseTab::AutoSizeColumns()
{
    if (!m_hListView) return;

    HWND hHeader = ListView_GetHeader(m_hListView);
    int columnCount = Header_GetItemCount(hHeader);

    for (int i = 0; i < columnCount; i++) {
        ListView_SetColumnWidth(m_hListView, i, LVSCW_AUTOSIZE_USEHEADER);
    }
}

// ============================================================================
// 排序
// ============================================================================

void BaseTab::SortListView(int column)
{
    if (column == m_sortColumn) {
        m_sortAscending = !m_sortAscending;
    } else {
        m_sortColumn = column;
        m_sortAscending = true;
    }

    // 子类应重写此方法实现具体排序逻辑
}

int CALLBACK BaseTab::CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
    // 默认比较 - 子类可提供自定义比较
    return 0;
}

// ============================================================================
// 获取选中项
// ============================================================================

int BaseTab::GetSelectedItem()
{
    if (!m_hListView) return -1;
    return ListView_GetNextItem(m_hListView, -1, LVNI_SELECTED);
}

std::vector<int> BaseTab::GetSelectedItems()
{
    std::vector<int> items;
    if (!m_hListView) return items;

    int index = -1;
    while ((index = ListView_GetNextItem(m_hListView, index, LVNI_SELECTED)) != -1) {
        items.push_back(index);
    }
    return items;
}

// ============================================================================
// 状态栏更新
// ============================================================================

void BaseTab::SetStatusText(const tstring& text)
{
    // 通过主窗口更新状态栏
    HWND hMainWnd = GetParent(GetParent(m_hWnd));  // Tab -> TabControl -> MainWindow
    if (hMainWnd) {
        // 找到状态栏并更新
        HWND hStatusBar = FindWindowEx(hMainWnd, NULL, STATUSCLASSNAME, NULL);
        if (hStatusBar) {
            SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)text.c_str());
        }
    }
}
