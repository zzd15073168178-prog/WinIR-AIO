// dump_tab.cpp - 内存转储标签页实现
#include "dump_tab.h"
#include <commctrl.h>
#include <strsafe.h>
#include <shellapi.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

DumpTab::DumpTab(HWND hParentTab, DumpManager* pDumpMgr, ProcessManager* pProcMgr)
    : BaseTab(hParentTab)
    , m_pDumpManager(pDumpMgr)
    , m_pProcessManager(pProcMgr)
    , m_hEditPid(NULL)
    , m_hComboDumpType(NULL)
    , m_hBtnDump(NULL)
    , m_hBtnDelete(NULL)
    , m_hBtnOpenFolder(NULL)
{
}

DumpTab::~DumpTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool DumpTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) {
        return false;
    }

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

    ListView_SetExtendedListViewStyle(m_hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    AddColumn(COL_FILE, TEXT("文件名"), 300);
    AddColumn(COL_PID, TEXT("PID"), 80);
    AddColumn(COL_SIZE, TEXT("大小"), 100);
    AddColumn(COL_TIME, TEXT("创建时间"), 150);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void DumpTab::CreateToolbar()
{
    // PID 输入
    CreateWindowEx(0, TEXT("STATIC"), TEXT("PID:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 30, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditPid = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE | ES_NUMBER,
        40, 5, 80, 25,
        m_hWnd, (HMENU)IDC_EDIT_SEARCH, GetModuleHandle(NULL), NULL);

    // 转储类型
    CreateWindowEx(0, TEXT("STATIC"), TEXT("类型:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        130, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hComboDumpType = CreateWindowEx(0, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        175, 5, 100, 100,
        m_hWnd, (HMENU)IDC_COMBO_FILTER, GetModuleHandle(NULL), NULL);

    SendMessage(m_hComboDumpType, CB_ADDSTRING, 0, (LPARAM)TEXT("Mini"));
    SendMessage(m_hComboDumpType, CB_ADDSTRING, 0, (LPARAM)TEXT("Full"));
    SendMessage(m_hComboDumpType, CB_ADDSTRING, 0, (LPARAM)TEXT("MiniPlus"));
    SendMessage(m_hComboDumpType, CB_SETCURSEL, 0, 0);

    // 按钮
    m_hBtnDump = CreateWindowEx(0, TEXT("BUTTON"), TEXT("创建转储"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        285, 5, 90, 25,
        m_hWnd, (HMENU)IDC_BTN_DUMP, GetModuleHandle(NULL), NULL);

    m_hBtnDelete = CreateWindowEx(0, TEXT("BUTTON"), TEXT("删除"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        385, 5, 60, 25,
        m_hWnd, (HMENU)IDC_BTN_DELETE, GetModuleHandle(NULL), NULL);

    m_hBtnOpenFolder = CreateWindowEx(0, TEXT("BUTTON"), TEXT("打开目录"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        455, 5, 80, 25,
        m_hWnd, (HMENU)IDC_BTN_OPENFOLDER, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("刷新列表"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        545, 5, 80, 25,
        m_hWnd, (HMENU)IDC_BTN_REFRESH, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 刷新
// ============================================================================

void DumpTab::Refresh()
{
    if (!m_pDumpManager) {
        return;
    }

    ListView_DeleteAllItems(m_hListView);
    m_dumps = m_pDumpManager->ListDumpFiles();

    for (size_t i = 0; i < m_dumps.size(); i++) {
        const DumpResult& dump = m_dumps[i];

        // 提取文件名
        tstring fileName = dump.dumpPath;
        size_t pos = fileName.rfind(TEXT('\\'));
        if (pos != tstring::npos) {
            fileName = fileName.substr(pos + 1);
        }

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = COL_FILE;
        lvi.pszText = (LPTSTR)fileName.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        // PID
        TCHAR szPid[16];
        StringCchPrintf(szPid, 16, TEXT("%lu"), dump.pid);
        ListView_SetItemText(m_hListView, (int)i, COL_PID, szPid);

        // 大小
        tstring sizeStr = FormatFileSize(dump.fileSize);
        ListView_SetItemText(m_hListView, (int)i, COL_SIZE, (LPTSTR)sizeStr.c_str());

        // 时间
        tstring timeStr = FormatFileTime(dump.createTime);
        ListView_SetItemText(m_hListView, (int)i, COL_TIME, (LPTSTR)timeStr.c_str());
    }

    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("共 %d 个转储文件"), (int)m_dumps.size());
    SetStatusText(szStatus);
}

// ============================================================================
// 创建转储
// ============================================================================

void DumpTab::CreateDump()
{
    if (!m_pDumpManager) {
        return;
    }

    // 检查 procdump 是否可用
    if (!m_pDumpManager->IsProcDumpAvailable()) {
        MessageBox(m_hWnd, TEXT("procdump.exe 未找到，请将其放置在 Tools 目录下"),
            TEXT("错误"), MB_ICONERROR);
        return;
    }

    // 获取 PID
    TCHAR szPid[32];
    GetWindowText(m_hEditPid, szPid, 32);
    DWORD pid = _ttol(szPid);

    if (pid == 0) {
        MessageBox(m_hWnd, TEXT("请输入有效的进程 PID"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    // 获取转储类型
    int typeIndex = (int)SendMessage(m_hComboDumpType, CB_GETCURSEL, 0, 0);
    DumpType dumpType = (DumpType)typeIndex;

    // 设置等待光标
    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));

    SetStatusText(TEXT("正在创建转储..."));

    // 创建转储
    DumpResult result = m_pDumpManager->CreateDump(pid, dumpType);

    SetCursor(hOldCursor);

    if (result.success) {
        MessageBox(m_hWnd,
            (TEXT("转储文件创建成功:\n") + result.dumpPath).c_str(),
            TEXT("成功"), MB_ICONINFORMATION);
        Refresh();
    }
    else {
        MessageBox(m_hWnd,
            (TEXT("转储创建失败:\n") + result.errorMessage).c_str(),
            TEXT("错误"), MB_ICONERROR);
    }

    SetStatusText(TEXT("就绪"));
}

// ============================================================================
// 删除选中的转储
// ============================================================================

void DumpTab::DeleteSelectedDump()
{
    int sel = ListView_GetNextItem(m_hListView, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)m_dumps.size()) {
        MessageBox(m_hWnd, TEXT("请先选择一个转储文件"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    if (MessageBox(m_hWnd, TEXT("确定要删除选中的转储文件吗？"),
        TEXT("确认"), MB_ICONQUESTION | MB_YESNO) == IDYES) {

        if (m_pDumpManager->DeleteDump(m_dumps[sel].dumpPath)) {
            Refresh();
        }
        else {
            MessageBox(m_hWnd, TEXT("删除失败"), TEXT("错误"), MB_ICONERROR);
        }
    }
}

// ============================================================================
// 打开转储目录
// ============================================================================

void DumpTab::OpenDumpFolder()
{
    if (m_pDumpManager) {
        ShellExecute(m_hWnd, TEXT("open"),
            m_pDumpManager->GetOutputDirectory().c_str(),
            NULL, NULL, SW_SHOWNORMAL);
    }
}

// ============================================================================
// 格式化文件大小
// ============================================================================

tstring DumpTab::FormatFileSize(ULONGLONG size)
{
    TCHAR buffer[32];
    if (size >= 1024ULL * 1024 * 1024) {
        StringCchPrintf(buffer, 32, TEXT("%.2f GB"), (double)size / (1024.0 * 1024 * 1024));
    }
    else if (size >= 1024 * 1024) {
        StringCchPrintf(buffer, 32, TEXT("%.2f MB"), (double)size / (1024.0 * 1024));
    }
    else if (size >= 1024) {
        StringCchPrintf(buffer, 32, TEXT("%.2f KB"), (double)size / 1024.0);
    }
    else {
        StringCchPrintf(buffer, 32, TEXT("%llu B"), size);
    }
    return buffer;
}

// ============================================================================
// 格式化时间
// ============================================================================

tstring DumpTab::FormatFileTime(const FILETIME& ft)
{
    SYSTEMTIME st;
    FILETIME localFt;

    FileTimeToLocalFileTime(&ft, &localFt);
    FileTimeToSystemTime(&localFt, &st);

    TCHAR buffer[32];
    StringCchPrintf(buffer, 32, TEXT("%04d-%02d-%02d %02d:%02d"),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

    return buffer;
}

// ============================================================================
// 命令处理
// ============================================================================

void DumpTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_DUMP:
        CreateDump();
        break;

    case IDC_BTN_DELETE:
        DeleteSelectedDump();
        break;

    case IDC_BTN_OPENFOLDER:
        OpenDumpFolder();
        break;

    case IDC_BTN_REFRESH:
        Refresh();
        break;
    }
}
