// file_locker_tab.cpp - 文件锁定分析标签页实现
#include "file_locker_tab.h"
#include <commctrl.h>
#include <strsafe.h>
#include <commdlg.h>
#include <shlobj.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

FileLockerTab::FileLockerTab(HWND hParentTab, FileLocker* pFileLocker, ProcessManager* pProcMgr)
    : BaseTab(hParentTab)
    , m_pFileLocker(pFileLocker)
    , m_pProcessManager(pProcMgr)
    , m_hEditPath(NULL)
    , m_hBtnBrowse(NULL)
    , m_hBtnAnalyze(NULL)
    , m_hBtnKill(NULL)
{
}

FileLockerTab::~FileLockerTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool FileLockerTab::Create(const RECT& rc)
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

    AddColumn(COL_PROCESS, TEXT("进程名"), 150);
    AddColumn(COL_PID, TEXT("PID"), 80);
    AddColumn(COL_HANDLE, TEXT("句柄"), 100);
    AddColumn(COL_TYPE, TEXT("类型"), 80);
    AddColumn(COL_PATH, TEXT("文件路径"), 500);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void FileLockerTab::CreateToolbar()
{
    // 文件路径输入
    CreateWindowEx(0, TEXT("STATIC"), TEXT("文件路径:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 65, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditPath = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        75, 5, 400, 25,
        m_hWnd, (HMENU)IDC_EDIT_PATH, GetModuleHandle(NULL), NULL);

    // 浏览按钮
    m_hBtnBrowse = CreateWindowEx(0, TEXT("BUTTON"), TEXT("..."),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        480, 5, 30, 25,
        m_hWnd, (HMENU)IDC_BTN_BROWSE, GetModuleHandle(NULL), NULL);

    // 分析按钮
    m_hBtnAnalyze = CreateWindowEx(0, TEXT("BUTTON"), TEXT("分析锁定"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        520, 5, 80, 25,
        m_hWnd, (HMENU)IDC_BTN_ANALYZE, GetModuleHandle(NULL), NULL);

    // 终止进程按钮
    m_hBtnKill = CreateWindowEx(0, TEXT("BUTTON"), TEXT("终止进程"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        610, 5, 80, 25,
        m_hWnd, (HMENU)IDC_BTN_KILL, GetModuleHandle(NULL), NULL);

    // 复制路径按钮
    CreateWindowEx(0, TEXT("BUTTON"), TEXT("复制路径"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        700, 5, 80, 25,
        m_hWnd, (HMENU)IDC_BTN_COPY, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 刷新
// ============================================================================

void FileLockerTab::Refresh()
{
    // 如果有路径，重新分析
    TCHAR szPath[MAX_PATH];
    GetWindowText(m_hEditPath, szPath, MAX_PATH);
    if (lstrlen(szPath) > 0) {
        AnalyzeFile();
    }
}

// ============================================================================
// 浏览文件
// ============================================================================

void FileLockerTab::BrowseFile()
{
    OPENFILENAME ofn = { 0 };
    TCHAR szFile[MAX_PATH] = TEXT("");

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hWnd;
    ofn.lpstrFilter = TEXT("所有文件 (*.*)\0*.*\0");
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = TEXT("选择要分析的文件");

    if (GetOpenFileName(&ofn)) {
        SetWindowText(m_hEditPath, szFile);
        AnalyzeFile();
    }
}

// ============================================================================
// 分析文件锁定
// ============================================================================

void FileLockerTab::AnalyzeFile()
{
    if (!m_pFileLocker) {
        return;
    }

    TCHAR szPath[MAX_PATH];
    GetWindowText(m_hEditPath, szPath, MAX_PATH);

    if (lstrlen(szPath) == 0) {
        MessageBox(m_hWnd, TEXT("请输入或选择要分析的文件路径"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    // 检查文件是否存在
    DWORD dwAttr = GetFileAttributes(szPath);
    if (dwAttr == INVALID_FILE_ATTRIBUTES) {
        MessageBox(m_hWnd, TEXT("指定的文件不存在"), TEXT("错误"), MB_ICONERROR);
        return;
    }

    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    SetStatusText(TEXT("正在分析文件锁定..."));

    ListView_DeleteAllItems(m_hListView);
    m_lockedFiles.clear();

    m_lockedFiles = m_pFileLocker->FindLockingProcesses(szPath);

    // 显示结果
    for (size_t i = 0; i < m_lockedFiles.size(); i++) {
        const LockedFileInfo& info = m_lockedFiles[i];

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = COL_PROCESS;
        lvi.pszText = (LPTSTR)info.processName.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        TCHAR szPid[16];
        StringCchPrintf(szPid, 16, TEXT("%lu"), info.pid);
        ListView_SetItemText(m_hListView, (int)i, COL_PID, szPid);

        TCHAR szHandle[32];
        StringCchPrintf(szHandle, 32, TEXT("0x%08X"), info.handleValue);
        ListView_SetItemText(m_hListView, (int)i, COL_HANDLE, szHandle);

        ListView_SetItemText(m_hListView, (int)i, COL_TYPE,
            (LPTSTR)info.accessMode.c_str());

        ListView_SetItemText(m_hListView, (int)i, COL_PATH,
            (LPTSTR)info.filePath.c_str());
    }

    SetCursor(hOldCursor);

    TCHAR szStatus[128];
    if (m_lockedFiles.empty()) {
        StringCchPrintf(szStatus, 128, TEXT("文件未被任何进程锁定"));
    }
    else {
        StringCchPrintf(szStatus, 128, TEXT("发现 %d 个进程锁定该文件"),
            (int)m_lockedFiles.size());
    }
    SetStatusText(szStatus);
}

// ============================================================================
// 终止选中的进程
// ============================================================================

void FileLockerTab::KillProcess()
{
    int sel = ListView_GetNextItem(m_hListView, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)m_lockedFiles.size()) {
        MessageBox(m_hWnd, TEXT("请先选择一个进程"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    const LockedFileInfo& info = m_lockedFiles[sel];

    tstring msg = TEXT("确定要终止进程 \"") + info.processName +
        TEXT("\" (PID: ") + std::to_wstring(info.pid) + TEXT(") 吗？\n\n");
    msg += TEXT("警告：强制终止进程可能导致数据丢失！");

    if (MessageBox(m_hWnd, msg.c_str(), TEXT("确认"), MB_ICONWARNING | MB_YESNO) == IDYES) {
        if (m_pProcessManager) {
            tstring errorMsg;
            if (m_pProcessManager->TerminateProcess(info.pid, errorMsg)) {
                MessageBox(m_hWnd, TEXT("进程已终止"), TEXT("成功"), MB_ICONINFORMATION);
                AnalyzeFile();  // 刷新列表
            }
            else {
                tstring errText = TEXT("无法终止进程: ") + errorMsg;
                MessageBox(m_hWnd, errText.c_str(),
                    TEXT("错误"), MB_ICONERROR);
            }
        }
    }
}

// ============================================================================
// 复制文件路径到剪贴板
// ============================================================================

void FileLockerTab::CopyPath()
{
    TCHAR szPath[MAX_PATH];
    GetWindowText(m_hEditPath, szPath, MAX_PATH);

    if (lstrlen(szPath) == 0) {
        return;
    }

    if (OpenClipboard(m_hWnd)) {
        EmptyClipboard();

        size_t len = (lstrlen(szPath) + 1) * sizeof(TCHAR);
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);

        if (hMem) {
            LPTSTR pszDest = (LPTSTR)GlobalLock(hMem);
            if (pszDest) {
                StringCchCopy(pszDest, lstrlen(szPath) + 1, szPath);
                GlobalUnlock(hMem);

#ifdef UNICODE
                SetClipboardData(CF_UNICODETEXT, hMem);
#else
                SetClipboardData(CF_TEXT, hMem);
#endif
            }
        }

        CloseClipboard();
        SetStatusText(TEXT("路径已复制到剪贴板"));
    }
}

// ============================================================================
// 命令处理
// ============================================================================

void FileLockerTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_BROWSE:
        BrowseFile();
        break;

    case IDC_BTN_ANALYZE:
        AnalyzeFile();
        break;

    case IDC_BTN_KILL:
        KillProcess();
        break;

    case IDC_BTN_COPY:
        CopyPath();
        break;

    case IDC_EDIT_PATH:
        if (code == EN_CHANGE) {
            // 可以在这里添加延迟自动分析
        }
        break;
    }
}
