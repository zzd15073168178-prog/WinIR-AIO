// hash_tab.cpp - 哈希计算标签页实现
#include "hash_tab.h"
#include <commctrl.h>
#include <strsafe.h>
#include <shlobj.h>
#include <commdlg.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

HashTab::HashTab(HWND hParentTab, HashManager* pManager)
    : BaseTab(hParentTab)
    , m_pManager(pManager)
    , m_hEditPath(NULL)
    , m_hBtnBrowse(NULL)
    , m_hBtnCalculate(NULL)
    , m_hChkMD5(NULL)
    , m_hChkSHA1(NULL)
    , m_hChkSHA256(NULL)
    , m_hProgress(NULL)
{
}

HashTab::~HashTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool HashTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) {
        return false;
    }

    // 创建工具栏区域
    CreateToolbar();

    // 创建 ListView
    RECT listRect = rc;
    listRect.top = 70; // 工具栏高度

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
    AddColumn(COL_FILE, TEXT("文件名"), 200);
    AddColumn(COL_SIZE, TEXT("大小"), 100);
    AddColumn(COL_MD5, TEXT("MD5"), 250);
    AddColumn(COL_SHA1, TEXT("SHA1"), 320);
    AddColumn(COL_SHA256, TEXT("SHA256"), 500);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void HashTab::CreateToolbar()
{
    // 第一行：文件路径
    CreateWindowEx(0, TEXT("STATIC"), TEXT("文件/目录:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 70, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditPath = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        80, 5, 350, 25,
        m_hWnd, (HMENU)IDC_EDIT_SEARCH, GetModuleHandle(NULL), NULL);

    m_hBtnBrowse = CreateWindowEx(0, TEXT("BUTTON"), TEXT("浏览..."),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        435, 5, 70, 25,
        m_hWnd, (HMENU)IDC_BTN_BROWSE, GetModuleHandle(NULL), NULL);

    m_hBtnCalculate = CreateWindowEx(0, TEXT("BUTTON"), TEXT("计算哈希"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        510, 5, 90, 25,
        m_hWnd, (HMENU)IDC_BTN_REFRESH, GetModuleHandle(NULL), NULL);

    // 第二行：选项和进度条
    m_hChkMD5 = CreateWindowEx(0, TEXT("BUTTON"), TEXT("MD5"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        5, 35, 60, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(m_hChkMD5, BM_SETCHECK, BST_CHECKED, 0);

    m_hChkSHA1 = CreateWindowEx(0, TEXT("BUTTON"), TEXT("SHA1"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        70, 35, 65, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(m_hChkSHA1, BM_SETCHECK, BST_CHECKED, 0);

    m_hChkSHA256 = CreateWindowEx(0, TEXT("BUTTON"), TEXT("SHA256"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        140, 35, 80, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(m_hChkSHA256, BM_SETCHECK, BST_CHECKED, 0);

    m_hProgress = CreateWindowEx(0, PROGRESS_CLASS, NULL,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        230, 38, 370, 18,
        m_hWnd, (HMENU)IDC_PROGRESS, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 刷新数据
// ============================================================================

void HashTab::Refresh()
{
    CalculateHash();
}

// ============================================================================
// 浏览文件
// ============================================================================

void HashTab::BrowseFile()
{
    TCHAR szPath[MAX_PATH] = { 0 };

    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hWnd;
    ofn.lpstrFile = szPath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = TEXT("所有文件\0*.*\0可执行文件\0*.exe;*.dll;*.sys\0");
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        SetWindowText(m_hEditPath, szPath);
    }
}

// ============================================================================
// 计算哈希
// ============================================================================

void HashTab::CalculateHash()
{
    if (!m_pManager) {
        return;
    }

    TCHAR szPath[MAX_PATH];
    GetWindowText(m_hEditPath, szPath, MAX_PATH);

    if (szPath[0] == 0) {
        MessageBox(m_hWnd, TEXT("请输入文件或目录路径"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    // 设置等待光标
    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));

    // 重置进度条
    SendMessage(m_hProgress, PBM_SETPOS, 0, 0);

    // 获取选项
    bool calcMD5 = (SendMessage(m_hChkMD5, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool calcSHA1 = (SendMessage(m_hChkSHA1, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool calcSHA256 = (SendMessage(m_hChkSHA256, BM_GETCHECK, 0, 0) == BST_CHECKED);

    // 检查是文件还是目录
    DWORD attrs = GetFileAttributes(szPath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        MessageBox(m_hWnd, TEXT("路径不存在"), TEXT("错误"), MB_ICONERROR);
        SetCursor(hOldCursor);
        return;
    }

    m_results.clear();

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        // 扫描目录 (recursive=true)
        m_results = m_pManager->CalculateDirectoryHashes(szPath, true);
    }
    else {
        // 单个文件
        FileHashResult result = m_pManager->CalculateFileHash(szPath);
        if (result.error.empty()) {
            m_results.push_back(result);
        }
    }

    // 更新 ListView
    ListView_DeleteAllItems(m_hListView);

    for (size_t i = 0; i < m_results.size(); i++) {
        const FileHashResult& result = m_results[i];

        // 提取文件名
        tstring fileName = result.filePath;
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

        // 大小
        TCHAR szSize[32];
        if (result.fileSize >= 1024 * 1024) {
            StringCchPrintf(szSize, 32, TEXT("%.2f MB"),
                (double)result.fileSize / (1024 * 1024));
        }
        else if (result.fileSize >= 1024) {
            StringCchPrintf(szSize, 32, TEXT("%.2f KB"),
                (double)result.fileSize / 1024);
        }
        else {
            StringCchPrintf(szSize, 32, TEXT("%llu B"), result.fileSize);
        }
        ListView_SetItemText(m_hListView, (int)i, COL_SIZE, szSize);

        // MD5
        ListView_SetItemText(m_hListView, (int)i, COL_MD5,
            (LPTSTR)result.md5.c_str());

        // SHA1
        ListView_SetItemText(m_hListView, (int)i, COL_SHA1,
            (LPTSTR)result.sha1.c_str());

        // SHA256
        ListView_SetItemText(m_hListView, (int)i, COL_SHA256,
            (LPTSTR)result.sha256.c_str());
    }

    // 完成进度
    SendMessage(m_hProgress, PBM_SETPOS, 100, 0);

    // 更新状态栏
    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("计算完成: %d 个文件"), (int)m_results.size());
    SetStatusText(szStatus);

    // 恢复光标
    SetCursor(hOldCursor);
}

// ============================================================================
// 进度回调
// ============================================================================

void CALLBACK HashTab::ProgressCallback(DWORD current, DWORD total, void* context)
{
    HashTab* pThis = (HashTab*)context;
    if (pThis && pThis->m_hProgress) {
        int percent = (total > 0) ? (int)(current * 100 / total) : 0;
        SendMessage(pThis->m_hProgress, PBM_SETPOS, percent, 0);
    }
}

// ============================================================================
// 命令处理
// ============================================================================

void HashTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_BROWSE:
        BrowseFile();
        break;

    case IDC_BTN_REFRESH:
        CalculateHash();
        break;
    }
}
