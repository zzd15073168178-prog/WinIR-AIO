// yara_tab.cpp - YARA 扫描标签页实现
#include "yara_tab.h"
#include <commctrl.h>
#include <strsafe.h>
#include <commdlg.h>
#include <shlobj.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

YaraTab::YaraTab(HWND hParentTab, YaraScanner* pYaraScanner, ProcessManager* pProcMgr)
    : BaseTab(hParentTab)
    , m_pYaraScanner(pYaraScanner)
    , m_pProcessManager(pProcMgr)
    , m_hEditTarget(NULL)
    , m_hComboProcess(NULL)
    , m_hStaticRules(NULL)
{
}

YaraTab::~YaraTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool YaraTab::Create(const RECT& rc)
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

    AddColumn(COL_RULE, TEXT("规则名"), 200);
    AddColumn(COL_NAMESPACE, TEXT("命名空间"), 120);
    AddColumn(COL_FILE, TEXT("匹配文件"), 400);
    AddColumn(COL_STRINGS, TEXT("匹配字符串"), 300);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void YaraTab::CreateToolbar()
{
    // 第一行：规则加载
    CreateWindowEx(0, TEXT("BUTTON"), TEXT("加载规则文件"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        5, 5, 110, 25,
        m_hWnd, (HMENU)IDC_BTN_LOAD_RULES, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("加载规则目录"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        125, 5, 110, 25,
        m_hWnd, (HMENU)IDC_BTN_LOAD_RULES_DIR, GetModuleHandle(NULL), NULL);

    // 规则状态
    m_hStaticRules = CreateWindowEx(0, TEXT("STATIC"), TEXT("规则: 0 个已加载"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        250, 5, 200, 25,
        m_hWnd, (HMENU)IDC_STATIC_RULES, GetModuleHandle(NULL), NULL);

    // 清空按钮
    CreateWindowEx(0, TEXT("BUTTON"), TEXT("清空结果"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        470, 5, 80, 25,
        m_hWnd, (HMENU)IDC_BTN_CLEAR, GetModuleHandle(NULL), NULL);

    // 第二行：扫描目标
    CreateWindowEx(0, TEXT("STATIC"), TEXT("目标:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 38, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditTarget = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        50, 38, 300, 25,
        m_hWnd, (HMENU)IDC_EDIT_TARGET, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("文件"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        360, 38, 50, 25,
        m_hWnd, (HMENU)IDC_BTN_BROWSE_FILE, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("目录"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        415, 38, 50, 25,
        m_hWnd, (HMENU)IDC_BTN_BROWSE_DIR, GetModuleHandle(NULL), NULL);

    // 扫描按钮
    CreateWindowEx(0, TEXT("BUTTON"), TEXT("扫描文件"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        480, 38, 80, 25,
        m_hWnd, (HMENU)IDC_BTN_SCAN_FILE, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("扫描目录"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        570, 38, 80, 25,
        m_hWnd, (HMENU)IDC_BTN_SCAN_DIR, GetModuleHandle(NULL), NULL);

    // 进程扫描
    CreateWindowEx(0, TEXT("STATIC"), TEXT("进程:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        665, 38, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hComboProcess = CreateWindowEx(0, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        710, 38, 150, 200,
        m_hWnd, (HMENU)IDC_COMBO_PROCESS, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("扫描"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        870, 38, 50, 25,
        m_hWnd, (HMENU)IDC_BTN_SCAN_PROCESS, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 刷新
// ============================================================================

void YaraTab::Refresh()
{
    // 刷新进程列表
    SendMessage(m_hComboProcess, CB_RESETCONTENT, 0, 0);
    SendMessage(m_hComboProcess, CB_ADDSTRING, 0, (LPARAM)TEXT("(选择进程)"));

    if (m_pProcessManager) {
        std::vector<ProcessInfo> processes = m_pProcessManager->GetAllProcesses();
        for (const auto& proc : processes) {
            tstring item = proc.name + TEXT(" (") + std::to_wstring(proc.pid) + TEXT(")");
            SendMessage(m_hComboProcess, CB_ADDSTRING, 0, (LPARAM)item.c_str());
        }
    }

    SendMessage(m_hComboProcess, CB_SETCURSEL, 0, 0);

    UpdateRulesStatus();
}

// ============================================================================
// 更新规则状态
// ============================================================================

void YaraTab::UpdateRulesStatus()
{
    if (m_pYaraScanner) {
        TCHAR szStatus[64];
        StringCchPrintf(szStatus, 64, TEXT("规则: %d 个已加载"),
            (int)m_pYaraScanner->GetLoadedRulesCount());
        SetWindowText(m_hStaticRules, szStatus);
    }
}

// ============================================================================
// 加载规则文件
// ============================================================================

void YaraTab::LoadRulesFromFile()
{
    if (!m_pYaraScanner) {
        return;
    }

    if (!m_pYaraScanner->IsYaraAvailable()) {
        MessageBox(m_hWnd,
            TEXT("yara64.exe/yara32.exe 未找到，请将其放置在 Tools 目录下"),
            TEXT("错误"), MB_ICONERROR);
        return;
    }

    OPENFILENAME ofn = { 0 };
    TCHAR szFile[MAX_PATH] = TEXT("");

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hWnd;
    ofn.lpstrFilter = TEXT("YARA 规则 (*.yar;*.yara)\0*.yar;*.yara\0所有文件 (*.*)\0*.*\0");
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = TEXT("选择 YARA 规则文件");

    if (GetOpenFileName(&ofn)) {
        if (m_pYaraScanner->LoadRulesFromFile(szFile)) {
            UpdateRulesStatus();
            SetStatusText(TEXT("规则加载成功"));
        }
        else {
            MessageBox(m_hWnd, TEXT("规则加载失败"), TEXT("错误"), MB_ICONERROR);
        }
    }
}

// ============================================================================
// 加载规则目录
// ============================================================================

void YaraTab::LoadRulesFromDirectory()
{
    if (!m_pYaraScanner) {
        return;
    }

    BROWSEINFO bi = { 0 };
    bi.hwndOwner = m_hWnd;
    bi.lpszTitle = TEXT("选择 YARA 规则目录");
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
    if (pidl) {
        TCHAR szPath[MAX_PATH];
        if (SHGetPathFromIDList(pidl, szPath)) {
            int count = m_pYaraScanner->LoadRulesFromDirectory(szPath);

            UpdateRulesStatus();

            TCHAR szMsg[128];
            StringCchPrintf(szMsg, 128, TEXT("已加载 %d 个规则文件"), count);
            SetStatusText(szMsg);
        }
        CoTaskMemFree(pidl);
    }
}

// ============================================================================
// 扫描文件
// ============================================================================

void YaraTab::ScanFile()
{
    if (!m_pYaraScanner) {
        return;
    }

    TCHAR szTarget[MAX_PATH];
    GetWindowText(m_hEditTarget, szTarget, MAX_PATH);

    if (lstrlen(szTarget) == 0) {
        MessageBox(m_hWnd, TEXT("请输入或选择要扫描的文件"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    if (m_pYaraScanner->GetLoadedRulesCount() == 0) {
        MessageBox(m_hWnd, TEXT("请先加载 YARA 规则"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    SetStatusText(TEXT("正在扫描文件..."));

    std::vector<YaraMatch> newMatches = m_pYaraScanner->ScanFile(szTarget);

    m_matches.insert(m_matches.end(), newMatches.begin(), newMatches.end());

    // 更新 ListView
    ListView_DeleteAllItems(m_hListView);
    for (size_t i = 0; i < m_matches.size(); i++) {
        const YaraMatch& match = m_matches[i];

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = COL_RULE;
        lvi.pszText = (LPTSTR)match.ruleName.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        ListView_SetItemText(m_hListView, (int)i, COL_NAMESPACE,
            (LPTSTR)match.ruleNamespace.c_str());

        ListView_SetItemText(m_hListView, (int)i, COL_FILE,
            (LPTSTR)match.filePath.c_str());

        // 合并匹配字符串
        tstring strings;
        for (size_t j = 0; j < match.matchedStrings.size() && j < 3; j++) {
            if (j > 0) strings += TEXT(", ");
            strings += match.matchedStrings[j];
        }
        if (match.matchedStrings.size() > 3) {
            strings += TEXT("...");
        }
        ListView_SetItemText(m_hListView, (int)i, COL_STRINGS, (LPTSTR)strings.c_str());
    }

    SetCursor(hOldCursor);

    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("扫描完成，发现 %d 个匹配"), (int)newMatches.size());
    SetStatusText(szStatus);
}

// ============================================================================
// 扫描目录
// ============================================================================

void YaraTab::ScanDirectory()
{
    if (!m_pYaraScanner) {
        return;
    }

    TCHAR szTarget[MAX_PATH];
    GetWindowText(m_hEditTarget, szTarget, MAX_PATH);

    if (lstrlen(szTarget) == 0) {
        MessageBox(m_hWnd, TEXT("请输入或选择要扫描的目录"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    if (m_pYaraScanner->GetLoadedRulesCount() == 0) {
        MessageBox(m_hWnd, TEXT("请先加载 YARA 规则"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    SetStatusText(TEXT("正在扫描目录..."));

    std::vector<YaraMatch> newMatches = m_pYaraScanner->ScanDirectory(szTarget, true);

    m_matches.insert(m_matches.end(), newMatches.begin(), newMatches.end());

    // 更新 ListView
    ListView_DeleteAllItems(m_hListView);
    for (size_t i = 0; i < m_matches.size(); i++) {
        const YaraMatch& match = m_matches[i];

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = COL_RULE;
        lvi.pszText = (LPTSTR)match.ruleName.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        ListView_SetItemText(m_hListView, (int)i, COL_NAMESPACE,
            (LPTSTR)match.ruleNamespace.c_str());

        ListView_SetItemText(m_hListView, (int)i, COL_FILE,
            (LPTSTR)match.filePath.c_str());

        tstring strings;
        for (size_t j = 0; j < match.matchedStrings.size() && j < 3; j++) {
            if (j > 0) strings += TEXT(", ");
            strings += match.matchedStrings[j];
        }
        if (match.matchedStrings.size() > 3) {
            strings += TEXT("...");
        }
        ListView_SetItemText(m_hListView, (int)i, COL_STRINGS, (LPTSTR)strings.c_str());
    }

    SetCursor(hOldCursor);

    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("扫描完成，发现 %d 个匹配"), (int)newMatches.size());
    SetStatusText(szStatus);
}

// ============================================================================
// 扫描进程内存
// ============================================================================

void YaraTab::ScanProcess()
{
    if (!m_pYaraScanner) {
        return;
    }

    int sel = (int)SendMessage(m_hComboProcess, CB_GETCURSEL, 0, 0);
    if (sel <= 0) {
        MessageBox(m_hWnd, TEXT("请选择要扫描的进程"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    if (m_pYaraScanner->GetLoadedRulesCount() == 0) {
        MessageBox(m_hWnd, TEXT("请先加载 YARA 规则"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    // 从 ComboBox 中提取 PID
    TCHAR szItem[256];
    SendMessage(m_hComboProcess, CB_GETLBTEXT, sel, (LPARAM)szItem);
    tstring item = szItem;

    DWORD pid = 0;
    size_t pos1 = item.rfind(TEXT('('));
    size_t pos2 = item.rfind(TEXT(')'));
    if (pos1 != tstring::npos && pos2 != tstring::npos) {
        tstring pidStr = item.substr(pos1 + 1, pos2 - pos1 - 1);
        pid = _ttol(pidStr.c_str());
    }

    if (pid == 0) {
        MessageBox(m_hWnd, TEXT("无效的进程"), TEXT("错误"), MB_ICONERROR);
        return;
    }

    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    SetStatusText(TEXT("正在扫描进程内存..."));

    std::vector<YaraMatch> newMatches = m_pYaraScanner->ScanProcessMemory(pid);

    m_matches.insert(m_matches.end(), newMatches.begin(), newMatches.end());

    // 更新 ListView
    ListView_DeleteAllItems(m_hListView);
    for (size_t i = 0; i < m_matches.size(); i++) {
        const YaraMatch& match = m_matches[i];

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.iSubItem = COL_RULE;
        lvi.pszText = (LPTSTR)match.ruleName.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        ListView_SetItemText(m_hListView, (int)i, COL_NAMESPACE,
            (LPTSTR)match.ruleNamespace.c_str());

        ListView_SetItemText(m_hListView, (int)i, COL_FILE,
            (LPTSTR)match.filePath.c_str());

        tstring strings;
        for (size_t j = 0; j < match.matchedStrings.size() && j < 3; j++) {
            if (j > 0) strings += TEXT(", ");
            strings += match.matchedStrings[j];
        }
        if (match.matchedStrings.size() > 3) {
            strings += TEXT("...");
        }
        ListView_SetItemText(m_hListView, (int)i, COL_STRINGS, (LPTSTR)strings.c_str());
    }

    SetCursor(hOldCursor);

    TCHAR szStatus[128];
    StringCchPrintf(szStatus, 128, TEXT("扫描完成，发现 %d 个匹配"), (int)newMatches.size());
    SetStatusText(szStatus);
}

// ============================================================================
// 清空结果
// ============================================================================

void YaraTab::ClearResults()
{
    m_matches.clear();
    ListView_DeleteAllItems(m_hListView);
    SetStatusText(TEXT("结果已清空"));
}

// ============================================================================
// 命令处理
// ============================================================================

void YaraTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_LOAD_RULES:
        LoadRulesFromFile();
        break;

    case IDC_BTN_LOAD_RULES_DIR:
        LoadRulesFromDirectory();
        break;

    case IDC_BTN_BROWSE_FILE:
    {
        OPENFILENAME ofn = { 0 };
        TCHAR szFile[MAX_PATH] = TEXT("");
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = m_hWnd;
        ofn.lpstrFilter = TEXT("所有文件 (*.*)\0*.*\0");
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_FILEMUSTEXIST;
        ofn.lpstrTitle = TEXT("选择要扫描的文件");
        if (GetOpenFileName(&ofn)) {
            SetWindowText(m_hEditTarget, szFile);
        }
    }
    break;

    case IDC_BTN_BROWSE_DIR:
    {
        BROWSEINFO bi = { 0 };
        bi.hwndOwner = m_hWnd;
        bi.lpszTitle = TEXT("选择要扫描的目录");
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
        if (pidl) {
            TCHAR szPath[MAX_PATH];
            if (SHGetPathFromIDList(pidl, szPath)) {
                SetWindowText(m_hEditTarget, szPath);
            }
            CoTaskMemFree(pidl);
        }
    }
    break;

    case IDC_BTN_SCAN_FILE:
        ScanFile();
        break;

    case IDC_BTN_SCAN_DIR:
        ScanDirectory();
        break;

    case IDC_BTN_SCAN_PROCESS:
        ScanProcess();
        break;

    case IDC_BTN_CLEAR:
        ClearResults();
        break;
    }
}
