// security_tab.cpp - 安全检测标签页实现
#include "security_tab.h"
#include <commctrl.h>
#include <strsafe.h>
#include <commdlg.h>
#include <fstream>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

SecurityTab::SecurityTab(HWND hParentTab, SecurityManager* pSecurityMgr)
    : BaseTab(hParentTab)
    , m_pSecurityManager(pSecurityMgr)
    , m_hComboType(NULL)
    , m_hCheckSuspicious(NULL)
    , m_hBtnScan(NULL)
    , m_hEditSearch(NULL)
    , m_showOnlySuspicious(false)
{
}

SecurityTab::~SecurityTab()
{
}

// ============================================================================
// 创建标签页
// ============================================================================

bool SecurityTab::Create(const RECT& rc)
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

    AddColumn(COL_TYPE, TEXT("类型"), 100);
    AddColumn(COL_LOCATION, TEXT("位置"), 200);
    AddColumn(COL_NAME, TEXT("名称"), 150);
    AddColumn(COL_PUBLISHER, TEXT("发布者"), 150);
    AddColumn(COL_PATH, TEXT("路径"), 350);
    AddColumn(COL_SUSPICIOUS, TEXT("可疑"), 60);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void SecurityTab::CreateToolbar()
{
    // 类型过滤
    CreateWindowEx(0, TEXT("STATIC"), TEXT("类型:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        5, 5, 40, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hComboType = CreateWindowEx(0, TEXT("COMBOBOX"), NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        50, 5, 120, 200,
        m_hWnd, (HMENU)IDC_SEC_COMBO_TYPE, GetModuleHandle(NULL), NULL);

    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("所有类型"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("登录项"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("计划任务"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("服务"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("驱动程序"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("浏览器插件"));
    SendMessage(m_hComboType, CB_ADDSTRING, 0, (LPARAM)TEXT("WMI"));
    SendMessage(m_hComboType, CB_SETCURSEL, 0, 0);

    // 搜索框
    CreateWindowEx(0, TEXT("STATIC"), TEXT("搜索:"),
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        180, 5, 45, 25,
        m_hWnd, NULL, GetModuleHandle(NULL), NULL);

    m_hEditSearch = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
        WS_CHILD | WS_VISIBLE,
        230, 5, 150, 25,
        m_hWnd, (HMENU)IDC_SEC_EDIT_SEARCH, GetModuleHandle(NULL), NULL);

    // 仅显示可疑
    m_hCheckSuspicious = CreateWindowEx(0, TEXT("BUTTON"), TEXT("仅显示可疑"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        390, 5, 100, 25,
        m_hWnd, (HMENU)IDC_SEC_CHECK_SUSPICIOUS, GetModuleHandle(NULL), NULL);

    // 扫描按钮
    m_hBtnScan = CreateWindowEx(0, TEXT("BUTTON"), TEXT("扫描自启动项"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        500, 5, 110, 25,
        m_hWnd, (HMENU)IDC_SEC_BTN_SCAN, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("导出"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        620, 5, 60, 25,
        m_hWnd, (HMENU)IDC_SEC_BTN_EXPORT, GetModuleHandle(NULL), NULL);

    CreateWindowEx(0, TEXT("BUTTON"), TEXT("详情"),
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        690, 5, 60, 25,
        m_hWnd, (HMENU)IDC_SEC_BTN_DETAILS, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// 刷新数据
// ============================================================================

void SecurityTab::Refresh()
{
    ScanAutoruns();
}

// ============================================================================
// 扫描自启动项
// ============================================================================

void SecurityTab::ScanAutoruns()
{
    if (!m_pSecurityManager) {
        return;
    }

    if (!m_pSecurityManager->IsAutorunsAvailable()) {
        MessageBox(m_hWnd,
            TEXT("autorunsc64.exe 未找到，请将其放置在 Tools 目录下"),
            TEXT("错误"), MB_ICONERROR);
        return;
    }

    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    SetStatusText(TEXT("正在扫描自启动项..."));

    m_entries = m_pSecurityManager->ScanAllAutoruns();

    SetCursor(hOldCursor);

    ShowOnlySuspicious();  // 刷新显示

    TCHAR szStatus[128];
    int suspiciousCount = 0;
    for (const auto& entry : m_entries) {
        if (entry.isSuspicious) suspiciousCount++;
    }
    StringCchPrintf(szStatus, 128, TEXT("扫描完成: %d 个自启动项 (%d 个可疑)"),
        (int)m_entries.size(), suspiciousCount);
    SetStatusText(szStatus);
}

// ============================================================================
// 刷新 ListView 显示
// ============================================================================

void SecurityTab::ShowOnlySuspicious()
{
    ListView_DeleteAllItems(m_hListView);

    // 获取过滤条件
    m_showOnlySuspicious = (SendMessage(m_hCheckSuspicious, BM_GETCHECK, 0, 0) == BST_CHECKED);

    int typeFilter = (int)SendMessage(m_hComboType, CB_GETCURSEL, 0, 0);

    TCHAR szSearch[256] = TEXT("");
    GetWindowText(m_hEditSearch, szSearch, 256);
    tstring search = szSearch;
    for (auto& c : search) c = (TCHAR)tolower(c);

    int displayIndex = 0;
    for (size_t i = 0; i < m_entries.size(); i++) {
        const AutorunEntry& entry = m_entries[i];

        // 可疑过滤
        if (m_showOnlySuspicious && !entry.isSuspicious) {
            continue;
        }

        // 类型过滤
        if (typeFilter > 0) {
            bool match = false;
            switch (typeFilter) {
            case 1: // 登录项
                match = (entry.type == AUTORUN_LOGON || entry.type == AUTORUN_EXPLORER);
                break;
            case 2: // 计划任务
                match = (entry.type == AUTORUN_SCHEDULED_TASK);
                break;
            case 3: // 服务
                match = (entry.type == AUTORUN_SERVICE);
                break;
            case 4: // 驱动
                match = (entry.type == AUTORUN_DRIVER);
                break;
            case 5: // 浏览器
                match = (entry.type == AUTORUN_IE || entry.type == AUTORUN_CHROME ||
                         entry.type == AUTORUN_FIREFOX || entry.type == AUTORUN_EDGE);
                break;
            case 6: // WMI
                match = (entry.type == AUTORUN_WMI);
                break;
            }
            if (!match) continue;
        }

        // 搜索过滤
        if (!search.empty()) {
            tstring nameLower = entry.entryName;
            tstring pathLower = entry.imagePath;
            tstring locLower = entry.location;
            for (auto& c : nameLower) c = (TCHAR)tolower(c);
            for (auto& c : pathLower) c = (TCHAR)tolower(c);
            for (auto& c : locLower) c = (TCHAR)tolower(c);

            if (nameLower.find(search) == tstring::npos &&
                pathLower.find(search) == tstring::npos &&
                locLower.find(search) == tstring::npos) {
                continue;
            }
        }

        // 添加到 ListView
        tstring typeName = GetAutorunTypeName(entry.type);

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = displayIndex;
        lvi.iSubItem = COL_TYPE;
        lvi.pszText = (LPTSTR)typeName.c_str();
        ListView_InsertItem(m_hListView, &lvi);

        ListView_SetItemText(m_hListView, displayIndex, COL_LOCATION,
            (LPTSTR)entry.location.c_str());

        ListView_SetItemText(m_hListView, displayIndex, COL_NAME,
            (LPTSTR)entry.entryName.c_str());

        ListView_SetItemText(m_hListView, displayIndex, COL_PUBLISHER,
            (LPTSTR)entry.publisher.c_str());

        ListView_SetItemText(m_hListView, displayIndex, COL_PATH,
            (LPTSTR)entry.imagePath.c_str());

        ListView_SetItemText(m_hListView, displayIndex, COL_SUSPICIOUS,
            (LPTSTR)(entry.isSuspicious ? TEXT("是") : TEXT("否")));

        displayIndex++;
    }
}

// ============================================================================
// 导出结果
// ============================================================================

void SecurityTab::ExportResults()
{
    if (m_entries.empty()) {
        MessageBox(m_hWnd, TEXT("没有数据可导出"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    OPENFILENAME ofn = { 0 };
    TCHAR szFile[MAX_PATH] = TEXT("autoruns_report.csv");

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hWnd;
    ofn.lpstrFilter = TEXT("CSV 文件 (*.csv)\0*.csv\0所有文件 (*.*)\0*.*\0");
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrTitle = TEXT("导出自启动项报告");
    ofn.lpstrDefExt = TEXT("csv");

    if (GetSaveFileName(&ofn)) {
#ifdef UNICODE
        std::wofstream file(szFile);
#else
        std::ofstream file(szFile);
#endif

        if (file.is_open()) {
            // CSV 头
            file << TEXT("类型,位置,名称,发布者,路径,可疑\n");

            for (const auto& entry : m_entries) {
                file << GetAutorunTypeName(entry.type) << TEXT(",");
                file << TEXT("\"") << entry.location << TEXT("\",");
                file << TEXT("\"") << entry.entryName << TEXT("\",");
                file << TEXT("\"") << entry.publisher << TEXT("\",");
                file << TEXT("\"") << entry.imagePath << TEXT("\",");
                file << (entry.isSuspicious ? TEXT("是") : TEXT("否")) << TEXT("\n");
            }

            file.close();

            MessageBox(m_hWnd, TEXT("导出成功"), TEXT("完成"), MB_ICONINFORMATION);
        }
    }
}

// ============================================================================
// 显示详情
// ============================================================================

void SecurityTab::ShowDetails()
{
    int sel = ListView_GetNextItem(m_hListView, -1, LVNI_SELECTED);
    if (sel < 0) {
        MessageBox(m_hWnd, TEXT("请先选择一个项目"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    // 获取对应的原始索引（需要遍历查找）
    // 简化处理：直接从 ListView 获取信息
    TCHAR szName[256], szPath[512], szLoc[256];
    ListView_GetItemText(m_hListView, sel, COL_NAME, szName, 256);
    ListView_GetItemText(m_hListView, sel, COL_PATH, szPath, 512);
    ListView_GetItemText(m_hListView, sel, COL_LOCATION, szLoc, 256);

    tstring details;
    details += TEXT("名称: ") + tstring(szName) + TEXT("\n\n");
    details += TEXT("位置: ") + tstring(szLoc) + TEXT("\n\n");
    details += TEXT("路径: ") + tstring(szPath);

    MessageBox(m_hWnd, details.c_str(), TEXT("自启动项详情"), MB_ICONINFORMATION);
}

// ============================================================================
// 获取类型名称
// ============================================================================

tstring SecurityTab::GetAutorunTypeName(AutorunType type)
{
    switch (type) {
    case AUTORUN_LOGON: return TEXT("登录");
    case AUTORUN_EXPLORER: return TEXT("Explorer");
    case AUTORUN_IE: return TEXT("IE");
    case AUTORUN_SCHEDULED_TASK: return TEXT("计划任务");
    case AUTORUN_SERVICE: return TEXT("服务");
    case AUTORUN_DRIVER: return TEXT("驱动");
    case AUTORUN_CODEC: return TEXT("编解码器");
    case AUTORUN_BOOT_EXECUTE: return TEXT("启动执行");
    case AUTORUN_IMAGE_HIJACK: return TEXT("映像劫持");
    case AUTORUN_APPINIT: return TEXT("AppInit");
    case AUTORUN_KNOWN_DLLS: return TEXT("KnownDLLs");
    case AUTORUN_WINLOGON: return TEXT("Winlogon");
    case AUTORUN_WINSOCK: return TEXT("Winsock");
    case AUTORUN_PRINT_MONITOR: return TEXT("打印");
    case AUTORUN_LSA_PROVIDER: return TEXT("LSA");
    case AUTORUN_NETWORK_PROVIDER: return TEXT("网络");
    case AUTORUN_WMI: return TEXT("WMI");
    case AUTORUN_OFFICE: return TEXT("Office");
    case AUTORUN_SIDEBAR: return TEXT("Sidebar");
    case AUTORUN_CHROME: return TEXT("Chrome");
    case AUTORUN_FIREFOX: return TEXT("Firefox");
    case AUTORUN_EDGE: return TEXT("Edge");
    default: return TEXT("未知");
    }
}

// ============================================================================
// 命令处理
// ============================================================================

void SecurityTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_SEC_BTN_SCAN:
        ScanAutoruns();
        break;

    case IDC_SEC_BTN_EXPORT:
        ExportResults();
        break;

    case IDC_SEC_BTN_DETAILS:
        ShowDetails();
        break;

    case IDC_SEC_CHECK_SUSPICIOUS:
        if (code == BN_CLICKED) {
            ShowOnlySuspicious();
        }
        break;

    case IDC_SEC_COMBO_TYPE:
        if (code == CBN_SELCHANGE) {
            ShowOnlySuspicious();
        }
        break;

    case IDC_SEC_EDIT_SEARCH:
        if (code == EN_CHANGE) {
            ShowOnlySuspicious();
        }
        break;
    }
}
