// dll_tab.cpp - DLL 检测标签页实现
#include "dll_tab.h"
#include <tchar.h>

#define IDC_EDIT_PID_DLL    8001
#define IDC_BTN_SCAN_DLL    8002
#define IDC_CHK_SUSP_DLL    8003

DllTab::DllTab(HWND hParentTab, DLLManager* pManager)
    : BaseTab(hParentTab, TEXT("DLL检测"))
    , m_pManager(pManager)
    , m_currentPid(0)
    , m_hEditPid(NULL)
    , m_hBtnScan(NULL)
    , m_hChkSuspicious(NULL)
{
}

DllTab::~DllTab()
{
}

bool DllTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) return false;

    CreateToolbar();

    std::vector<tstring> columns = {
        TEXT("路径"), TEXT("基地址"), TEXT("大小"),
        TEXT("公司"), TEXT("描述")
    };
    std::vector<int> widths = { 400, 100, 80, 150, 200 };

    CreateListView(rc, columns, widths);
    return true;
}

void DllTab::CreateToolbar()
{
    int y = 5, h = 25, x = 10;

    AddLabel(x, y + 3, 30, h, TEXT("PID:"));
    x += 35;

    m_hEditPid = AddEdit(x, y, 80, h, IDC_EDIT_PID_DLL);
    x += 90;

    m_hBtnScan = AddButton(x, y, 60, h, IDC_BTN_SCAN_DLL, TEXT("扫描"));
    x += 80;

    m_hChkSuspicious = CreateWindowEx(0, TEXT("BUTTON"), TEXT("只显示可疑"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        x, y + 3, 100, h, m_hWnd, (HMENU)IDC_CHK_SUSP_DLL,
        GetModuleHandle(NULL), NULL);

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(m_hChkSuspicious, WM_SETFONT, (WPARAM)hFont, TRUE);
}

void DllTab::Refresh()
{
    if (m_currentPid > 0) {
        ScanProcess();
    }
}

void DllTab::ScanProcess()
{
    TCHAR pidText[32];
    GetWindowText(m_hEditPid, pidText, 32);
    m_currentPid = _ttoi(pidText);

    if (m_currentPid == 0) {
        MessageBox(m_hWnd, TEXT("请输入有效的 PID"), TEXT("提示"), MB_ICONINFORMATION);
        return;
    }

    m_dlls = m_pManager->GetProcessDlls(m_currentPid);
    FilterDlls();
}

void DllTab::FilterDlls()
{
    ClearListView();

    bool showSuspiciousOnly = (SendMessage(m_hChkSuspicious, BM_GETCHECK, 0, 0) == BST_CHECKED);
    int suspiciousCount = 0;

    for (const auto& dll : m_dlls) {
        if (dll.isSuspicious) suspiciousCount++;

        if (showSuspiciousOnly && !dll.isSuspicious) continue;

        std::vector<tstring> values;

        tstring path = dll.path;
        if (dll.isSuspicious) path = TEXT("[!] ") + path;
        values.push_back(path);

        TCHAR buf[64];
        _stprintf_s(buf, TEXT("0x%p"), dll.baseAddr);
        values.push_back(buf);

        values.push_back(Utils::FormatSize(dll.size));
        values.push_back(dll.company);
        values.push_back(dll.description);

        AddListViewItem(values);
    }

    TCHAR status[128];
    _stprintf_s(status, TEXT("DLL 总数: %d | 可疑: %d"),
        (int)m_dlls.size(), suspiciousCount);

    HWND hMainWnd = GetParent(GetParent(m_hWnd));
    HWND hStatusBar = GetDlgItem(hMainWnd, IDC_STATUSBAR);
    if (hStatusBar) {
        SendMessage(hStatusBar, SB_SETTEXT, 1, (LPARAM)status);
    }
}

void DllTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_SCAN_DLL:
        ScanProcess();
        break;
    case IDC_CHK_SUSP_DLL:
        FilterDlls();
        break;
    }
}

void DllTab::ShowContextMenu(int x, int y)
{
    int sel = GetSelectedItem();
    if (sel < 0) return;

    HMENU hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING, 8101, TEXT("复制路径"));
    AppendMenu(hMenu, MF_STRING, 8102, TEXT("打开文件位置"));
    AppendMenu(hMenu, MF_STRING, 8103, TEXT("计算哈希"));

    TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON, x, y, 0, m_hWnd, NULL);
    DestroyMenu(hMenu);
}
