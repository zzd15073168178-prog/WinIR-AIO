// process_tab.cpp - 进程列表标签页实现
#include "process_tab.h"
#include <tchar.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <algorithm>

#pragma comment(lib, "shlwapi.lib")

// 控件 ID
#define IDC_BTN_REFRESH_PROC    6001
#define IDC_BTN_KILL_PROC       6002
#define IDC_EDIT_SEARCH_PROC    6003
#define IDC_BTN_SEARCH_PROC     6004
#define IDC_CHK_SUSPICIOUS      6005

// ============================================================================
// 构造函数和析构函数
// ============================================================================

ProcessTab::ProcessTab(HWND hParentTab, ProcessManager* pManager)
    : BaseTab(hParentTab, TEXT("进程列表"))
    , m_pManager(pManager)
    , m_hBtnRefresh(NULL)
    , m_hBtnKill(NULL)
    , m_hEditSearch(NULL)
    , m_hBtnSearch(NULL)
    , m_hChkSuspicious(NULL)
    , m_showSuspiciousOnly(false)
{
}

ProcessTab::~ProcessTab()
{
}

// ============================================================================
// 创建
// ============================================================================

bool ProcessTab::Create(const RECT& rc)
{
    if (!BaseTab::Create(rc)) {
        return false;
    }

    // 创建工具栏
    CreateToolbar();

    // 创建 ListView
    std::vector<tstring> columns = {
        TEXT("PID"),
        TEXT("进程名"),
        TEXT("CPU%"),
        TEXT("内存"),
        TEXT("用户"),
        TEXT("路径"),
        TEXT("状态")
    };

    std::vector<int> widths = { 60, 150, 60, 80, 120, 350, 80 };

    CreateListView(rc, columns, widths);

    return true;
}

// ============================================================================
// 创建工具栏
// ============================================================================

void ProcessTab::CreateToolbar()
{
    int y = 5;
    int h = 25;
    int x = 10;

    // 刷新按钮
    m_hBtnRefresh = AddButton(x, y, 60, h, IDC_BTN_REFRESH_PROC, TEXT("刷新"));
    x += 70;

    // 终止按钮
    m_hBtnKill = AddButton(x, y, 60, h, IDC_BTN_KILL_PROC, TEXT("终止"));
    x += 70;

    // 分隔
    x += 20;

    // 搜索框
    AddLabel(x, y + 3, 40, h, TEXT("搜索:"));
    x += 45;

    m_hEditSearch = AddEdit(x, y, 150, h, IDC_EDIT_SEARCH_PROC);
    x += 155;

    m_hBtnSearch = AddButton(x, y, 50, h, IDC_BTN_SEARCH_PROC, TEXT("查找"));
    x += 60;

    // 分隔
    x += 20;

    // 只显示可疑进程
    m_hChkSuspicious = CreateWindowEx(
        0,
        TEXT("BUTTON"),
        TEXT("只显示可疑"),
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        x, y + 3, 100, h,
        m_hWnd,
        (HMENU)IDC_CHK_SUSPICIOUS,
        GetModuleHandle(NULL),
        NULL);

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(m_hChkSuspicious, WM_SETFONT, (WPARAM)hFont, TRUE);
}

// ============================================================================
// 刷新
// ============================================================================

void ProcessTab::Refresh()
{
    // 获取进程列表
    m_processes = m_pManager->GetAllProcesses();

    // 更新显示
    FilterProcesses();
}

// ============================================================================
// 过滤进程
// ============================================================================

void ProcessTab::FilterProcesses()
{
    ClearListView();

    // 获取搜索关键字
    TCHAR searchText[256] = { 0 };
    if (m_hEditSearch) {
        GetWindowText(m_hEditSearch, searchText, 256);
    }
    m_searchKeyword = searchText;

    // 获取可疑过滤状态
    m_showSuspiciousOnly = (SendMessage(m_hChkSuspicious, BM_GETCHECK, 0, 0) == BST_CHECKED);

    int displayCount = 0;
    int suspiciousCount = 0;

    for (const auto& proc : m_processes) {
        // 统计可疑进程
        if (proc.isSuspicious) {
            suspiciousCount++;
        }

        // 应用过滤
        bool show = true;

        // 搜索过滤
        if (!m_searchKeyword.empty()) {
            bool match = false;

            // 搜索进程名
            if (proc.name.find(m_searchKeyword) != tstring::npos) {
                match = true;
            }
            // 搜索路径
            else if (proc.exePath.find(m_searchKeyword) != tstring::npos) {
                match = true;
            }
            // 搜索 PID
            else {
                TCHAR pidStr[32];
                _stprintf_s(pidStr, TEXT("%u"), proc.pid);
                if (_tcsstr(pidStr, m_searchKeyword.c_str()) != NULL) {
                    match = true;
                }
            }

            if (!match) show = false;
        }

        // 可疑过滤
        if (m_showSuspiciousOnly && !proc.isSuspicious) {
            show = false;
        }

        if (show) {
            // 添加到 ListView
            std::vector<tstring> values;

            // PID
            TCHAR buffer[64];
            _stprintf_s(buffer, TEXT("%u"), proc.pid);
            values.push_back(buffer);

            // 进程名
            tstring name = proc.name;
            if (proc.isSuspicious) {
                name = TEXT("[!] ") + name;
            }
            values.push_back(name);

            // CPU
            _stprintf_s(buffer, TEXT("%.1f"), proc.cpuPercent);
            values.push_back(buffer);

            // 内存
            values.push_back(Utils::FormatSize(proc.workingSetKB * 1024));

            // 用户
            values.push_back(proc.username);

            // 路径
            values.push_back(proc.exePath);

            // 状态
            values.push_back(proc.status);

            int index = AddListViewItem(values);

            // 存储 PID 作为项数据
            LVITEM lvi;
            lvi.mask = LVIF_PARAM;
            lvi.iItem = index;
            lvi.iSubItem = 0;
            lvi.lParam = proc.pid;
            ListView_SetItem(m_hListView, &lvi);

            displayCount++;
        }
    }

    // 更新状态栏
    TCHAR statusText[256];
    _stprintf_s(statusText, TEXT("进程总数: %d | 显示: %d | 可疑: %d"),
        (int)m_processes.size(), displayCount, suspiciousCount);

    // 通过主窗口更新状态栏
    HWND hMainWnd = GetParent(GetParent(m_hWnd));
    HWND hStatusBar = GetDlgItem(hMainWnd, IDC_STATUSBAR);
    if (hStatusBar) {
        SendMessage(hStatusBar, SB_SETTEXT, 1, (LPARAM)statusText);
    }
}

// ============================================================================
// 命令处理
// ============================================================================

void ProcessTab::OnCommand(WORD id, WORD code, HWND hCtrl)
{
    switch (id) {
    case IDC_BTN_REFRESH_PROC:
        Refresh();
        break;

    case IDC_BTN_KILL_PROC:
        OnTerminateProcess();
        break;

    case IDC_BTN_SEARCH_PROC:
        FilterProcesses();
        break;

    case IDC_CHK_SUSPICIOUS:
        FilterProcesses();
        break;

    case IDM_PROCESS_TERMINATE:
        OnTerminateProcess();
        break;

    case IDM_PROCESS_SUSPEND:
        OnSuspendProcess();
        break;

    case IDM_PROCESS_RESUME:
        OnResumeProcess();
        break;

    case IDM_PROCESS_PROPERTIES:
        OnViewProperties();
        break;

    case IDM_PROCESS_OPENLOCATION:
        OnOpenFileLocation();
        break;
    }

    // 搜索框回车
    if (id == IDC_EDIT_SEARCH_PROC && code == EN_CHANGE) {
        // 可选：实时过滤
    }
}

// ============================================================================
// 通知处理
// ============================================================================

void ProcessTab::OnNotify(LPNMHDR pnmh)
{
    if (pnmh->hwndFrom == m_hListView) {
        switch (pnmh->code) {
        case NM_DBLCLK:
            OnViewProperties();
            break;
        }
    }
}

// ============================================================================
// 右键菜单
// ============================================================================

void ProcessTab::ShowContextMenu(int x, int y)
{
    int sel = GetSelectedItem();
    if (sel < 0) return;

    HMENU hMenu = CreatePopupMenu();

    AppendMenu(hMenu, MF_STRING, IDM_PROCESS_TERMINATE, TEXT("终止进程"));
    AppendMenu(hMenu, MF_STRING, IDM_PROCESS_SUSPEND, TEXT("挂起进程"));
    AppendMenu(hMenu, MF_STRING, IDM_PROCESS_RESUME, TEXT("恢复进程"));
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, IDM_PROCESS_PROPERTIES, TEXT("属性"));
    AppendMenu(hMenu, MF_STRING, IDM_PROCESS_OPENLOCATION, TEXT("打开文件位置"));
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, IDM_PROCESS_VIEWDLL, TEXT("查看 DLL"));
    AppendMenu(hMenu, MF_STRING, IDM_PROCESS_VIEWHANDLE, TEXT("查看句柄"));
    AppendMenu(hMenu, MF_STRING, IDM_PROCESS_VIEWNETWORK, TEXT("查看网络连接"));

    TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON,
        x, y, 0, m_hWnd, NULL);

    DestroyMenu(hMenu);
}

// ============================================================================
// 获取选中的 PID
// ============================================================================

DWORD ProcessTab::GetSelectedPid()
{
    int sel = GetSelectedItem();
    if (sel < 0) return 0;

    LVITEM lvi;
    lvi.mask = LVIF_PARAM;
    lvi.iItem = sel;
    lvi.iSubItem = 0;
    ListView_GetItem(m_hListView, &lvi);

    return (DWORD)lvi.lParam;
}

// ============================================================================
// 进程操作
// ============================================================================

void ProcessTab::OnTerminateProcess()
{
    DWORD pid = GetSelectedPid();
    if (pid == 0) return;

    // 确认
    TCHAR msg[256];
    _stprintf_s(msg, TEXT("确定要终止进程 %u 吗？"), pid);

    if (MessageBox(m_hWnd, msg, TEXT("确认"), MB_YESNO | MB_ICONQUESTION) == IDYES) {
        tstring errorMsg;
        if (m_pManager->TerminateProcess(pid, errorMsg)) {
            MessageBox(m_hWnd, TEXT("进程已终止"), TEXT("成功"), MB_ICONINFORMATION);
            Refresh();
        } else {
            MessageBox(m_hWnd, errorMsg.c_str(), TEXT("错误"), MB_ICONERROR);
        }
    }
}

void ProcessTab::OnSuspendProcess()
{
    DWORD pid = GetSelectedPid();
    if (pid == 0) return;

    tstring errorMsg;
    if (m_pManager->SuspendProcess(pid, errorMsg)) {
        MessageBox(m_hWnd, TEXT("进程已挂起"), TEXT("成功"), MB_ICONINFORMATION);
        Refresh();
    } else {
        MessageBox(m_hWnd, errorMsg.c_str(), TEXT("错误"), MB_ICONERROR);
    }
}

void ProcessTab::OnResumeProcess()
{
    DWORD pid = GetSelectedPid();
    if (pid == 0) return;

    tstring errorMsg;
    if (m_pManager->ResumeProcess(pid, errorMsg)) {
        MessageBox(m_hWnd, TEXT("进程已恢复"), TEXT("成功"), MB_ICONINFORMATION);
        Refresh();
    } else {
        MessageBox(m_hWnd, errorMsg.c_str(), TEXT("错误"), MB_ICONERROR);
    }
}

void ProcessTab::OnViewProperties()
{
    DWORD pid = GetSelectedPid();
    if (pid == 0) return;

    // 查找进程信息
    ProcessInfo info;
    if (!m_pManager->GetProcessDetails(pid, info)) {
        MessageBox(m_hWnd, TEXT("无法获取进程信息"), TEXT("错误"), MB_ICONERROR);
        return;
    }

    // 显示属性对话框
    tstring msg;
    msg += TEXT("PID: ") + to_tstring(info.pid) + TEXT("\n");
    msg += TEXT("名称: ") + info.name + TEXT("\n");
    msg += TEXT("路径: ") + info.exePath + TEXT("\n");
    msg += TEXT("用户: ") + info.username + TEXT("\n");
    msg += TEXT("CPU: ") + to_tstring((int)info.cpuPercent) + TEXT("%\n");
    msg += TEXT("内存: ") + Utils::FormatSize(info.workingSetKB * 1024) + TEXT("\n");
    msg += TEXT("线程数: ") + to_tstring(info.threadCount) + TEXT("\n");
    msg += TEXT("句柄数: ") + to_tstring(info.handleCount) + TEXT("\n");

    if (info.isSuspicious) {
        msg += TEXT("\n[警告] 可疑原因: ") + info.suspiciousReason;
    }

    MessageBox(m_hWnd, msg.c_str(), TEXT("进程属性"), MB_ICONINFORMATION);
}

void ProcessTab::OnOpenFileLocation()
{
    DWORD pid = GetSelectedPid();
    if (pid == 0) return;

    // 查找进程路径
    for (const auto& proc : m_processes) {
        if (proc.pid == pid) {
            if (!proc.exePath.empty()) {
                // 打开资源管理器并选中文件
                tstring param = TEXT("/select,\"") + proc.exePath + TEXT("\"");
                ShellExecute(NULL, TEXT("open"), TEXT("explorer.exe"),
                    param.c_str(), NULL, SW_SHOWNORMAL);
            } else {
                MessageBox(m_hWnd, TEXT("无法获取进程路径"), TEXT("错误"), MB_ICONERROR);
            }
            break;
        }
    }
}

// ============================================================================
// 排序
// ============================================================================

void ProcessTab::SortListView(int column)
{
    BaseTab::SortListView(column);

    // 根据列进行排序
    auto compareFunc = [this, column](const ProcessInfo& a, const ProcessInfo& b) -> bool {
        switch (column) {
        case COL_PID:
            return m_sortAscending ? (a.pid < b.pid) : (a.pid > b.pid);
        case COL_NAME:
            return m_sortAscending ? (a.name < b.name) : (a.name > b.name);
        case COL_CPU:
            return m_sortAscending ? (a.cpuPercent < b.cpuPercent) : (a.cpuPercent > b.cpuPercent);
        case COL_MEMORY:
            return m_sortAscending ? (a.workingSetKB < b.workingSetKB) : (a.workingSetKB > b.workingSetKB);
        case COL_USER:
            return m_sortAscending ? (a.username < b.username) : (a.username > b.username);
        case COL_PATH:
            return m_sortAscending ? (a.exePath < b.exePath) : (a.exePath > b.exePath);
        default:
            return false;
        }
    };

    std::sort(m_processes.begin(), m_processes.end(), compareFunc);
    FilterProcesses();
}
