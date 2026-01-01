// process_manager.cpp - 进程管理器实现
#include "../include/process_manager.h"
#include <shlwapi.h>
#include <tchar.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

ProcessManager::ProcessManager()
    : m_lastRefreshTime(0)
    , m_pfnQueryFullProcessImageName(NULL)
    , m_pfnNtSuspendProcess(NULL)
    , m_pfnNtResumeProcess(NULL)
{
    LoadOptionalAPIs();
}

ProcessManager::~ProcessManager()
{
}

// ============================================================================
// 动态加载可选 API
// ============================================================================

void ProcessManager::LoadOptionalAPIs()
{
    // Vista+ API: QueryFullProcessImageNameW
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (hKernel32) {
        m_pfnQueryFullProcessImageName = (PFN_QueryFullProcessImageNameW)
            GetProcAddress(hKernel32, "QueryFullProcessImageNameW");
    }

    // NtSuspendProcess / NtResumeProcess (ntdll.dll)
    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll) {
        m_pfnNtSuspendProcess = (PFN_NtSuspendProcess)
            GetProcAddress(hNtdll, "NtSuspendProcess");
        m_pfnNtResumeProcess = (PFN_NtResumeProcess)
            GetProcAddress(hNtdll, "NtResumeProcess");
    }
}

// ============================================================================
// 获取所有进程
// ============================================================================

std::vector<ProcessInfo> ProcessManager::GetAllProcesses()
{
    std::vector<ProcessInfo> processes;

    // 创建进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            ProcessInfo info = GetBasicProcessInfo(pe);

            // 获取详细信息
            HANDLE hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID);

            if (hProcess) {
                // 获取进程路径
                info.exePath = GetProcessPath(pe.th32ProcessID);

                // 获取用户名
                info.username = GetProcessUsername(hProcess);

                // 计算 CPU 使用率
                info.cpuPercent = CalculateCpuUsage(pe.th32ProcessID, hProcess);

                // 获取内存信息
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    info.workingSetKB = pmc.WorkingSetSize / 1024;
                    info.memoryKB = pmc.PagefileUsage / 1024;
                }

                // 获取句柄数
                DWORD handleCount = 0;
                GetProcessHandleCount(hProcess, &handleCount);
                info.handleCount = handleCount;

                CloseHandle(hProcess);
            } else {
                // 无法打开进程 (权限不足)
                info.exePath = TEXT("");
                info.username = TEXT("N/A");
                info.cpuPercent = 0;
            }

            // 分析是否可疑
            AnalyzeSuspiciousProcess(info);

            processes.push_back(info);

        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    m_processCache = processes;
    return processes;
}

// ============================================================================
// 获取基本进程信息
// ============================================================================

ProcessInfo ProcessManager::GetBasicProcessInfo(const PROCESSENTRY32& pe)
{
    ProcessInfo info;
    info.pid = pe.th32ProcessID;
    info.ppid = pe.th32ParentProcessID;
    info.name = pe.szExeFile;
    info.threadCount = pe.cntThreads;
    info.priority = pe.pcPriClassBase;
    info.status = TEXT("运行中");
    info.cpuPercent = 0;
    info.memoryKB = 0;
    info.workingSetKB = 0;
    info.handleCount = 0;
    info.isSuspicious = false;

    ZeroMemory(&info.createTime, sizeof(info.createTime));

    return info;
}

// ============================================================================
// 获取进程完整路径
// ============================================================================

tstring ProcessManager::GetProcessPath(DWORD pid)
{
    tstring path;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        // 尝试更低的权限
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }

    if (!hProcess) {
        return path;
    }

    TCHAR buffer[MAX_PATH] = { 0 };

    // 优先使用 Vista+ API
    if (m_pfnQueryFullProcessImageName) {
        DWORD size = MAX_PATH;
        if (m_pfnQueryFullProcessImageName(hProcess, 0, buffer, &size)) {
            path = buffer;
        }
    }

    // 回退到 XP 兼容方法
    if (path.empty()) {
        if (GetModuleFileNameEx(hProcess, NULL, buffer, MAX_PATH)) {
            path = buffer;
        }
    }

    CloseHandle(hProcess);
    return path;
}

// ============================================================================
// 获取进程所属用户
// ============================================================================

tstring ProcessManager::GetProcessUsername(HANDLE hProcess)
{
    tstring username;
    HANDLE hToken = NULL;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return TEXT("N/A");
    }

    // 获取 Token User 信息
    DWORD tokenInfoSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);

    if (tokenInfoSize > 0) {
        BYTE* tokenInfo = new BYTE[tokenInfoSize];
        if (GetTokenInformation(hToken, TokenUser, tokenInfo, tokenInfoSize, &tokenInfoSize)) {
            TOKEN_USER* pTokenUser = (TOKEN_USER*)tokenInfo;

            TCHAR name[256] = { 0 };
            TCHAR domain[256] = { 0 };
            DWORD nameSize = 256;
            DWORD domainSize = 256;
            SID_NAME_USE sidType;

            if (LookupAccountSid(NULL, pTokenUser->User.Sid,
                name, &nameSize, domain, &domainSize, &sidType)) {
                if (domain[0] != 0) {
                    username = domain;
                    username += TEXT("\\");
                }
                username += name;
            }
        }
        delete[] tokenInfo;
    }

    CloseHandle(hToken);
    return username.empty() ? TEXT("N/A") : username;
}

// ============================================================================
// 计算 CPU 使用率
// ============================================================================

double ProcessManager::CalculateCpuUsage(DWORD pid, HANDLE hProcess)
{
    FILETIME createTime, exitTime, kernelTime, userTime;

    if (!GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        return 0.0;
    }

    ULONGLONG kernel = ((ULONGLONG)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
    ULONGLONG user = ((ULONGLONG)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime;
    ULONGLONG now = 0;

    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    now = ((ULONGLONG)nowFt.dwHighDateTime << 32) | nowFt.dwLowDateTime;

    auto it = m_cpuTimes.find(pid);
    if (it == m_cpuTimes.end()) {
        // 首次记录
        CpuTimeInfo cti;
        cti.lastKernelTime = kernel;
        cti.lastUserTime = user;
        cti.lastSampleTime = now;
        m_cpuTimes[pid] = cti;
        return 0.0;
    }

    // 计算差值
    ULONGLONG kernelDiff = kernel - it->second.lastKernelTime;
    ULONGLONG userDiff = user - it->second.lastUserTime;
    ULONGLONG timeDiff = now - it->second.lastSampleTime;

    // 更新记录
    it->second.lastKernelTime = kernel;
    it->second.lastUserTime = user;
    it->second.lastSampleTime = now;

    if (timeDiff == 0) return 0.0;

    // 获取 CPU 核心数
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD numCpus = sysInfo.dwNumberOfProcessors;

    double cpuPercent = (double)(kernelDiff + userDiff) / timeDiff * 100.0 / numCpus;

    return (cpuPercent > 100.0) ? 100.0 : cpuPercent;
}

// ============================================================================
// 分析可疑进程
// ============================================================================

void ProcessManager::AnalyzeSuspiciousProcess(ProcessInfo& info)
{
    info.isSuspicious = false;
    info.suspiciousReason.clear();

    // 1. 检查可疑进程名
    if (Utils::IsSuspiciousProcessName(info.name)) {
        // 系统进程调用不一定可疑，需要检查路径
        if (!info.exePath.empty() && !Utils::IsInSystemDirectory(info.exePath)) {
            info.isSuspicious = true;
            info.suspiciousReason = TEXT("敏感进程从非系统目录运行");
        }
    }

    // 2. 检查进程名伪装 (svchost.exe 不是从 system32 启动)
    if (_tcsicmp(info.name.c_str(), TEXT("svchost.exe")) == 0) {
        if (!info.exePath.empty()) {
            TCHAR expectedPath[MAX_PATH];
            GetSystemDirectory(expectedPath, MAX_PATH);
            _tcscat_s(expectedPath, TEXT("\\svchost.exe"));

            if (_tcsicmp(info.exePath.c_str(), expectedPath) != 0) {
                info.isSuspicious = true;
                info.suspiciousReason = TEXT("svchost.exe 路径异常");
            }
        }
    }

    // 3. 检查进程名称中的可疑字符 (空格、Unicode欺骗)
    for (size_t i = 0; i < info.name.length(); i++) {
        TCHAR c = info.name[i];
        // 检查零宽字符等
        if (c == 0x200B || c == 0x200C || c == 0x200D || c == 0xFEFF) {
            info.isSuspicious = true;
            info.suspiciousReason = TEXT("进程名包含可疑字符");
            break;
        }
    }

    // 4. 检查双扩展名 (.txt.exe, .pdf.exe 等)
    const TCHAR* exts[] = { TEXT(".txt"), TEXT(".pdf"), TEXT(".doc"), TEXT(".jpg"), TEXT(".png"), NULL };
    for (int i = 0; exts[i] != NULL; i++) {
        if (info.name.find(exts[i]) != tstring::npos &&
            info.name.find(TEXT(".exe")) != tstring::npos) {
            info.isSuspicious = true;
            info.suspiciousReason = TEXT("双扩展名文件");
            break;
        }
    }
}

// ============================================================================
// 构建进程树
// ============================================================================

std::map<DWORD, ProcessTreeNode> ProcessManager::GetProcessTree()
{
    std::map<DWORD, ProcessTreeNode> tree;

    // 先获取所有进程
    std::vector<ProcessInfo> processes = GetAllProcesses();

    // 构建树结构
    for (const auto& proc : processes) {
        ProcessTreeNode node;
        node.info = proc;
        tree[proc.pid] = node;
    }

    // 建立父子关系
    for (auto& pair : tree) {
        DWORD ppid = pair.second.info.ppid;
        if (ppid != 0 && tree.find(ppid) != tree.end()) {
            tree[ppid].children.push_back(pair.first);
        }
    }

    return tree;
}

// ============================================================================
// 获取单个进程详情
// ============================================================================

bool ProcessManager::GetProcessDetails(DWORD pid, ProcessInfo& info)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    bool found = false;
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                info = GetBasicProcessInfo(pe);

                HANDLE hProcess = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProcess) {
                    info.exePath = GetProcessPath(pid);
                    info.username = GetProcessUsername(hProcess);
                    info.cpuPercent = CalculateCpuUsage(pid, hProcess);
                    info.commandLine = GetProcessCommandLine(pid);

                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        info.workingSetKB = pmc.WorkingSetSize / 1024;
                        info.memoryKB = pmc.PagefileUsage / 1024;
                    }

                    FILETIME createTime, exitTime, kernelTime, userTime;
                    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                        info.createTime = createTime;
                    }

                    CloseHandle(hProcess);
                }

                AnalyzeSuspiciousProcess(info);
                found = true;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return found;
}

// ============================================================================
// 获取进程命令行
// ============================================================================

tstring ProcessManager::GetProcessCommandLine(DWORD pid)
{
    // 注意：获取命令行需要读取进程 PEB，比较复杂
    // 这里简化处理，返回空字符串
    // 完整实现需要 NtQueryInformationProcess + 远程内存读取
    return TEXT("");
}

// ============================================================================
// 终止进程
// ============================================================================

bool ProcessManager::TerminateProcess(DWORD pid, tstring& errorMsg)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        errorMsg = TEXT("无法打开进程: ") + GetLastErrorString();
        return false;
    }

    BOOL result = ::TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);

    if (!result) {
        errorMsg = TEXT("终止进程失败: ") + GetLastErrorString();
        return false;
    }

    return true;
}

// ============================================================================
// 挂起进程
// ============================================================================

bool ProcessManager::SuspendProcess(DWORD pid, tstring& errorMsg)
{
    if (!m_pfnNtSuspendProcess) {
        errorMsg = TEXT("系统不支持挂起进程操作");
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) {
        errorMsg = TEXT("无法打开进程: ") + GetLastErrorString();
        return false;
    }

    LONG status = m_pfnNtSuspendProcess(hProcess);
    CloseHandle(hProcess);

    if (status != 0) {
        errorMsg = TEXT("挂起进程失败");
        return false;
    }

    return true;
}

// ============================================================================
// 恢复进程
// ============================================================================

bool ProcessManager::ResumeProcess(DWORD pid, tstring& errorMsg)
{
    if (!m_pfnNtResumeProcess) {
        errorMsg = TEXT("系统不支持恢复进程操作");
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) {
        errorMsg = TEXT("无法打开进程: ") + GetLastErrorString();
        return false;
    }

    LONG status = m_pfnNtResumeProcess(hProcess);
    CloseHandle(hProcess);

    if (status != 0) {
        errorMsg = TEXT("恢复进程失败");
        return false;
    }

    return true;
}

// ============================================================================
// 搜索进程
// ============================================================================

std::vector<ProcessInfo> ProcessManager::SearchProcesses(const tstring& keyword)
{
    std::vector<ProcessInfo> results;

    for (const auto& proc : m_processCache) {
        // 搜索进程名
        if (proc.name.find(keyword) != tstring::npos) {
            results.push_back(proc);
            continue;
        }

        // 搜索路径
        if (proc.exePath.find(keyword) != tstring::npos) {
            results.push_back(proc);
            continue;
        }

        // 搜索 PID
        TCHAR pidStr[32];
        _stprintf_s(pidStr, TEXT("%u"), proc.pid);
        if (_tcsstr(pidStr, keyword.c_str()) != NULL) {
            results.push_back(proc);
        }
    }

    return results;
}

// ============================================================================
// 刷新缓存
// ============================================================================

void ProcessManager::Refresh()
{
    GetAllProcesses();
}

// ============================================================================
// 枚举进程 PID 列表
// ============================================================================

std::vector<DWORD> ProcessManager::EnumProcesses()
{
    std::vector<DWORD> pids;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return pids;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID != 0) {  // 排除 System Idle Process
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pids;
}
