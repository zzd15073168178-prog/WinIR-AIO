// file_locker.cpp - 文件锁定分析器实现
#include "../include/file_locker.h"
#include <shlwapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

// Restart Manager 结构体定义 (Vista+ API, 手动定义以保持 XP 兼容)
#define CCH_RM_SESSION_KEY 32
#define CCH_RM_MAX_APP_NAME 255
#define CCH_RM_MAX_SVC_NAME 63

typedef struct {
    DWORD dwProcessId;
    FILETIME ProcessStartTime;
} RM_UNIQUE_PROCESS, *PRM_UNIQUE_PROCESS;

typedef enum {
    RmUnknownApp = 0,
    RmMainWindow = 1,
    RmOtherWindow = 2,
    RmService = 3,
    RmExplorer = 4,
    RmConsole = 5,
    RmCritical = 1000
} RM_APP_TYPE;

typedef struct {
    RM_UNIQUE_PROCESS Process;
    WCHAR strAppName[CCH_RM_MAX_APP_NAME + 1];
    WCHAR strServiceShortName[CCH_RM_MAX_SVC_NAME + 1];
    RM_APP_TYPE ApplicationType;
    ULONG AppStatus;
    DWORD TSSessionId;
    BOOL bRestartable;
} RM_PROCESS_INFO, *PRM_PROCESS_INFO;

// Restart Manager API 函数指针 (Vista+)
typedef DWORD (WINAPI *PFN_RmStartSession)(DWORD*, DWORD, WCHAR*);
typedef DWORD (WINAPI *PFN_RmRegisterResources)(DWORD, UINT, LPCWSTR*, UINT, PRM_UNIQUE_PROCESS, UINT, LPCWSTR*);
typedef DWORD (WINAPI *PFN_RmGetList)(DWORD, UINT*, UINT*, PRM_PROCESS_INFO, LPDWORD);
typedef DWORD (WINAPI *PFN_RmEndSession)(DWORD);

// ============================================================================
// 构造函数和析构函数
// ============================================================================

FileLocker::FileLocker()
{
    InitDefaultPaths();
}

FileLocker::~FileLocker()
{
}

// ============================================================================
// 初始化默认路径
// ============================================================================

void FileLocker::InitDefaultPaths()
{
    TCHAR modulePath[MAX_PATH];
    GetModuleFileName(NULL, modulePath, MAX_PATH);
    PathRemoveFileSpec(modulePath);

    m_handlePath = modulePath;
    m_handlePath += TEXT("\\Tools\\handle.exe");

    if (!PathFileExists(m_handlePath.c_str())) {
        m_handlePath = modulePath;
        m_handlePath += TEXT("\\handle.exe");
    }

    if (!PathFileExists(m_handlePath.c_str())) {
        m_handlePath = modulePath;
        m_handlePath += TEXT("\\Tools\\handle64.exe");
    }
}

// ============================================================================
// 设置路径
// ============================================================================

void FileLocker::SetHandlePath(const tstring& path)
{
    m_handlePath = path;
}

// ============================================================================
// 检查 handle.exe 是否可用
// ============================================================================

bool FileLocker::IsHandleAvailable() const
{
    return PathFileExists(m_handlePath.c_str()) != FALSE;
}

// ============================================================================
// 查找锁定指定文件的进程
// ============================================================================

std::vector<LockedFileInfo> FileLocker::FindLockingProcesses(const tstring& filePath)
{
    // 优先尝试使用 Restart Manager API (不需要 handle.exe)
    auto results = FindUsingRestartManager(filePath);
    if (!results.empty()) {
        return results;
    }

    // 回退到 handle.exe
    if (IsHandleAvailable()) {
        tstring output = ExecuteHandle(TEXT("-accepteula \"") + filePath + TEXT("\""));
        return ParseHandleOutput(output, filePath);
    }

    // 最后尝试原生方法
    return FindLockingProcessesNative(filePath);
}

// ============================================================================
// 使用 Restart Manager API
// ============================================================================

std::vector<LockedFileInfo> FileLocker::FindUsingRestartManager(const tstring& filePath)
{
    std::vector<LockedFileInfo> results;

    // 动态加载 Restart Manager (Vista+)
    HMODULE hRstrtMgr = LoadLibrary(TEXT("rstrtmgr.dll"));
    if (!hRstrtMgr) {
        return results;
    }

    PFN_RmStartSession pfnRmStartSession = (PFN_RmStartSession)GetProcAddress(hRstrtMgr, "RmStartSession");
    PFN_RmRegisterResources pfnRmRegisterResources = (PFN_RmRegisterResources)GetProcAddress(hRstrtMgr, "RmRegisterResources");
    PFN_RmGetList pfnRmGetList = (PFN_RmGetList)GetProcAddress(hRstrtMgr, "RmGetList");
    PFN_RmEndSession pfnRmEndSession = (PFN_RmEndSession)GetProcAddress(hRstrtMgr, "RmEndSession");

    if (!pfnRmStartSession || !pfnRmRegisterResources || !pfnRmGetList || !pfnRmEndSession) {
        FreeLibrary(hRstrtMgr);
        return results;
    }

    DWORD dwSession;
    WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };

    if (pfnRmStartSession(&dwSession, 0, szSessionKey) != ERROR_SUCCESS) {
        FreeLibrary(hRstrtMgr);
        return results;
    }

    // 转换文件路径为宽字符
#ifdef UNICODE
    LPCWSTR pszFile = filePath.c_str();
#else
    WCHAR wszPath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, filePath.c_str(), -1, wszPath, MAX_PATH);
    LPCWSTR pszFile = wszPath;
#endif

    if (pfnRmRegisterResources(dwSession, 1, &pszFile, 0, NULL, 0, NULL) == ERROR_SUCCESS) {
        UINT nProcInfoNeeded = 0;
        UINT nProcInfo = 0;
        DWORD dwReason;

        // 第一次调用获取所需大小
        DWORD dwError = pfnRmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);

        if (dwError == ERROR_MORE_DATA && nProcInfoNeeded > 0) {
            RM_PROCESS_INFO* pProcessInfo = new RM_PROCESS_INFO[nProcInfoNeeded];
            nProcInfo = nProcInfoNeeded;

            if (pfnRmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, pProcessInfo, &dwReason) == ERROR_SUCCESS) {
                for (UINT i = 0; i < nProcInfo; i++) {
                    LockedFileInfo info;
                    info.filePath = filePath;
                    info.pid = pProcessInfo[i].Process.dwProcessId;

#ifdef UNICODE
                    info.processName = pProcessInfo[i].strAppName;
#else
                    char szAppName[CCH_RM_MAX_APP_NAME + 1];
                    WideCharToMultiByte(CP_ACP, 0, pProcessInfo[i].strAppName, -1, szAppName, CCH_RM_MAX_APP_NAME + 1, NULL, NULL);
                    info.processName = szAppName;
#endif

                    // 获取进程路径 (使用 GetModuleFileNameEx 保持 XP 兼容)
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
                    if (hProcess) {
                        TCHAR szPath[MAX_PATH];
                        if (GetModuleFileNameEx(hProcess, NULL, szPath, MAX_PATH)) {
                            info.processPath = szPath;
                        }
                        CloseHandle(hProcess);
                    }

                    results.push_back(info);
                }
            }

            delete[] pProcessInfo;
        }
    }

    pfnRmEndSession(dwSession);
    FreeLibrary(hRstrtMgr);

    return results;
}

// ============================================================================
// 获取指定进程打开的文件
// ============================================================================

std::vector<LockedFileInfo> FileLocker::GetProcessFiles(DWORD pid)
{
    std::vector<LockedFileInfo> results;

    if (!IsHandleAvailable()) {
        return results;
    }

    TCHAR args[64];
    StringCchPrintf(args, 64, TEXT("-accepteula -p %lu"), pid);

    tstring output = ExecuteHandle(args);

    // 解析输出
    // 格式: process.exe pid: handle type name
    // 只提取 File 类型

    size_t pos = 0;
    while ((pos = output.find(TEXT("File"), pos)) != tstring::npos) {
        // 找行首
        size_t lineStart = output.rfind(TEXT('\n'), pos);
        if (lineStart == tstring::npos) lineStart = 0;
        else lineStart++;

        // 找行尾
        size_t lineEnd = output.find(TEXT('\n'), pos);
        if (lineEnd == tstring::npos) lineEnd = output.length();

        tstring line = output.substr(lineStart, lineEnd - lineStart);

        // 解析行
        // 格式类似: 1234: File  (RW-)   C:\path\to\file
        size_t colonPos = line.find(TEXT(':'));
        if (colonPos != tstring::npos) {
            LockedFileInfo info;
            info.pid = pid;
            info.handleValue = _ttol(line.c_str());

            // 查找路径
            size_t pathPos = line.find(TEXT("   "), colonPos);
            if (pathPos != tstring::npos) {
                pathPos += 3;
                while (pathPos < line.length() && line[pathPos] == ' ') pathPos++;
                info.filePath = line.substr(pathPos);

                // 去除末尾空格
                while (!info.filePath.empty() &&
                    (info.filePath.back() == ' ' || info.filePath.back() == '\r')) {
                    info.filePath.pop_back();
                }

                if (!info.filePath.empty()) {
                    results.push_back(info);
                }
            }
        }

        pos = lineEnd;
    }

    return results;
}

// ============================================================================
// 尝试解锁文件
// ============================================================================

bool FileLocker::UnlockFile(const LockedFileInfo& info)
{
    if (!IsHandleAvailable()) {
        return false;
    }

    // 使用 handle.exe -c 关闭句柄
    // 警告：强制关闭句柄可能导致目标进程崩溃或数据损坏
    TCHAR args[128];
    StringCchPrintf(args, 128, TEXT("-accepteula -c %lX -p %lu -y"),
        info.handleValue, info.pid);

    tstring output = ExecuteHandle(args);

    return output.find(TEXT("closed")) != tstring::npos ||
        output.find(TEXT("Handle closed")) != tstring::npos;
}

// ============================================================================
// 检查文件是否被锁定
// ============================================================================

bool FileLocker::IsFileLocked(const tstring& filePath)
{
    return !TryOpenFile(filePath);
}

// ============================================================================
// 尝试打开文件
// ============================================================================

bool FileLocker::TryOpenFile(const tstring& filePath)
{
    HANDLE hFile = CreateFile(
        filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,  // 不共享
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_SHARING_VIOLATION ||
            error == ERROR_LOCK_VIOLATION) {
            return false;  // 被锁定
        }
    }
    else {
        CloseHandle(hFile);
    }

    return true;  // 未锁定或文件不存在
}

// ============================================================================
// 获取锁定信息
// ============================================================================

tstring FileLocker::GetLockInfo(const tstring& filePath)
{
    auto lockers = FindLockingProcesses(filePath);

    if (lockers.empty()) {
        return TEXT("文件未被锁定");
    }

    tstring info;
    for (size_t i = 0; i < lockers.size(); i++) {
        if (i > 0) info += TEXT(", ");
        info += lockers[i].processName;
        info += TEXT(" (PID: ");

        TCHAR pidStr[16];
        StringCchPrintf(pidStr, 16, TEXT("%lu"), lockers[i].pid);
        info += pidStr;
        info += TEXT(")");
    }

    return info;
}

// ============================================================================
// 执行 handle.exe
// ============================================================================

tstring FileLocker::ExecuteHandle(const tstring& args)
{
    tstring output;

    tstring cmdLine = TEXT("\"") + m_handlePath + TEXT("\" ") + args;

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return output;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };
    TCHAR* cmdLineCopy = _tcsdup(cmdLine.c_str());

    BOOL success = CreateProcess(
        NULL,
        cmdLineCopy,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi);

    free(cmdLineCopy);

    if (!success) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return output;
    }

    CloseHandle(hWritePipe);

    char buffer[4096];
    DWORD bytesRead;
    std::string outputA;

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        outputA += buffer;
    }

    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

#ifdef UNICODE
    int len = MultiByteToWideChar(CP_ACP, 0, outputA.c_str(), -1, NULL, 0);
    if (len > 0) {
        TCHAR* wideStr = new TCHAR[len];
        MultiByteToWideChar(CP_ACP, 0, outputA.c_str(), -1, wideStr, len);
        output = wideStr;
        delete[] wideStr;
    }
#else
    output = outputA;
#endif

    return output;
}

// ============================================================================
// 解析 handle.exe 输出
// ============================================================================

std::vector<LockedFileInfo> FileLocker::ParseHandleOutput(const tstring& output, const tstring& targetPath)
{
    std::vector<LockedFileInfo> results;

    // handle.exe 输出格式:
    // ProcessName         pid: Handle Type          Name
    // 例如:
    // notepad.exe        1234: 1C: File  (RW-)   C:\test.txt

    tstring currentProcess;
    DWORD currentPid = 0;

    size_t pos = 0;
    while (pos < output.length()) {
        // 找行尾
        size_t lineEnd = output.find(TEXT('\n'), pos);
        if (lineEnd == tstring::npos) lineEnd = output.length();

        tstring line = output.substr(pos, lineEnd - pos);

        // 去除回车
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }

        if (!line.empty()) {
            // 检查是否是进程行 (包含 pid:)
            size_t pidPos = line.find(TEXT(" pid: "));
            if (pidPos != tstring::npos) {
                // 这是新进程
                currentProcess = line.substr(0, pidPos);
                // 去除空格
                while (!currentProcess.empty() && currentProcess.back() == ' ') {
                    currentProcess.pop_back();
                }

                currentPid = _ttol(line.c_str() + pidPos + 6);
            }
            else if (line.find(TEXT("File")) != tstring::npos) {
                // 这是文件句柄行
                LockedFileInfo info;
                info.processName = currentProcess;
                info.pid = currentPid;
                info.filePath = targetPath;

                // 解析句柄值
                size_t colonPos = line.find(TEXT(':'));
                if (colonPos != tstring::npos) {
                    info.handleValue = _tcstol(line.c_str(), NULL, 16);
                }

                results.push_back(info);
            }
        }

        pos = lineEnd + 1;
    }

    return results;
}

// ============================================================================
// 原生方法查找 (通过枚举进程和句柄)
// ============================================================================

std::vector<LockedFileInfo> FileLocker::FindLockingProcessesNative(const tstring& filePath)
{
    std::vector<LockedFileInfo> results;

    // 这个方法使用 NtQuerySystemInformation 枚举所有句柄
    // 然后检查哪些是文件句柄并且指向目标文件
    // 实现较复杂，这里提供简化版本

    // 枚举所有进程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return results;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            // 尝试打开进程
            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                FALSE, pe.th32ProcessID);

            if (hProcess) {
                // 这里应该枚举进程的句柄
                // 但完整实现需要 NtQuerySystemInformation
                // 略过详细实现

                CloseHandle(hProcess);
            }

        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return results;
}
