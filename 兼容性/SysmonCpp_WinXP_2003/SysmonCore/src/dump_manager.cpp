// dump_manager.cpp - 内存转储管理器实现
#include "../include/dump_manager.h"
#include <shlwapi.h>
#include <strsafe.h>

#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

DumpManager::DumpManager()
{
    InitDefaultPaths();
}

DumpManager::~DumpManager()
{
}

// ============================================================================
// 初始化默认路径
// ============================================================================

void DumpManager::InitDefaultPaths()
{
    // 获取程序所在目录
    TCHAR modulePath[MAX_PATH];
    GetModuleFileName(NULL, modulePath, MAX_PATH);
    PathRemoveFileSpec(modulePath);

    // 设置 procdump.exe 默认路径
    m_procDumpPath = modulePath;
    m_procDumpPath += TEXT("\\Tools\\procdump.exe");

    // 如果 Tools 目录不存在，尝试同级目录
    if (!PathFileExists(m_procDumpPath.c_str())) {
        m_procDumpPath = modulePath;
        m_procDumpPath += TEXT("\\procdump.exe");
    }

    // 设置输出目录
    m_outputDir = modulePath;
    m_outputDir += TEXT("\\Dumps");

    // 创建输出目录
    CreateDirectory(m_outputDir.c_str(), NULL);
}

// ============================================================================
// 设置路径
// ============================================================================

void DumpManager::SetProcDumpPath(const tstring& path)
{
    m_procDumpPath = path;
}

void DumpManager::SetOutputDirectory(const tstring& path)
{
    m_outputDir = path;
    CreateDirectory(m_outputDir.c_str(), NULL);
}

// ============================================================================
// 检查 procdump.exe 是否存在
// ============================================================================

bool DumpManager::IsProcDumpAvailable() const
{
    return PathFileExists(m_procDumpPath.c_str()) != FALSE;
}

// ============================================================================
// 创建进程转储
// ============================================================================

DumpResult DumpManager::CreateDump(DWORD pid, DumpType type)
{
    DumpResult result = { 0 };
    result.pid = pid;
    result.success = false;

    // 检查 procdump.exe
    if (!IsProcDumpAvailable()) {
        result.errorMessage = TEXT("procdump.exe 未找到: ") + m_procDumpPath;
        return result;
    }

    // 生成转储文件名
    SYSTEMTIME st;
    GetLocalTime(&st);

    TCHAR dumpFileName[MAX_PATH];
    StringCchPrintf(dumpFileName, MAX_PATH,
        TEXT("%s\\dump_%lu_%04d%02d%02d_%02d%02d%02d.dmp"),
        m_outputDir.c_str(), pid,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    result.dumpPath = dumpFileName;

    // 构建命令行
    tstring cmdLine = TEXT("\"") + m_procDumpPath + TEXT("\" -accepteula ");

    switch (type) {
    case DUMP_MINI:
        // 默认为 mini dump
        break;
    case DUMP_FULL:
        cmdLine += TEXT("-ma ");  // Full memory dump
        break;
    case DUMP_CUSTOM:
        cmdLine += TEXT("-mp ");  // MiniPlus
        break;
    }

    TCHAR pidStr[32];
    StringCchPrintf(pidStr, 32, TEXT("%lu"), pid);
    cmdLine += pidStr;
    cmdLine += TEXT(" \"");
    cmdLine += dumpFileName;
    cmdLine += TEXT("\"");

    // 执行命令
    tstring output;
    if (ExecuteCommand(cmdLine, output)) {
        // 检查文件是否创建成功
        if (PathFileExists(dumpFileName)) {
            result.success = true;
            result.fileSize = GetFileSize(dumpFileName);

            // 获取创建时间
            WIN32_FILE_ATTRIBUTE_DATA fileInfo;
            if (GetFileAttributesEx(dumpFileName, GetFileExInfoStandard, &fileInfo)) {
                result.createTime = fileInfo.ftCreationTime;
            }
        }
        else {
            result.errorMessage = TEXT("转储文件创建失败");
        }
    }
    else {
        result.errorMessage = TEXT("执行 procdump 失败: ") + output;
    }

    return result;
}

// ============================================================================
// 创建异常转储
// ============================================================================

DumpResult DumpManager::CreateExceptionDump(DWORD pid)
{
    DumpResult result = { 0 };
    result.pid = pid;
    result.success = false;

    if (!IsProcDumpAvailable()) {
        result.errorMessage = TEXT("procdump.exe 未找到");
        return result;
    }

    // 生成转储文件名
    SYSTEMTIME st;
    GetLocalTime(&st);

    TCHAR dumpFileName[MAX_PATH];
    StringCchPrintf(dumpFileName, MAX_PATH,
        TEXT("%s\\exception_%lu_%04d%02d%02d_%02d%02d%02d.dmp"),
        m_outputDir.c_str(), pid,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    result.dumpPath = dumpFileName;

    // 构建命令行 - 等待异常
    tstring cmdLine = TEXT("\"") + m_procDumpPath + TEXT("\" -accepteula -e ");

    TCHAR pidStr[32];
    StringCchPrintf(pidStr, 32, TEXT("%lu"), pid);
    cmdLine += pidStr;
    cmdLine += TEXT(" \"");
    cmdLine += dumpFileName;
    cmdLine += TEXT("\"");

    tstring output;
    if (ExecuteCommand(cmdLine, output)) {
        if (PathFileExists(dumpFileName)) {
            result.success = true;
            result.fileSize = GetFileSize(dumpFileName);
        }
    }
    else {
        result.errorMessage = output;
    }

    return result;
}

// ============================================================================
// 列出转储文件
// ============================================================================

std::vector<DumpResult> DumpManager::ListDumpFiles()
{
    std::vector<DumpResult> dumps;

    tstring searchPath = m_outputDir + TEXT("\\*.dmp");

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(searchPath.c_str(), &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                DumpResult dump = { 0 };
                dump.success = true;
                dump.dumpPath = m_outputDir + TEXT("\\") + fd.cFileName;
                dump.createTime = fd.ftCreationTime;
                dump.fileSize = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

                // 尝试从文件名解析 PID
                // 格式: dump_PID_YYYYMMDD_HHMMSS.dmp
                const TCHAR* fileName = fd.cFileName;
                if (_tcsncmp(fileName, TEXT("dump_"), 5) == 0 ||
                    _tcsncmp(fileName, TEXT("exception_"), 10) == 0) {
                    const TCHAR* pidStart = _tcschr(fileName, '_');
                    if (pidStart) {
                        pidStart++;
                        dump.pid = _ttol(pidStart);
                    }
                }

                dumps.push_back(dump);
            }
        } while (FindNextFile(hFind, &fd));

        FindClose(hFind);
    }

    return dumps;
}

// ============================================================================
// 删除转储文件
// ============================================================================

bool DumpManager::DeleteDump(const tstring& dumpPath)
{
    return DeleteFile(dumpPath.c_str()) != FALSE;
}

// ============================================================================
// 执行外部命令
// ============================================================================

bool DumpManager::ExecuteCommand(const tstring& cmdLine, tstring& output)
{
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // 创建管道
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return false;
    }

    // 确保读取句柄不被继承
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };

    // 复制命令行（CreateProcess 需要可修改的字符串）
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
        return false;
    }

    // 关闭写入端
    CloseHandle(hWritePipe);

    // 读取输出
    char buffer[4096];
    DWORD bytesRead;
    std::string outputA;

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        outputA += buffer;
    }

    CloseHandle(hReadPipe);

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, 60000); // 最多等待 60 秒

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 转换输出
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

    return exitCode == 0;
}

// ============================================================================
// 获取文件大小
// ============================================================================

ULONGLONG DumpManager::GetFileSize(const tstring& path)
{
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesEx(path.c_str(), GetFileExInfoStandard, &fileInfo)) {
        return ((ULONGLONG)fileInfo.nFileSizeHigh << 32) | fileInfo.nFileSizeLow;
    }
    return 0;
}
