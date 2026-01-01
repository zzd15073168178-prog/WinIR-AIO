// monitor_manager.cpp - 进程监控管理器实现
#include "../include/monitor_manager.h"
#include <shlwapi.h>
#include <strsafe.h>
#include <fstream>

#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

MonitorManager::MonitorManager()
    : m_isMonitoring(false)
    , m_hProcmonProcess(NULL)
{
    InitDefaultPaths();
}

MonitorManager::~MonitorManager()
{
    if (m_isMonitoring) {
        StopMonitoring();
    }
}

// ============================================================================
// 初始化默认路径
// ============================================================================

void MonitorManager::InitDefaultPaths()
{
    TCHAR modulePath[MAX_PATH];
    GetModuleFileName(NULL, modulePath, MAX_PATH);
    PathRemoveFileSpec(modulePath);

    // 设置 Procmon.exe 默认路径
    m_procmonPath = modulePath;
    m_procmonPath += TEXT("\\Tools\\Procmon.exe");

    if (!PathFileExists(m_procmonPath.c_str())) {
        m_procmonPath = modulePath;
        m_procmonPath += TEXT("\\Procmon.exe");
    }

    // 设置输出目录
    m_outputDir = modulePath;
    m_outputDir += TEXT("\\ProcmonLogs");

    CreateDirectory(m_outputDir.c_str(), NULL);
}

// ============================================================================
// 设置路径
// ============================================================================

void MonitorManager::SetProcmonPath(const tstring& path)
{
    m_procmonPath = path;
}

void MonitorManager::SetOutputDirectory(const tstring& path)
{
    m_outputDir = path;
    CreateDirectory(m_outputDir.c_str(), NULL);
}

// ============================================================================
// 设置监控配置
// ============================================================================

void MonitorManager::SetConfig(const MonitorConfig& config)
{
    m_config = config;
}

// ============================================================================
// 开始监控 (无参数版本)
// ============================================================================

bool MonitorManager::StartMonitoring()
{
    return StartMonitoring(m_config);
}

// ============================================================================
// 检查 Procmon 是否可用
// ============================================================================

bool MonitorManager::IsProcmonAvailable() const
{
    return PathFileExists(m_procmonPath.c_str()) != FALSE;
}

// ============================================================================
// 开始监控
// ============================================================================

bool MonitorManager::StartMonitoring(const MonitorConfig& config)
{
    if (m_isMonitoring) {
        return false;
    }

    if (!IsProcmonAvailable()) {
        return false;
    }

    // 生成日志文件名
    SYSTEMTIME st;
    GetLocalTime(&st);

    TCHAR logFileName[MAX_PATH];
    StringCchPrintf(logFileName, MAX_PATH,
        TEXT("%s\\procmon_%04d%02d%02d_%02d%02d%02d.pml"),
        m_outputDir.c_str(),
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    m_currentLogPath = logFileName;

    // 构建命令行
    // /AcceptEula /Quiet /Minimized /BackingFile <path>
    tstring cmdLine = TEXT("\"") + m_procmonPath + TEXT("\" /AcceptEula /Quiet /Minimized /BackingFile \"");
    cmdLine += logFileName;
    cmdLine += TEXT("\"");

    // 添加过滤选项
    if (!config.captureProcess) {
        cmdLine += TEXT(" /NoProcess");
    }
    if (!config.captureFileSystem) {
        cmdLine += TEXT(" /NoFileSystem");
    }
    if (!config.captureRegistry) {
        cmdLine += TEXT(" /NoRegistry");
    }
    if (!config.captureNetwork) {
        cmdLine += TEXT(" /NoNetwork");
    }

    // 启动 Procmon
    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_MINIMIZE;

    PROCESS_INFORMATION pi = { 0 };
    TCHAR* cmdLineCopy = _tcsdup(cmdLine.c_str());

    BOOL success = CreateProcess(
        NULL,
        cmdLineCopy,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi);

    free(cmdLineCopy);

    if (success) {
        m_hProcmonProcess = pi.hProcess;
        CloseHandle(pi.hThread);
        m_isMonitoring = true;

        // 等待 Procmon 初始化
        Sleep(2000);

        return true;
    }

    return false;
}

// ============================================================================
// 停止监控
// ============================================================================

tstring MonitorManager::StopMonitoring()
{
    if (!m_isMonitoring) {
        return TEXT("");
    }

    // 发送终止命令给 Procmon
    // /Terminate 参数会让正在运行的 Procmon 实例停止
    tstring cmdLine = TEXT("\"") + m_procmonPath + TEXT("\" /Terminate");

    ExecuteCommand(cmdLine, true);

    // 等待进程结束
    if (m_hProcmonProcess) {
        WaitForSingleObject(m_hProcmonProcess, 5000);
        CloseHandle(m_hProcmonProcess);
        m_hProcmonProcess = NULL;
    }

    m_isMonitoring = false;

    // 解析日志文件
    if (!m_currentLogPath.empty()) {
        m_events = ParseCSVFile(m_currentLogPath);
    }

    return m_currentLogPath;
}

// ============================================================================
// 保存日志
// ============================================================================

bool MonitorManager::SaveLog(const tstring& filePath)
{
    if (m_currentLogPath.empty()) {
        return false;
    }

    // 如果正在监控，先停止
    bool wasMonitoring = m_isMonitoring;
    if (wasMonitoring) {
        StopMonitoring();
    }

    // 导出为 CSV
    tstring cmdLine = TEXT("\"") + m_procmonPath + TEXT("\" /OpenLog \"");
    cmdLine += m_currentLogPath;
    cmdLine += TEXT("\" /SaveAs \"");
    cmdLine += filePath;
    cmdLine += TEXT("\" /SaveApplyFilter");

    return ExecuteCommand(cmdLine, true);
}

// ============================================================================
// 解析 CSV 文件
// ============================================================================

std::vector<ProcmonEvent> MonitorManager::ParseCSVFile(const tstring& csvPath)
{
    std::vector<ProcmonEvent> events;

#ifdef UNICODE
    std::wifstream file(csvPath);
#else
    std::ifstream file(csvPath);
#endif

    if (!file.is_open()) {
        return events;
    }

    tstring line;
    bool isFirstLine = true;

    while (std::getline(file, line)) {
        // 跳过标题行
        if (isFirstLine) {
            isFirstLine = false;
            continue;
        }

        if (line.empty()) {
            continue;
        }

        std::vector<tstring> fields = ParseCSVLine(line);

        // Procmon CSV 格式:
        // Time,Process Name,PID,Operation,Path,Result,Detail
        if (fields.size() >= 7) {
            ProcmonEvent event;

            // 解析时间 (简化处理)
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            event.timestamp = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

            event.processName = fields[1];
            event.pid = _ttol(fields[2].c_str());
            event.operation = fields[3];
            event.path = fields[4];
            event.result = fields[5];
            event.detail = fields[6];
            event.type = ParseEventType(event.operation);

            events.push_back(event);
        }
    }

    file.close();
    return events;
}

// ============================================================================
// 解析 PML 文件 (简化版 - 实际需要二进制解析)
// ============================================================================

std::vector<ProcmonEvent> MonitorManager::ParsePMLFile(const tstring& pmlPath)
{
    std::vector<ProcmonEvent> events;

    // PML 是二进制格式，需要导出为 CSV 再解析
    // 生成临时 CSV 文件
    TCHAR tempPath[MAX_PATH];
    GetTempPath(MAX_PATH, tempPath);

    tstring csvPath = tempPath;
    csvPath += TEXT("procmon_export.csv");

    // 导出为 CSV
    tstring cmdLine = TEXT("\"") + m_procmonPath + TEXT("\" /OpenLog \"");
    cmdLine += pmlPath;
    cmdLine += TEXT("\" /SaveAs \"");
    cmdLine += csvPath;
    cmdLine += TEXT("\"");

    if (ExecuteCommand(cmdLine, true)) {
        events = ParseCSVFile(csvPath);
        DeleteFile(csvPath.c_str());
    }

    return events;
}

// ============================================================================
// 获取最近事件
// ============================================================================

std::vector<ProcmonEvent> MonitorManager::GetRecentEvents(DWORD maxCount)
{
    if (m_currentLogPath.empty()) {
        return std::vector<ProcmonEvent>();
    }

    // 如果正在监控，需要先保存当前日志
    if (m_isMonitoring) {
        // 暂时停止以获取数据
        tstring cmdLine = TEXT("\"") + m_procmonPath + TEXT("\" /Terminate");
        ExecuteCommand(cmdLine, true);
        Sleep(1000);

        // 重新启动
        MonitorConfig config;
        config.captureProcess = true;
        config.captureFileSystem = true;
        config.captureRegistry = true;
        config.captureNetwork = true;
        // StartMonitoring(config);  // 可选：自动重启监控
    }

    auto events = ParsePMLFile(m_currentLogPath);

    // 限制返回数量
    if (events.size() > maxCount) {
        events.erase(events.begin(), events.begin() + (events.size() - maxCount));
    }

    return events;
}

// ============================================================================
// 执行命令
// ============================================================================

bool MonitorManager::ExecuteCommand(const tstring& cmdLine, bool wait)
{
    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };
    TCHAR* cmdLineCopy = _tcsdup(cmdLine.c_str());

    BOOL success = CreateProcess(
        NULL,
        cmdLineCopy,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi);

    free(cmdLineCopy);

    if (success) {
        if (wait) {
            WaitForSingleObject(pi.hProcess, 30000);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }

    return false;
}

// ============================================================================
// 解析事件类型
// ============================================================================

ProcmonEventType MonitorManager::ParseEventType(const tstring& operation)
{
    if (operation.find(TEXT("Process Start")) != tstring::npos) {
        return EVENT_PROCESS_START;
    }
    if (operation.find(TEXT("Process Exit")) != tstring::npos) {
        return EVENT_PROCESS_EXIT;
    }
    if (operation.find(TEXT("ReadFile")) != tstring::npos ||
        operation.find(TEXT("QueryDirectory")) != tstring::npos) {
        return EVENT_FILE_READ;
    }
    if (operation.find(TEXT("WriteFile")) != tstring::npos) {
        return EVENT_FILE_WRITE;
    }
    if (operation.find(TEXT("CreateFile")) != tstring::npos) {
        return EVENT_FILE_CREATE;
    }
    if (operation.find(TEXT("SetDispositionInformation")) != tstring::npos) {
        return EVENT_FILE_DELETE;
    }
    if (operation.find(TEXT("RegQueryValue")) != tstring::npos ||
        operation.find(TEXT("RegOpenKey")) != tstring::npos) {
        return EVENT_REGISTRY_READ;
    }
    if (operation.find(TEXT("RegSetValue")) != tstring::npos ||
        operation.find(TEXT("RegCreateKey")) != tstring::npos) {
        return EVENT_REGISTRY_WRITE;
    }
    if (operation.find(TEXT("TCP")) != tstring::npos ||
        operation.find(TEXT("UDP")) != tstring::npos) {
        return EVENT_NETWORK;
    }

    return EVENT_UNKNOWN;
}

// ============================================================================
// CSV 行解析
// ============================================================================

std::vector<tstring> MonitorManager::ParseCSVLine(const tstring& line)
{
    std::vector<tstring> fields;
    tstring field;
    bool inQuotes = false;

    for (size_t i = 0; i < line.length(); i++) {
        TCHAR c = line[i];

        if (c == '"') {
            inQuotes = !inQuotes;
        }
        else if (c == ',' && !inQuotes) {
            fields.push_back(field);
            field.clear();
        }
        else {
            field += c;
        }
    }

    // 添加最后一个字段
    fields.push_back(field);

    return fields;
}
