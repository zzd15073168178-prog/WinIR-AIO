// report_generator.cpp - 报告生成器实现
#include "../include/report_generator.h"
#include <shlwapi.h>
#include <strsafe.h>
#include <fstream>

#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

ReportGenerator::ReportGenerator()
{
    InitDefaults();
}

ReportGenerator::~ReportGenerator()
{
}

// ============================================================================
// 初始化默认配置
// ============================================================================

void ReportGenerator::InitDefaults()
{
    // 输出目录
    TCHAR modulePath[MAX_PATH];
    GetModuleFileName(NULL, modulePath, MAX_PATH);
    PathRemoveFileSpec(modulePath);

    m_outputDir = modulePath;
    m_outputDir += TEXT("\\Reports");

    CreateDirectory(m_outputDir.c_str(), NULL);

    // 默认配置
    m_config.format = REPORT_HTML;
    m_config.sections = SECTION_ALL;
    m_config.title = TEXT("系统安全分析报告");
    m_config.author = TEXT("Sysmon 分析工具");
    m_config.includeTimestamp = true;
    m_config.highlightSuspicious = true;

    // 清空数据
    ZeroMemory(&m_data, sizeof(m_data));
}

// ============================================================================
// 设置方法
// ============================================================================

void ReportGenerator::SetOutputDirectory(const tstring& path)
{
    m_outputDir = path;
    CreateDirectory(m_outputDir.c_str(), NULL);
}

void ReportGenerator::SetConfig(const ReportConfig& config)
{
    m_config = config;
}

void ReportGenerator::SetData(const ReportData& data)
{
    m_data = data;
}

// ============================================================================
// 添加数据
// ============================================================================

void ReportGenerator::AddProcesses(const std::vector<ProcessInfo>& processes)
{
    m_data.processes.insert(m_data.processes.end(), processes.begin(), processes.end());
    m_data.totalProcesses = (DWORD)m_data.processes.size();

    // 找出可疑进程
    m_data.suspiciousProcesses.clear();
    for (const auto& proc : m_data.processes) {
        if (proc.isSuspicious) {
            m_data.suspiciousProcesses.push_back(proc);
        }
    }
    m_data.suspiciousProcessCount = (DWORD)m_data.suspiciousProcesses.size();
}

void ReportGenerator::AddConnections(const std::vector<NetworkConnection>& connections)
{
    m_data.connections.insert(m_data.connections.end(), connections.begin(), connections.end());
    m_data.totalConnections = (DWORD)m_data.connections.size();

    // 找出可疑连接
    m_data.suspiciousConnections.clear();
    for (const auto& conn : m_data.connections) {
        if (conn.isSuspicious) {
            m_data.suspiciousConnections.push_back(conn);
        }
    }
    m_data.suspiciousConnectionCount = (DWORD)m_data.suspiciousConnections.size();
}

void ReportGenerator::AddPersistenceItems(const std::vector<PersistenceItem>& items)
{
    m_data.persistenceItems.insert(m_data.persistenceItems.end(), items.begin(), items.end());
    m_data.totalPersistenceItems = (DWORD)m_data.persistenceItems.size();

    // 找出可疑项
    m_data.suspiciousPersistence.clear();
    for (const auto& item : m_data.persistenceItems) {
        if (item.isSuspicious) {
            m_data.suspiciousPersistence.push_back(item);
        }
    }
    m_data.suspiciousPersistenceCount = (DWORD)m_data.suspiciousPersistence.size();
}

void ReportGenerator::AddEvents(const std::vector<EventLogEntry>& events)
{
    m_data.events.insert(m_data.events.end(), events.begin(), events.end());
}

// ============================================================================
// 收集系统信息
// ============================================================================

void ReportGenerator::CollectSystemInfo()
{
    // 计算机名
    TCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerName(computerName, &size)) {
        m_data.computerName = computerName;
    }

    // 用户名
    TCHAR userName[256];
    size = 256;
    if (GetUserName(userName, &size)) {
        m_data.userName = userName;
    }

    // OS 版本
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

#pragma warning(push)
#pragma warning(disable: 4996) // GetVersionEx 已弃用
    if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
        TCHAR osVersion[128];
        StringCchPrintf(osVersion, 128, TEXT("Windows %lu.%lu (Build %lu)"),
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        m_data.osVersion = osVersion;
    }
#pragma warning(pop)

    // 报告时间
    GetSystemTimeAsFileTime(&m_data.reportTime);
}

// ============================================================================
// 生成报告
// ============================================================================

bool ReportGenerator::GenerateReport(const tstring& outputPath)
{
    CollectSystemInfo();

    // 确定输出路径
    tstring path = outputPath;
    if (path.empty()) {
        SYSTEMTIME st;
        GetLocalTime(&st);

        TCHAR fileName[MAX_PATH];
        const TCHAR* ext = TEXT(".html");

        switch (m_config.format) {
        case REPORT_JSON: ext = TEXT(".json"); break;
        case REPORT_CSV: ext = TEXT(".csv"); break;
        case REPORT_TEXT: ext = TEXT(".txt"); break;
        default: ext = TEXT(".html"); break;
        }

        StringCchPrintf(fileName, MAX_PATH,
            TEXT("%s\\report_%04d%02d%02d_%02d%02d%02d%s"),
            m_outputDir.c_str(),
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            ext);

        path = fileName;
    }

    bool success = false;

    switch (m_config.format) {
    case REPORT_HTML:
        success = GenerateHTML(path);
        break;
    case REPORT_JSON:
        success = GenerateJSON(path);
        break;
    case REPORT_CSV:
        success = GenerateCSV(path);
        break;
    case REPORT_TEXT:
        success = GenerateText(path);
        break;
    }

    if (success) {
        m_lastReportPath = path;
    }

    return success;
}

// ============================================================================
// 生成快速报告
// ============================================================================

bool ReportGenerator::GenerateQuickReport(const tstring& outputPath)
{
    // 使用已添加的数据生成报告
    return GenerateReport(outputPath);
}

// ============================================================================
// 生成 HTML 报告
// ============================================================================

bool ReportGenerator::GenerateHTML(const tstring& path)
{
#ifdef UNICODE
    std::wofstream file(path);
#else
    std::ofstream file(path);
#endif

    if (!file.is_open()) {
        return false;
    }

    file << GenerateHTMLHeader();

    if (m_config.sections & SECTION_SUMMARY) {
        file << GenerateHTMLSummary();
    }

    if (m_config.sections & SECTION_PROCESSES) {
        file << GenerateHTMLProcesses();
    }

    if (m_config.sections & SECTION_NETWORK) {
        file << GenerateHTMLNetwork();
    }

    if (m_config.sections & SECTION_PERSISTENCE) {
        file << GenerateHTMLPersistence();
    }

    if (m_config.sections & SECTION_EVENTS) {
        file << GenerateHTMLEvents();
    }

    file << GenerateHTMLFooter();

    file.close();
    return true;
}

// ============================================================================
// HTML 辅助函数
// ============================================================================

tstring ReportGenerator::EscapeHTML(const tstring& text)
{
    tstring result;
    for (size_t i = 0; i < text.length(); i++) {
        switch (text[i]) {
        case '<': result += TEXT("&lt;"); break;
        case '>': result += TEXT("&gt;"); break;
        case '&': result += TEXT("&amp;"); break;
        case '"': result += TEXT("&quot;"); break;
        default: result += text[i]; break;
        }
    }
    return result;
}

tstring ReportGenerator::GenerateHTMLHeader()
{
    tstring html;
    html += TEXT("<!DOCTYPE html>\n<html>\n<head>\n");
    html += TEXT("<meta charset=\"UTF-8\">\n");
    html += TEXT("<title>") + EscapeHTML(m_config.title) + TEXT("</title>\n");
    html += TEXT("<style>\n");
    html += TEXT("body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }\n");
    html += TEXT("h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }\n");
    html += TEXT("h2 { color: #555; margin-top: 30px; }\n");
    html += TEXT(".summary-box { background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }\n");
    html += TEXT(".stat { display: inline-block; margin-right: 30px; }\n");
    html += TEXT(".stat-number { font-size: 24px; font-weight: bold; color: #4CAF50; }\n");
    html += TEXT(".stat-label { color: #666; }\n");
    html += TEXT(".warning { color: #f44336; }\n");
    html += TEXT("table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }\n");
    html += TEXT("th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }\n");
    html += TEXT("th { background: #4CAF50; color: white; }\n");
    html += TEXT("tr:nth-child(even) { background: #f9f9f9; }\n");
    html += TEXT("tr:hover { background: #f1f1f1; }\n");
    html += TEXT(".suspicious { background: #ffebee !important; }\n");
    html += TEXT(".suspicious td { color: #c62828; }\n");
    html += TEXT("</style>\n");
    html += TEXT("</head>\n<body>\n");
    html += TEXT("<h1>") + EscapeHTML(m_config.title) + TEXT("</h1>\n");

    return html;
}

tstring ReportGenerator::GenerateHTMLSummary()
{
    tstring html;
    html += TEXT("<div class=\"summary-box\">\n");
    html += TEXT("<h2>报告摘要</h2>\n");

    html += TEXT("<p><strong>计算机:</strong> ") + EscapeHTML(m_data.computerName) + TEXT("</p>\n");
    html += TEXT("<p><strong>用户:</strong> ") + EscapeHTML(m_data.userName) + TEXT("</p>\n");
    html += TEXT("<p><strong>操作系统:</strong> ") + EscapeHTML(m_data.osVersion) + TEXT("</p>\n");
    html += TEXT("<p><strong>报告时间:</strong> ") + FormatTime(m_data.reportTime) + TEXT("</p>\n");

    html += TEXT("<div style=\"margin-top: 20px;\">\n");

    html += TEXT("<div class=\"stat\"><span class=\"stat-number\">") + std::to_wstring(m_data.totalProcesses) +
        TEXT("</span><br><span class=\"stat-label\">进程</span></div>\n");

    if (m_data.suspiciousProcessCount > 0) {
        html += TEXT("<div class=\"stat\"><span class=\"stat-number warning\">") +
            std::to_wstring(m_data.suspiciousProcessCount) +
            TEXT("</span><br><span class=\"stat-label\">可疑进程</span></div>\n");
    }

    html += TEXT("<div class=\"stat\"><span class=\"stat-number\">") + std::to_wstring(m_data.totalConnections) +
        TEXT("</span><br><span class=\"stat-label\">网络连接</span></div>\n");

    if (m_data.suspiciousConnectionCount > 0) {
        html += TEXT("<div class=\"stat\"><span class=\"stat-number warning\">") +
            std::to_wstring(m_data.suspiciousConnectionCount) +
            TEXT("</span><br><span class=\"stat-label\">可疑连接</span></div>\n");
    }

    html += TEXT("<div class=\"stat\"><span class=\"stat-number\">") + std::to_wstring(m_data.totalPersistenceItems) +
        TEXT("</span><br><span class=\"stat-label\">持久化项</span></div>\n");

    if (m_data.suspiciousPersistenceCount > 0) {
        html += TEXT("<div class=\"stat\"><span class=\"stat-number warning\">") +
            std::to_wstring(m_data.suspiciousPersistenceCount) +
            TEXT("</span><br><span class=\"stat-label\">可疑持久化</span></div>\n");
    }

    html += TEXT("</div>\n");
    html += TEXT("</div>\n");

    return html;
}

tstring ReportGenerator::GenerateHTMLProcesses()
{
    tstring html;
    html += TEXT("<h2>进程列表</h2>\n");
    html += TEXT("<table>\n");
    html += TEXT("<tr><th>PID</th><th>进程名</th><th>路径</th><th>用户</th><th>CPU</th><th>内存</th></tr>\n");

    for (const auto& proc : m_data.processes) {
        tstring rowClass = proc.isSuspicious ? TEXT(" class=\"suspicious\"") : TEXT("");

        html += TEXT("<tr") + rowClass + TEXT(">");
        html += TEXT("<td>") + std::to_wstring(proc.pid) + TEXT("</td>");
        html += TEXT("<td>") + EscapeHTML(proc.name) + TEXT("</td>");
        html += TEXT("<td>") + EscapeHTML(proc.exePath) + TEXT("</td>");
        html += TEXT("<td>") + EscapeHTML(proc.username) + TEXT("</td>");

        TCHAR cpu[16];
        StringCchPrintf(cpu, 16, TEXT("%.1f%%"), proc.cpuPercent);
        html += TEXT("<td>") + tstring(cpu) + TEXT("</td>");

        TCHAR mem[32];
        StringCchPrintf(mem, 32, TEXT("%.1f MB"), (double)proc.memoryKB / 1024.0);
        html += TEXT("<td>") + tstring(mem) + TEXT("</td>");

        html += TEXT("</tr>\n");
    }

    html += TEXT("</table>\n");
    return html;
}

tstring ReportGenerator::GenerateHTMLNetwork()
{
    tstring html;
    html += TEXT("<h2>网络连接</h2>\n");
    html += TEXT("<table>\n");
    html += TEXT("<tr><th>协议</th><th>本地地址</th><th>远程地址</th><th>状态</th><th>PID</th><th>进程</th></tr>\n");

    for (const auto& conn : m_data.connections) {
        tstring rowClass = conn.isSuspicious ? TEXT(" class=\"suspicious\"") : TEXT("");

        html += TEXT("<tr") + rowClass + TEXT(">");
        html += TEXT("<td>") + EscapeHTML(conn.protocol) + TEXT("</td>");

        TCHAR localAddr[64];
        StringCchPrintf(localAddr, 64, TEXT("%s:%d"), conn.localAddr.c_str(), conn.localPort);
        html += TEXT("<td>") + tstring(localAddr) + TEXT("</td>");

        TCHAR remoteAddr[64];
        StringCchPrintf(remoteAddr, 64, TEXT("%s:%d"), conn.remoteAddr.c_str(), conn.remotePort);
        html += TEXT("<td>") + tstring(remoteAddr) + TEXT("</td>");

        html += TEXT("<td>") + EscapeHTML(conn.state) + TEXT("</td>");
        html += TEXT("<td>") + std::to_wstring(conn.pid) + TEXT("</td>");
        html += TEXT("<td>") + EscapeHTML(conn.processName) + TEXT("</td>");
        html += TEXT("</tr>\n");
    }

    html += TEXT("</table>\n");
    return html;
}

tstring ReportGenerator::GenerateHTMLPersistence()
{
    tstring html;
    html += TEXT("<h2>持久化配置</h2>\n");
    html += TEXT("<table>\n");
    html += TEXT("<tr><th>类型</th><th>名称</th><th>值</th><th>路径</th><th>可疑</th></tr>\n");

    for (const auto& item : m_data.persistenceItems) {
        tstring rowClass = item.isSuspicious ? TEXT(" class=\"suspicious\"") : TEXT("");

        html += TEXT("<tr") + rowClass + TEXT(">");
        html += TEXT("<td>") + EscapeHTML(item.category) + TEXT("</td>");
        html += TEXT("<td>") + EscapeHTML(item.name) + TEXT("</td>");
        html += TEXT("<td>") + EscapeHTML(item.value) + TEXT("</td>");
        html += TEXT("<td>") + EscapeHTML(item.location) + TEXT("</td>");
        html += TEXT("<td>") + tstring(item.isSuspicious ? TEXT("是") : TEXT("否")) + TEXT("</td>");
        html += TEXT("</tr>\n");
    }

    html += TEXT("</table>\n");
    return html;
}

tstring ReportGenerator::GenerateHTMLEvents()
{
    tstring html;
    html += TEXT("<h2>事件日志</h2>\n");
    html += TEXT("<table>\n");
    html += TEXT("<tr><th>时间</th><th>级别</th><th>来源</th><th>事件ID</th><th>消息</th></tr>\n");

    for (const auto& event : m_data.events) {
        html += TEXT("<tr>");
        html += TEXT("<td>") + FormatTime(event.timeGenerated) + TEXT("</td>");
        html += TEXT("<td>") + EscapeHTML(event.level) + TEXT("</td>");
        html += TEXT("<td>") + EscapeHTML(event.source) + TEXT("</td>");
        html += TEXT("<td>") + std::to_wstring(event.eventId) + TEXT("</td>");

        tstring msg = event.message;
        if (msg.length() > 200) {
            msg = msg.substr(0, 200) + TEXT("...");
        }
        html += TEXT("<td>") + EscapeHTML(msg) + TEXT("</td>");
        html += TEXT("</tr>\n");
    }

    html += TEXT("</table>\n");
    return html;
}

tstring ReportGenerator::GenerateHTMLFooter()
{
    tstring html;
    html += TEXT("<div style=\"margin-top: 30px; color: #666; text-align: center;\">\n");
    html += TEXT("<p>由 ") + EscapeHTML(m_config.author) + TEXT(" 生成</p>\n");
    html += TEXT("</div>\n");
    html += TEXT("</body>\n</html>\n");
    return html;
}

// ============================================================================
// 生成 JSON 报告
// ============================================================================

bool ReportGenerator::GenerateJSON(const tstring& path)
{
#ifdef UNICODE
    std::wofstream file(path);
#else
    std::ofstream file(path);
#endif

    if (!file.is_open()) {
        return false;
    }

    file << TEXT("{\n");
    file << TEXT("  \"report\": {\n");
    file << TEXT("    \"title\": \"") << EscapeJSON(m_config.title) << TEXT("\",\n");
    file << TEXT("    \"time\": \"") << FormatTime(m_data.reportTime) << TEXT("\",\n");
    file << TEXT("    \"computer\": \"") << EscapeJSON(m_data.computerName) << TEXT("\",\n");
    file << TEXT("    \"user\": \"") << EscapeJSON(m_data.userName) << TEXT("\",\n");
    file << TEXT("    \"os\": \"") << EscapeJSON(m_data.osVersion) << TEXT("\"\n");
    file << TEXT("  },\n");

    // 进程
    file << TEXT("  \"processes\": [\n");
    for (size_t i = 0; i < m_data.processes.size(); i++) {
        const auto& proc = m_data.processes[i];
        file << TEXT("    {\n");
        file << TEXT("      \"pid\": ") << proc.pid << TEXT(",\n");
        file << TEXT("      \"name\": \"") << EscapeJSON(proc.name) << TEXT("\",\n");
        file << TEXT("      \"path\": \"") << EscapeJSON(proc.exePath) << TEXT("\",\n");
        file << TEXT("      \"suspicious\": ") << (proc.isSuspicious ? TEXT("true") : TEXT("false")) << TEXT("\n");
        file << TEXT("    }") << (i < m_data.processes.size() - 1 ? TEXT(",") : TEXT("")) << TEXT("\n");
    }
    file << TEXT("  ],\n");

    // 网络连接
    file << TEXT("  \"connections\": [\n");
    for (size_t i = 0; i < m_data.connections.size(); i++) {
        const auto& conn = m_data.connections[i];
        file << TEXT("    {\n");
        file << TEXT("      \"protocol\": \"") << conn.protocol << TEXT("\",\n");
        file << TEXT("      \"localAddress\": \"") << conn.localAddr << TEXT("\",\n");
        file << TEXT("      \"localPort\": ") << conn.localPort << TEXT(",\n");
        file << TEXT("      \"remoteAddress\": \"") << conn.remoteAddr << TEXT("\",\n");
        file << TEXT("      \"remotePort\": ") << conn.remotePort << TEXT(",\n");
        file << TEXT("      \"pid\": ") << conn.pid << TEXT(",\n");
        file << TEXT("      \"suspicious\": ") << (conn.isSuspicious ? TEXT("true") : TEXT("false")) << TEXT("\n");
        file << TEXT("    }") << (i < m_data.connections.size() - 1 ? TEXT(",") : TEXT("")) << TEXT("\n");
    }
    file << TEXT("  ]\n");

    file << TEXT("}\n");

    file.close();
    return true;
}

// ============================================================================
// 生成 CSV 报告
// ============================================================================

bool ReportGenerator::GenerateCSV(const tstring& path)
{
#ifdef UNICODE
    std::wofstream file(path);
#else
    std::ofstream file(path);
#endif

    if (!file.is_open()) {
        return false;
    }

    // 进程 CSV
    file << TEXT("=== 进程列表 ===\n");
    file << TEXT("PID,进程名,路径,用户,可疑\n");

    for (const auto& proc : m_data.processes) {
        file << proc.pid << TEXT(",");
        file << TEXT("\"") << proc.name << TEXT("\",");
        file << TEXT("\"") << proc.exePath << TEXT("\",");
        file << TEXT("\"") << proc.username << TEXT("\",");
        file << (proc.isSuspicious ? TEXT("是") : TEXT("否")) << TEXT("\n");
    }

    file << TEXT("\n=== 网络连接 ===\n");
    file << TEXT("协议,本地地址,本地端口,远程地址,远程端口,PID,进程名,可疑\n");

    for (const auto& conn : m_data.connections) {
        file << conn.protocol << TEXT(",");
        file << conn.localAddr << TEXT(",");
        file << conn.localPort << TEXT(",");
        file << conn.remoteAddr << TEXT(",");
        file << conn.remotePort << TEXT(",");
        file << conn.pid << TEXT(",");
        file << TEXT("\"") << conn.processName << TEXT("\",");
        file << (conn.isSuspicious ? TEXT("是") : TEXT("否")) << TEXT("\n");
    }

    file.close();
    return true;
}

// ============================================================================
// 生成文本报告
// ============================================================================

bool ReportGenerator::GenerateText(const tstring& path)
{
#ifdef UNICODE
    std::wofstream file(path);
#else
    std::ofstream file(path);
#endif

    if (!file.is_open()) {
        return false;
    }

    file << TEXT("================================================================================\n");
    file << TEXT("                           ") << m_config.title << TEXT("\n");
    file << TEXT("================================================================================\n\n");

    file << TEXT("报告时间: ") << FormatTime(m_data.reportTime) << TEXT("\n");
    file << TEXT("计算机名: ") << m_data.computerName << TEXT("\n");
    file << TEXT("当前用户: ") << m_data.userName << TEXT("\n");
    file << TEXT("操作系统: ") << m_data.osVersion << TEXT("\n\n");

    file << TEXT("统计信息:\n");
    file << TEXT("  - 进程总数: ") << m_data.totalProcesses << TEXT(" (可疑: ") << m_data.suspiciousProcessCount << TEXT(")\n");
    file << TEXT("  - 网络连接: ") << m_data.totalConnections << TEXT(" (可疑: ") << m_data.suspiciousConnectionCount << TEXT(")\n");
    file << TEXT("  - 持久化项: ") << m_data.totalPersistenceItems << TEXT(" (可疑: ") << m_data.suspiciousPersistenceCount << TEXT(")\n\n");

    file << TEXT("--------------------------------------------------------------------------------\n");
    file << TEXT("进程列表\n");
    file << TEXT("--------------------------------------------------------------------------------\n\n");

    for (const auto& proc : m_data.processes) {
        file << TEXT("PID: ") << proc.pid;
        if (proc.isSuspicious) file << TEXT(" [可疑]");
        file << TEXT("\n");
        file << TEXT("  名称: ") << proc.name << TEXT("\n");
        file << TEXT("  路径: ") << proc.exePath << TEXT("\n");
        file << TEXT("  用户: ") << proc.username << TEXT("\n\n");
    }

    file.close();
    return true;
}

// ============================================================================
// JSON 转义
// ============================================================================

tstring ReportGenerator::EscapeJSON(const tstring& text)
{
    tstring result;
    for (size_t i = 0; i < text.length(); i++) {
        switch (text[i]) {
        case '"': result += TEXT("\\\""); break;
        case '\\': result += TEXT("\\\\"); break;
        case '\n': result += TEXT("\\n"); break;
        case '\r': result += TEXT("\\r"); break;
        case '\t': result += TEXT("\\t"); break;
        default: result += text[i]; break;
        }
    }
    return result;
}

// ============================================================================
// 格式化时间
// ============================================================================

tstring ReportGenerator::FormatTime(const FILETIME& ft)
{
    SYSTEMTIME st;
    FILETIME localFt;

    FileTimeToLocalFileTime(&ft, &localFt);
    FileTimeToSystemTime(&localFt, &st);

    TCHAR buffer[64];
    StringCchPrintf(buffer, 64, TEXT("%04d-%02d-%02d %02d:%02d:%02d"),
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return buffer;
}

tstring ReportGenerator::FormatCurrentTime()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return FormatTime(ft);
}
