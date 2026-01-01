// security_manager.cpp - 安全检测管理器实现
#include "../include/security_manager.h"
#include <shlwapi.h>
#include <strsafe.h>
#include <fstream>

#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

SecurityManager::SecurityManager()
{
    InitDefaultPaths();
}

SecurityManager::~SecurityManager()
{
}

// ============================================================================
// 初始化默认路径
// ============================================================================

void SecurityManager::InitDefaultPaths()
{
    TCHAR modulePath[MAX_PATH];
    GetModuleFileName(NULL, modulePath, MAX_PATH);
    PathRemoveFileSpec(modulePath);

    // 尝试不同路径
    m_autorunsPath = modulePath;
    m_autorunsPath += TEXT("\\Tools\\autorunsc64.exe");

    if (!PathFileExists(m_autorunsPath.c_str())) {
        m_autorunsPath = modulePath;
        m_autorunsPath += TEXT("\\Tools\\autorunsc.exe");
    }

    if (!PathFileExists(m_autorunsPath.c_str())) {
        m_autorunsPath = modulePath;
        m_autorunsPath += TEXT("\\autorunsc64.exe");
    }

    if (!PathFileExists(m_autorunsPath.c_str())) {
        m_autorunsPath = modulePath;
        m_autorunsPath += TEXT("\\autorunsc.exe");
    }
}

// ============================================================================
// 设置路径
// ============================================================================

void SecurityManager::SetAutorunsPath(const tstring& path)
{
    m_autorunsPath = path;
}

// ============================================================================
// 检查 autorunsc 是否可用
// ============================================================================

bool SecurityManager::IsAutorunsAvailable() const
{
    return PathFileExists(m_autorunsPath.c_str()) != FALSE;
}

// ============================================================================
// 扫描所有启动项
// ============================================================================

std::vector<AutorunEntry> SecurityManager::ScanAllAutoruns()
{
    // -a * = 所有条目
    // -c = CSV 格式
    // -h = 隐藏微软签名条目 (可选)
    // -s = 验证数字签名
    // -v = 查询 VirusTotal (可选，需要网络)
    // -nobanner = 不显示横幅
    return ExecuteAutorunsc(TEXT("-a * -c -s -nobanner"));
}

// ============================================================================
// 扫描特定类型
// ============================================================================

std::vector<AutorunEntry> SecurityManager::ScanAutorunsByType(AutorunType type)
{
    tstring args = TEXT("-c -s -nobanner ");

    switch (type) {
    case AUTORUN_LOGON:
        args += TEXT("-l"); // Logon
        break;
    case AUTORUN_EXPLORER:
        args += TEXT("-e"); // Explorer
        break;
    case AUTORUN_IE:
        args += TEXT("-i"); // Internet Explorer
        break;
    case AUTORUN_SCHEDULED_TASK:
        args += TEXT("-t"); // Scheduled tasks
        break;
    case AUTORUN_SERVICE:
        args += TEXT("-s"); // Services
        break;
    case AUTORUN_DRIVER:
        args += TEXT("-d"); // Drivers
        break;
    case AUTORUN_CODEC:
        args += TEXT("-c"); // Codecs
        break;
    case AUTORUN_BOOT_EXECUTE:
        args += TEXT("-b"); // Boot execute
        break;
    case AUTORUN_IMAGE_HIJACK:
        args += TEXT("-j"); // Image hijacks
        break;
    case AUTORUN_APPINIT:
        args += TEXT("-a"); // AppInit
        break;
    case AUTORUN_KNOWN_DLLS:
        args += TEXT("-k"); // Known DLLs
        break;
    case AUTORUN_WINLOGON:
        args += TEXT("-w"); // Winlogon
        break;
    case AUTORUN_WINSOCK:
        args += TEXT("-n"); // Winsock providers
        break;
    case AUTORUN_PRINT_MONITOR:
        args += TEXT("-p"); // Print monitors
        break;
    case AUTORUN_LSA_PROVIDER:
        args += TEXT("-r"); // LSA providers
        break;
    case AUTORUN_OFFICE:
        args += TEXT("-o"); // Office
        break;
    default:
        args += TEXT("-a *"); // 所有
        break;
    }

    return ExecuteAutorunsc(args);
}

// ============================================================================
// 获取可疑启动项
// ============================================================================

std::vector<AutorunEntry> SecurityManager::GetSuspiciousAutoruns()
{
    auto allEntries = ScanAllAutoruns();
    std::vector<AutorunEntry> suspicious;

    for (auto& entry : allEntries) {
        if (CheckSuspicious(entry)) {
            entry.isSuspicious = true;
            suspicious.push_back(entry);
        }
    }

    return suspicious;
}

// ============================================================================
// 执行 autorunsc 并解析输出
// ============================================================================

std::vector<AutorunEntry> SecurityManager::ExecuteAutorunsc(const tstring& args)
{
    std::vector<AutorunEntry> entries;

    if (!IsAutorunsAvailable()) {
        return entries;
    }

    // 创建临时文件
    TCHAR tempPath[MAX_PATH];
    GetTempPath(MAX_PATH, tempPath);

    tstring outputFile = tempPath;
    outputFile += TEXT("autoruns_output.csv");

    // 构建命令行
    tstring cmdLine = TEXT("\"") + m_autorunsPath + TEXT("\" ") + args;
    cmdLine += TEXT(" > \"");
    cmdLine += outputFile;
    cmdLine += TEXT("\"");

    // 使用 cmd /c 执行重定向
    tstring fullCmd = TEXT("cmd /c \"") + cmdLine + TEXT("\"");

    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };
    TCHAR* cmdLineCopy = _tcsdup(fullCmd.c_str());

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
        // 等待完成 (最多 2 分钟)
        WaitForSingleObject(pi.hProcess, 120000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // 读取 CSV 输出
#ifdef UNICODE
        std::wifstream file(outputFile);
#else
        std::ifstream file(outputFile);
#endif

        if (file.is_open()) {
            tstring line;
            bool isFirstLine = true;

            while (std::getline(file, line)) {
                // 跳过空行和标题行
                if (line.empty()) {
                    continue;
                }

                // 第一行是标题
                if (isFirstLine) {
                    isFirstLine = false;
                    continue;
                }

                AutorunEntry entry = ParseCSVLine(line);
                if (!entry.entryName.empty() || !entry.imagePath.empty()) {
                    entries.push_back(entry);
                }
            }

            file.close();
        }

        // 删除临时文件
        DeleteFile(outputFile.c_str());
    }

    return entries;
}

// ============================================================================
// 解析 CSV 行
// ============================================================================

AutorunEntry SecurityManager::ParseCSVLine(const tstring& line)
{
    AutorunEntry entry = { 0 };
    entry.isEnabled = true;
    entry.isSigned = false;
    entry.isVerified = false;
    entry.isSuspicious = false;
    entry.type = AUTORUN_UNKNOWN;

    std::vector<tstring> fields = SplitCSV(line);

    // autorunsc CSV 格式:
    // Time,Entry Location,Entry,Enabled,Category,Profile,Description,Company,Image Path,Version,Launch String,MD5,SHA-1,PESHA-1,PESHA-256,SHA-256,IMP,Signer,NIST,VT detection,VT Permalink

    if (fields.size() >= 11) {
        // 跳过 Time (字段 0)
        entry.location = fields.size() > 1 ? fields[1] : TEXT("");
        entry.entryName = fields.size() > 2 ? fields[2] : TEXT("");

        // Enabled
        if (fields.size() > 3) {
            entry.isEnabled = (fields[3] != TEXT("disabled"));
        }

        // Category (字段 4) - 可用于类型判断
        // Profile (字段 5)
        entry.description = fields.size() > 6 ? fields[6] : TEXT("");
        entry.publisher = fields.size() > 7 ? fields[7] : TEXT("");
        entry.imagePath = fields.size() > 8 ? fields[8] : TEXT("");
        entry.version = fields.size() > 9 ? fields[9] : TEXT("");
        entry.launchString = fields.size() > 10 ? fields[10] : TEXT("");

        // Signer (字段 17)
        if (fields.size() > 17 && !fields[17].empty()) {
            entry.isSigned = true;
            if (fields[17].find(TEXT("(Verified)")) != tstring::npos) {
                entry.isVerified = true;
            }
        }

        // VT detection (字段 19)
        if (fields.size() > 19) {
            entry.virusTotalResult = fields[19];
        }

        // 解析类型
        entry.type = ParseAutorunType(entry.location);

        // 检查是否可疑
        entry.isSuspicious = CheckSuspicious(entry);
    }

    return entry;
}

// ============================================================================
// 解析启动项类型
// ============================================================================

AutorunType SecurityManager::ParseAutorunType(const tstring& location)
{
    tstring loc = location;
    // 转小写
    for (size_t i = 0; i < loc.length(); i++) {
        loc[i] = _totlower(loc[i]);
    }

    if (loc.find(TEXT("run")) != tstring::npos ||
        loc.find(TEXT("startup")) != tstring::npos) {
        return AUTORUN_LOGON;
    }
    if (loc.find(TEXT("explorer")) != tstring::npos ||
        loc.find(TEXT("shellexecute")) != tstring::npos) {
        return AUTORUN_EXPLORER;
    }
    if (loc.find(TEXT("internet explorer")) != tstring::npos ||
        loc.find(TEXT("browser")) != tstring::npos) {
        return AUTORUN_IE;
    }
    if (loc.find(TEXT("task")) != tstring::npos ||
        loc.find(TEXT("schedule")) != tstring::npos) {
        return AUTORUN_SCHEDULED_TASK;
    }
    if (loc.find(TEXT("services")) != tstring::npos) {
        return AUTORUN_SERVICE;
    }
    if (loc.find(TEXT("driver")) != tstring::npos) {
        return AUTORUN_DRIVER;
    }
    if (loc.find(TEXT("codec")) != tstring::npos) {
        return AUTORUN_CODEC;
    }
    if (loc.find(TEXT("bootexecute")) != tstring::npos) {
        return AUTORUN_BOOT_EXECUTE;
    }
    if (loc.find(TEXT("image file execution")) != tstring::npos ||
        loc.find(TEXT("debugger")) != tstring::npos) {
        return AUTORUN_IMAGE_HIJACK;
    }
    if (loc.find(TEXT("appinit")) != tstring::npos) {
        return AUTORUN_APPINIT;
    }
    if (loc.find(TEXT("knowndll")) != tstring::npos) {
        return AUTORUN_KNOWN_DLLS;
    }
    if (loc.find(TEXT("winlogon")) != tstring::npos) {
        return AUTORUN_WINLOGON;
    }
    if (loc.find(TEXT("winsock")) != tstring::npos) {
        return AUTORUN_WINSOCK;
    }
    if (loc.find(TEXT("print")) != tstring::npos) {
        return AUTORUN_PRINT_MONITOR;
    }
    if (loc.find(TEXT("lsa")) != tstring::npos ||
        loc.find(TEXT("security")) != tstring::npos) {
        return AUTORUN_LSA_PROVIDER;
    }
    if (loc.find(TEXT("network")) != tstring::npos) {
        return AUTORUN_NETWORK_PROVIDER;
    }
    if (loc.find(TEXT("wmi")) != tstring::npos) {
        return AUTORUN_WMI;
    }
    if (loc.find(TEXT("office")) != tstring::npos) {
        return AUTORUN_OFFICE;
    }

    return AUTORUN_UNKNOWN;
}

// ============================================================================
// 检查是否可疑
// ============================================================================

bool SecurityManager::CheckSuspicious(const AutorunEntry& entry)
{
    // 1. 未签名或签名未验证
    if (!entry.isVerified && !entry.publisher.empty()) {
        // 检查是否来自可信发布者
        tstring pub = entry.publisher;
        for (size_t i = 0; i < pub.length(); i++) {
            pub[i] = _totlower(pub[i]);
        }

        if (pub.find(TEXT("microsoft")) == tstring::npos &&
            pub.find(TEXT("windows")) == tstring::npos) {
            // 非微软签名且未验证，标记为可疑
            if (!entry.isSigned) {
                return true;
            }
        }
    }

    // 2. 路径可疑
    tstring path = entry.imagePath;
    for (size_t i = 0; i < path.length(); i++) {
        path[i] = _totlower(path[i]);
    }

    // 临时目录
    if (path.find(TEXT("\\temp\\")) != tstring::npos ||
        path.find(TEXT("\\tmp\\")) != tstring::npos) {
        return true;
    }

    // 用户目录下的隐藏位置
    if (path.find(TEXT("\\appdata\\local\\")) != tstring::npos &&
        path.find(TEXT("\\programs\\")) == tstring::npos) {
        // AppData\Local 下但不在 Programs 目录
        if (path.find(TEXT("\\microsoft\\")) == tstring::npos) {
            return true;
        }
    }

    // 3. 高风险位置
    if (entry.type == AUTORUN_IMAGE_HIJACK ||
        entry.type == AUTORUN_APPINIT ||
        entry.type == AUTORUN_LSA_PROVIDER ||
        entry.type == AUTORUN_BOOT_EXECUTE) {
        // 这些位置的非微软项都是可疑的
        tstring pub = entry.publisher;
        for (size_t i = 0; i < pub.length(); i++) {
            pub[i] = _totlower(pub[i]);
        }
        if (pub.find(TEXT("microsoft")) == tstring::npos) {
            return true;
        }
    }

    // 4. VirusTotal 有检测
    if (!entry.virusTotalResult.empty() &&
        entry.virusTotalResult != TEXT("0|0") &&
        entry.virusTotalResult.find(TEXT("0")) != 0) {
        return true;
    }

    // 5. 文件不存在
    if (!entry.imagePath.empty() && !PathFileExists(entry.imagePath.c_str())) {
        // 文件路径不为空但文件不存在
        // 排除带参数的情况
        if (entry.imagePath.find(TEXT(" ")) == tstring::npos) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// 禁用启动项
// ============================================================================

bool SecurityManager::DisableAutorun(const AutorunEntry& entry)
{
    // 这需要根据不同类型采取不同操作
    // 对于注册表项，可以添加 "disabled" 前缀或删除
    // 这里提供基本框架

    if (entry.location.find(TEXT("HKLM\\")) == 0 ||
        entry.location.find(TEXT("HKCU\\")) == 0) {
        // 注册表项
        // 实际实现需要使用 RegOpenKeyEx / RegDeleteValue
        return false; // 暂未实现
    }

    return false;
}

// ============================================================================
// 启用启动项
// ============================================================================

bool SecurityManager::EnableAutorun(const AutorunEntry& entry)
{
    // 需要根据类型实现
    return false;
}

// ============================================================================
// 删除启动项
// ============================================================================

bool SecurityManager::DeleteAutorun(const AutorunEntry& entry)
{
    // 需要根据类型实现
    return false;
}

// ============================================================================
// 导出到 CSV
// ============================================================================

bool SecurityManager::ExportToCSV(const tstring& filePath, const std::vector<AutorunEntry>& entries)
{
#ifdef UNICODE
    std::wofstream file(filePath);
#else
    std::ofstream file(filePath);
#endif

    if (!file.is_open()) {
        return false;
    }

    // 写入标题
    file << TEXT("Location,Entry,Description,Publisher,ImagePath,Version,Enabled,Signed,Verified,Suspicious\n");

    for (const auto& entry : entries) {
        file << TEXT("\"") << entry.location << TEXT("\",");
        file << TEXT("\"") << entry.entryName << TEXT("\",");
        file << TEXT("\"") << entry.description << TEXT("\",");
        file << TEXT("\"") << entry.publisher << TEXT("\",");
        file << TEXT("\"") << entry.imagePath << TEXT("\",");
        file << TEXT("\"") << entry.version << TEXT("\",");
        file << (entry.isEnabled ? TEXT("Yes") : TEXT("No")) << TEXT(",");
        file << (entry.isSigned ? TEXT("Yes") : TEXT("No")) << TEXT(",");
        file << (entry.isVerified ? TEXT("Yes") : TEXT("No")) << TEXT(",");
        file << (entry.isSuspicious ? TEXT("Yes") : TEXT("No")) << TEXT("\n");
    }

    file.close();
    return true;
}

// ============================================================================
// CSV 字段分割
// ============================================================================

std::vector<tstring> SecurityManager::SplitCSV(const tstring& line)
{
    std::vector<tstring> fields;
    tstring field;
    bool inQuotes = false;

    for (size_t i = 0; i < line.length(); i++) {
        TCHAR c = line[i];

        if (c == '"') {
            if (inQuotes && i + 1 < line.length() && line[i + 1] == '"') {
                // 转义的引号
                field += '"';
                i++;
            }
            else {
                inQuotes = !inQuotes;
            }
        }
        else if (c == ',' && !inQuotes) {
            fields.push_back(field);
            field.clear();
        }
        else {
            field += c;
        }
    }

    fields.push_back(field);
    return fields;
}
