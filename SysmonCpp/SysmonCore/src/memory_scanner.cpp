// memory_scanner.cpp - 内存扫描器实现
#include "../include/memory_scanner.h"
#include <tlhelp32.h>
#include <tchar.h>

// ============================================================================
// 构造函数和析构函数
// ============================================================================

MemoryScanner::MemoryScanner()
    : m_maxRegionSize(16 * 1024 * 1024)  // 16MB
    , m_scanStrings(true)
{
    // 加载内置模式
    m_patterns = GetBuiltinPatterns();
}

MemoryScanner::~MemoryScanner()
{
}

// ============================================================================
// 获取内置扫描模式
// ============================================================================

std::vector<ScanPattern> MemoryScanner::GetBuiltinPatterns()
{
    std::vector<ScanPattern> patterns;

    // IP 地址
    patterns.push_back({
        TEXT("IPv4地址"),
        TEXT("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"),
        TEXT("Network"),
        true
    });

    // URL
    patterns.push_back({
        TEXT("URL"),
        TEXT("https?://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,}(?:/[^\\s]*)?"),
        TEXT("Network"),
        true
    });

    // 电子邮件
    patterns.push_back({
        TEXT("Email"),
        TEXT("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"),
        TEXT("PII"),
        true
    });

    // Windows 路径
    patterns.push_back({
        TEXT("Windows路径"),
        TEXT("[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*"),
        TEXT("File"),
        true
    });

    // PowerShell 命令
    patterns.push_back({
        TEXT("PowerShell命令"),
        TEXT("(?:powershell|pwsh)(?:\\.exe)?\\s+[^\\x00]+"),
        TEXT("Command"),
        true
    });

    // Base64 编码数据 (长度 > 50)
    patterns.push_back({
        TEXT("Base64数据"),
        TEXT("[A-Za-z0-9+/]{50,}={0,2}"),
        TEXT("Encoded"),
        true
    });

    // 注册表路径
    patterns.push_back({
        TEXT("注册表路径"),
        TEXT("(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\\\[^\\x00\\r\\n]+"),
        TEXT("Registry"),
        true
    });

    // 可疑字符串
    patterns.push_back({
        TEXT("Mimikatz相关"),
        TEXT("mimikatz|sekurlsa|kerberos::"),
        TEXT("Malware"),
        true
    });

    patterns.push_back({
        TEXT("Shell命令"),
        TEXT("cmd\\.exe\\s+/c|cmd\\.exe\\s+/k"),
        TEXT("Command"),
        true
    });

    patterns.push_back({
        TEXT("网络命令"),
        TEXT("net\\s+user|net\\s+localgroup|net\\s+group"),
        TEXT("Command"),
        true
    });

    // 密码相关
    patterns.push_back({
        TEXT("密码字段"),
        TEXT("(?:password|passwd|pwd)\\s*[=:]\\s*[^\\s]+"),
        TEXT("Credential"),
        true
    });

    // API Key / Token
    patterns.push_back({
        TEXT("API密钥"),
        TEXT("(?:api[_-]?key|token|secret)\\s*[=:]\\s*[a-zA-Z0-9]{16,}"),
        TEXT("Credential"),
        true
    });

    return patterns;
}

// ============================================================================
// 扫描进程内存
// ============================================================================

std::vector<MemoryScanResult> MemoryScanner::ScanProcess(DWORD pid)
{
    std::vector<MemoryScanResult> results;

    // 打开进程
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        return results;
    }

    tstring processName = GetProcessName(pid);

    // 枚举内存区域
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = NULL;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        // 检查内存是否可读
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_READABLE) &&
            !(mbi.Protect & PAGE_GUARD)) {

            // 限制区域大小
            SIZE_T scanSize = mbi.RegionSize;
            if (scanSize > m_maxRegionSize) {
                scanSize = m_maxRegionSize;
            }

            ScanRegion(hProcess, mbi.BaseAddress, scanSize,
                processName, pid, results);
        }

        // 移动到下一个区域
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);

        // 防止无限循环
        if ((ULONG_PTR)address < (ULONG_PTR)mbi.BaseAddress) {
            break;
        }
    }

    CloseHandle(hProcess);
    return results;
}

// ============================================================================
// 扫描内存区域
// ============================================================================

void MemoryScanner::ScanRegion(HANDLE hProcess, PVOID baseAddr, SIZE_T regionSize,
    const tstring& processName, DWORD pid, std::vector<MemoryScanResult>& results)
{
    // 分配读取缓冲区
    std::vector<BYTE> buffer(regionSize);
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, baseAddr, buffer.data(), regionSize, &bytesRead)) {
        return;
    }

    if (bytesRead == 0) {
        return;
    }

    // 转换为字符串进行模式匹配
    std::string data((char*)buffer.data(), bytesRead);

    // 对每个模式进行匹配
    for (const auto& pattern : m_patterns) {
        std::string matchedContent;

        if (MatchPattern(data, pattern, matchedContent)) {
            MemoryScanResult result;
            result.pid = pid;
            result.processName = processName;
            result.address = baseAddr;
            result.regionSize = regionSize;
            result.pattern = pattern.name;
            result.category = pattern.category;

            // 截断匹配内容
            if (matchedContent.length() > 100) {
                matchedContent = matchedContent.substr(0, 100) + "...";
            }

#ifdef UNICODE
            // 转换为宽字符
            int len = MultiByteToWideChar(CP_ACP, 0,
                matchedContent.c_str(), -1, NULL, 0);
            if (len > 0) {
                result.matchedContent.resize(len);
                MultiByteToWideChar(CP_ACP, 0,
                    matchedContent.c_str(), -1,
                    &result.matchedContent[0], len);
            }
#else
            result.matchedContent = matchedContent;
#endif

            // 设置风险级别
            if (pattern.category == TEXT("Malware") ||
                pattern.category == TEXT("Credential")) {
                result.riskLevel = TEXT("高");
            } else if (pattern.category == TEXT("Command") ||
                pattern.category == TEXT("Encoded")) {
                result.riskLevel = TEXT("中");
            } else {
                result.riskLevel = TEXT("低");
            }

            results.push_back(result);
        }
    }

    // 提取可打印字符串
    if (m_scanStrings) {
        auto strings = FindStrings(buffer.data(), bytesRead, 8);

        for (const auto& str : strings) {
            // 检查是否包含可疑关键字
            const char* suspiciousKeywords[] = {
                "password", "secret", "token", "admin",
                "root", "shell", "inject", "payload",
                "exploit", "backdoor", "trojan", "keylog",
                NULL
            };

            std::string lowerStr = str.second;
            for (auto& c : lowerStr) c = tolower(c);

            for (int i = 0; suspiciousKeywords[i] != NULL; i++) {
                if (lowerStr.find(suspiciousKeywords[i]) != std::string::npos) {
                    MemoryScanResult result;
                    result.pid = pid;
                    result.processName = processName;
                    result.address = (PVOID)((ULONG_PTR)baseAddr + str.first);
                    result.regionSize = str.second.length();
                    result.pattern = TEXT("可疑关键字");
                    result.category = TEXT("String");
                    result.riskLevel = TEXT("中");

#ifdef UNICODE
                    int len = MultiByteToWideChar(CP_ACP, 0,
                        str.second.c_str(), -1, NULL, 0);
                    if (len > 0) {
                        result.matchedContent.resize(len);
                        MultiByteToWideChar(CP_ACP, 0,
                            str.second.c_str(), -1,
                            &result.matchedContent[0], len);
                    }
#else
                    result.matchedContent = str.second;
#endif

                    results.push_back(result);
                    break;
                }
            }
        }
    }
}

// ============================================================================
// 搜索可打印字符串
// ============================================================================

std::vector<std::pair<SIZE_T, std::string>> MemoryScanner::FindStrings(
    const BYTE* buffer, SIZE_T size, size_t minLength)
{
    std::vector<std::pair<SIZE_T, std::string>> strings;
    std::string current;
    SIZE_T startOffset = 0;

    for (SIZE_T i = 0; i < size; i++) {
        BYTE b = buffer[i];

        // 可打印 ASCII 字符
        if (b >= 32 && b < 127) {
            if (current.empty()) {
                startOffset = i;
            }
            current += (char)b;
        } else {
            if (current.length() >= minLength) {
                strings.push_back({ startOffset, current });
            }
            current.clear();
        }
    }

    // 处理末尾
    if (current.length() >= minLength) {
        strings.push_back({ startOffset, current });
    }

    return strings;
}

// ============================================================================
// 匹配模式
// ============================================================================

bool MemoryScanner::MatchPattern(const std::string& data, const ScanPattern& pattern,
    std::string& matchedContent)
{
    if (pattern.isRegex) {
        try {
            // 转换模式为 ANSI
            std::string patternStr;
#ifdef UNICODE
            int len = WideCharToMultiByte(CP_ACP, 0,
                pattern.pattern.c_str(), -1, NULL, 0, NULL, NULL);
            if (len > 0) {
                patternStr.resize(len);
                WideCharToMultiByte(CP_ACP, 0,
                    pattern.pattern.c_str(), -1,
                    &patternStr[0], len, NULL, NULL);
            }
#else
            patternStr = pattern.pattern;
#endif

            std::regex re(patternStr, std::regex::icase | std::regex::optimize);
            std::smatch match;

            if (std::regex_search(data, match, re)) {
                matchedContent = match[0].str();
                return true;
            }
        } catch (...) {
            // 正则表达式错误
        }
    } else {
        // 简单字符串搜索
        std::string patternStr;
#ifdef UNICODE
        int len = WideCharToMultiByte(CP_ACP, 0,
            pattern.pattern.c_str(), -1, NULL, 0, NULL, NULL);
        if (len > 0) {
            patternStr.resize(len);
            WideCharToMultiByte(CP_ACP, 0,
                pattern.pattern.c_str(), -1,
                &patternStr[0], len, NULL, NULL);
        }
#else
        patternStr = pattern.pattern;
#endif

        size_t pos = data.find(patternStr);
        if (pos != std::string::npos) {
            size_t endPos = pos + patternStr.length() + 50;
            if (endPos > data.length()) endPos = data.length();
            matchedContent = data.substr(pos, endPos - pos);
            return true;
        }
    }

    return false;
}

// ============================================================================
// 扫描特定模式
// ============================================================================

std::vector<MemoryScanResult> MemoryScanner::ScanProcessForPattern(
    DWORD pid, const ScanPattern& pattern)
{
    // 临时保存当前模式
    std::vector<ScanPattern> savedPatterns = m_patterns;

    // 只使用指定模式
    m_patterns.clear();
    m_patterns.push_back(pattern);

    // 扫描
    std::vector<MemoryScanResult> results = ScanProcess(pid);

    // 恢复模式
    m_patterns = savedPatterns;

    return results;
}

// ============================================================================
// 添加/清除模式
// ============================================================================

void MemoryScanner::AddPattern(const ScanPattern& pattern)
{
    m_patterns.push_back(pattern);
}

void MemoryScanner::ClearPatterns()
{
    m_patterns.clear();
}

// ============================================================================
// 获取进程名
// ============================================================================

tstring MemoryScanner::GetProcessName(DWORD pid)
{
    tstring name = TEXT("Unknown");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    name = pe.szExeFile;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    return name;
}
