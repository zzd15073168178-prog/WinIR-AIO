// yara_scanner.cpp - YARA 规则扫描器实现
#include "../include/yara_scanner.h"
#include <shlwapi.h>
#include <strsafe.h>
#include <fstream>
#include <tlhelp32.h>

#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

YaraScanner::YaraScanner()
{
    InitDefaultPaths();
}

YaraScanner::~YaraScanner()
{
}

// ============================================================================
// 初始化默认路径
// ============================================================================

void YaraScanner::InitDefaultPaths()
{
    TCHAR modulePath[MAX_PATH];
    GetModuleFileName(NULL, modulePath, MAX_PATH);
    PathRemoveFileSpec(modulePath);

    // yara.exe 路径
    m_yaraPath = modulePath;
    m_yaraPath += TEXT("\\Tools\\yara64.exe");

    if (!PathFileExists(m_yaraPath.c_str())) {
        m_yaraPath = modulePath;
        m_yaraPath += TEXT("\\Tools\\yara.exe");
    }

    if (!PathFileExists(m_yaraPath.c_str())) {
        m_yaraPath = modulePath;
        m_yaraPath += TEXT("\\yara.exe");
    }

    // 规则目录
    m_rulesDir = modulePath;
    m_rulesDir += TEXT("\\Rules");

    CreateDirectory(m_rulesDir.c_str(), NULL);
}

// ============================================================================
// 设置路径
// ============================================================================

void YaraScanner::SetYaraPath(const tstring& path)
{
    m_yaraPath = path;
}

void YaraScanner::SetRulesDirectory(const tstring& path)
{
    m_rulesDir = path;
}

// ============================================================================
// 检查 yara 是否可用
// ============================================================================

bool YaraScanner::IsYaraAvailable() const
{
    return PathFileExists(m_yaraPath.c_str()) != FALSE;
}

// ============================================================================
// 加载规则文件
// ============================================================================

bool YaraScanner::LoadRule(const tstring& rulePath)
{
    if (!PathFileExists(rulePath.c_str())) {
        return false;
    }

    // 检查是否已加载
    for (const auto& file : m_ruleFiles) {
        if (_tcsicmp(file.c_str(), rulePath.c_str()) == 0) {
            return true; // 已加载
        }
    }

    m_ruleFiles.push_back(rulePath);

    // 解析规则信息
    auto rules = ParseRuleFile(rulePath);
    m_loadedRules.insert(m_loadedRules.end(), rules.begin(), rules.end());

    return true;
}

// ============================================================================
// 加载目录下所有规则
// ============================================================================

bool YaraScanner::LoadRulesFromDirectory(const tstring& dirPath)
{
    tstring searchPath = dirPath + TEXT("\\*.yar");

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(searchPath.c_str(), &fd);

    if (hFind == INVALID_HANDLE_VALUE) {
        // 尝试 .yara 扩展名
        searchPath = dirPath + TEXT("\\*.yara");
        hFind = FindFirstFile(searchPath.c_str(), &fd);
    }

    if (hFind == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool loaded = false;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            tstring rulePath = dirPath + TEXT("\\") + fd.cFileName;
            if (LoadRule(rulePath)) {
                loaded = true;
            }
        }
    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);

    return loaded;
}

// ============================================================================
// 清空规则
// ============================================================================

void YaraScanner::ClearRules()
{
    m_loadedRules.clear();
    m_ruleFiles.clear();
}

// ============================================================================
// 扫描文件
// ============================================================================

std::vector<YaraMatch> YaraScanner::ScanFile(const tstring& filePath)
{
    std::vector<YaraMatch> matches;

    if (!IsYaraAvailable()) {
        return matches;
    }

    if (m_ruleFiles.empty()) {
        // 尝试加载默认规则目录
        LoadRulesFromDirectory(m_rulesDir);
    }

    if (m_ruleFiles.empty()) {
        return matches;
    }

    // 对每个规则文件执行扫描
    for (const auto& ruleFile : m_ruleFiles) {
        tstring args = TEXT("\"") + ruleFile + TEXT("\" \"") + filePath + TEXT("\"");
        tstring output = ExecuteYara(args);

        auto fileMatches = ParseYaraOutput(output, filePath);
        matches.insert(matches.end(), fileMatches.begin(), fileMatches.end());
    }

    return matches;
}

// ============================================================================
// 扫描目录
// ============================================================================

std::vector<YaraMatch> YaraScanner::ScanDirectory(const tstring& dirPath, bool recursive,
    YaraScanCallback callback, void* context)
{
    std::vector<YaraMatch> allMatches;

    // 枚举文件
    std::vector<tstring> files;
    EnumerateFiles(dirPath, files, recursive);

    DWORD total = (DWORD)files.size();
    DWORD processed = 0;

    for (const auto& file : files) {
        if (callback) {
            callback(file, processed, total, context);
        }

        auto matches = ScanFile(file);
        allMatches.insert(allMatches.end(), matches.begin(), matches.end());

        processed++;
    }

    if (callback) {
        callback(TEXT(""), total, total, context);
    }

    return allMatches;
}

// ============================================================================
// 扫描进程内存
// ============================================================================

std::vector<YaraMatch> YaraScanner::ScanProcessMemory(DWORD pid)
{
    std::vector<YaraMatch> matches;

    if (!IsYaraAvailable()) {
        return matches;
    }

    if (m_ruleFiles.empty()) {
        LoadRulesFromDirectory(m_rulesDir);
    }

    if (m_ruleFiles.empty()) {
        return matches;
    }

    // yara 支持扫描进程: yara rules.yar pid
    for (const auto& ruleFile : m_ruleFiles) {
        TCHAR args[MAX_PATH + 32];
        StringCchPrintf(args, MAX_PATH + 32, TEXT("\"%s\" %lu"), ruleFile.c_str(), pid);

        tstring output = ExecuteYara(args);

        TCHAR target[32];
        StringCchPrintf(target, 32, TEXT("Process %lu"), pid);

        auto procMatches = ParseYaraOutput(output, target);
        matches.insert(matches.end(), procMatches.begin(), procMatches.end());
    }

    return matches;
}

// ============================================================================
// 扫描所有运行进程
// ============================================================================

std::vector<YaraMatch> YaraScanner::ScanAllProcesses(YaraScanCallback callback, void* context)
{
    std::vector<YaraMatch> allMatches;

    // 枚举所有进程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return allMatches;
    }

    std::vector<DWORD> pids;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID != 0 && pe.th32ProcessID != 4) {
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    DWORD total = (DWORD)pids.size();
    DWORD processed = 0;

    for (DWORD pid : pids) {
        if (callback) {
            TCHAR procName[64];
            StringCchPrintf(procName, 64, TEXT("Process %lu"), pid);
            callback(procName, processed, total, context);
        }

        auto matches = ScanProcessMemory(pid);
        allMatches.insert(allMatches.end(), matches.begin(), matches.end());

        processed++;
    }

    if (callback) {
        callback(TEXT(""), total, total, context);
    }

    return allMatches;
}

// ============================================================================
// 执行 yara.exe
// ============================================================================

tstring YaraScanner::ExecuteYara(const tstring& args)
{
    tstring output;

    tstring cmdLine = TEXT("\"") + m_yaraPath + TEXT("\" ") + args;

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
    WaitForSingleObject(pi.hProcess, 60000);
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
// 解析 yara 输出
// ============================================================================

std::vector<YaraMatch> YaraScanner::ParseYaraOutput(const tstring& output, const tstring& targetPath)
{
    std::vector<YaraMatch> matches;

    // yara 输出格式:
    // rule_name file_path
    // 或带 -s 选项时:
    // rule_name file_path
    // 0x12345:$string_name: matched_content

    size_t pos = 0;
    while (pos < output.length()) {
        size_t lineEnd = output.find(TEXT('\n'), pos);
        if (lineEnd == tstring::npos) lineEnd = output.length();

        tstring line = output.substr(pos, lineEnd - pos);

        // 去除回车
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }

        if (!line.empty() && line[0] != '0') {
            // 这是规则匹配行
            size_t spacePos = line.find(TEXT(' '));
            if (spacePos != tstring::npos) {
                YaraMatch match;
                match.ruleName = line.substr(0, spacePos);
                match.filePath = targetPath;

                // 检查是否有命名空间
                size_t colonPos = match.ruleName.find(TEXT(':'));
                if (colonPos != tstring::npos) {
                    match.ruleNamespace = match.ruleName.substr(0, colonPos);
                    match.ruleName = match.ruleName.substr(colonPos + 1);
                }

                matches.push_back(match);
            }
        }
        else if (!line.empty() && line[0] == '0') {
            // 这是字符串匹配行 (如果使用了 -s 选项)
            if (!matches.empty()) {
                matches.back().strings.push_back(line);
            }
        }

        pos = lineEnd + 1;
    }

    return matches;
}

// ============================================================================
// 解析规则文件
// ============================================================================

std::vector<YaraRule> YaraScanner::ParseRuleFile(const tstring& rulePath)
{
    std::vector<YaraRule> rules;

#ifdef UNICODE
    std::wifstream file(rulePath);
#else
    std::ifstream file(rulePath);
#endif

    if (!file.is_open()) {
        return rules;
    }

    tstring line;
    YaraRule currentRule;
    bool inRule = false;

    while (std::getline(file, line)) {
        // 去除前导空格
        size_t start = line.find_first_not_of(TEXT(" \t"));
        if (start == tstring::npos) continue;
        line = line.substr(start);

        // 检查规则定义
        if (line.find(TEXT("rule ")) == 0) {
            if (inRule && !currentRule.name.empty()) {
                currentRule.filePath = rulePath;
                rules.push_back(currentRule);
            }

            currentRule = YaraRule();
            inRule = true;

            // 解析规则名
            size_t nameStart = 5; // "rule " 长度
            size_t nameEnd = line.find_first_of(TEXT(" :{"), nameStart);
            if (nameEnd != tstring::npos) {
                currentRule.name = line.substr(nameStart, nameEnd - nameStart);
            }
            else {
                currentRule.name = line.substr(nameStart);
            }

            // 检查标签
            size_t colonPos = line.find(TEXT(':'));
            if (colonPos != tstring::npos) {
                tstring tagPart = line.substr(nameEnd, colonPos - nameEnd);
                // 简单解析标签
            }
        }
        else if (inRule && line.find(TEXT("meta:")) == 0) {
            // 进入 meta 部分
        }
        else if (inRule && line.find(TEXT("description")) != tstring::npos) {
            // 解析描述
            size_t eqPos = line.find(TEXT('='));
            if (eqPos != tstring::npos) {
                size_t start = line.find(TEXT('"'), eqPos);
                size_t end = line.rfind(TEXT('"'));
                if (start != tstring::npos && end != tstring::npos && end > start) {
                    currentRule.description = line.substr(start + 1, end - start - 1);
                }
            }
        }
        else if (line[0] == '}') {
            // 规则结束
            if (inRule && !currentRule.name.empty()) {
                currentRule.filePath = rulePath;
                rules.push_back(currentRule);
            }
            currentRule = YaraRule();
            inRule = false;
        }
    }

    // 处理最后一个规则
    if (inRule && !currentRule.name.empty()) {
        currentRule.filePath = rulePath;
        rules.push_back(currentRule);
    }

    file.close();
    return rules;
}

// ============================================================================
// 递归枚举文件
// ============================================================================

void YaraScanner::EnumerateFiles(const tstring& dirPath, std::vector<tstring>& files, bool recursive)
{
    tstring searchPath = dirPath + TEXT("\\*");

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(searchPath.c_str(), &fd);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (_tcscmp(fd.cFileName, TEXT(".")) == 0 ||
            _tcscmp(fd.cFileName, TEXT("..")) == 0) {
            continue;
        }

        tstring fullPath = dirPath + TEXT("\\") + fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (recursive) {
                EnumerateFiles(fullPath, files, recursive);
            }
        }
        else {
            files.push_back(fullPath);
        }
    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);
}
