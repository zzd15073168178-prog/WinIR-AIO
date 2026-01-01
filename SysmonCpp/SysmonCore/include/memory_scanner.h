// memory_scanner.h - 内存扫描器
#pragma once

#include "common.h"
#include <regex>

// 扫描模式
struct ScanPattern {
    tstring name;           // 模式名称
    tstring pattern;        // 正则表达式或字符串
    tstring category;       // 分类
    bool isRegex;           // 是否为正则
};

class MemoryScanner {
public:
    MemoryScanner();
    ~MemoryScanner();

    // 扫描进程内存
    std::vector<MemoryScanResult> ScanProcess(DWORD pid);

    // 扫描特定模式
    std::vector<MemoryScanResult> ScanProcessForPattern(DWORD pid, const ScanPattern& pattern);

    // 添加自定义模式
    void AddPattern(const ScanPattern& pattern);

    // 清除模式
    void ClearPatterns();

    // 获取内置模式
    static std::vector<ScanPattern> GetBuiltinPatterns();

    // 设置扫描选项
    void SetMaxRegionSize(SIZE_T size) { m_maxRegionSize = size; }
    void SetScanStrings(bool scan) { m_scanStrings = scan; }

private:
    std::vector<ScanPattern> m_patterns;
    SIZE_T m_maxRegionSize;
    bool m_scanStrings;

    // 内存保护常量
    static const DWORD PAGE_READABLE = PAGE_READONLY | PAGE_READWRITE |
        PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    // 扫描内存区域
    void ScanRegion(HANDLE hProcess, PVOID baseAddr, SIZE_T regionSize,
        const tstring& processName, DWORD pid, std::vector<MemoryScanResult>& results);

    // 搜索字符串 (返回 ANSI 字符串，因为内存数据是字节)
    std::vector<std::pair<SIZE_T, std::string>> FindStrings(const BYTE* buffer, SIZE_T size,
        size_t minLength = 4);

    // 匹配模式
    bool MatchPattern(const std::string& data, const ScanPattern& pattern,
        std::string& matchedContent);

    // 获取进程名
    tstring GetProcessName(DWORD pid);
};
