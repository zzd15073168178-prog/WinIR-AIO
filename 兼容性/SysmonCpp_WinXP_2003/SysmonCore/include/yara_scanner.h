// yara_scanner.h - YARA 规则扫描器
#pragma once

#include "common.h"

// YARA 匹配结果
struct YaraMatch {
    tstring ruleName;
    tstring ruleNamespace;
    tstring filePath;
    std::vector<tstring> tags;
    std::vector<tstring> strings;           // 保留兼容
    std::vector<tstring> matchedStrings;    // 匹配到的字符串
    tstring meta;
};

// YARA 规则信息
struct YaraRule {
    tstring name;
    tstring ruleNamespace;
    tstring filePath;
    tstring description;
    std::vector<tstring> tags;
};

// 扫描进度回调
typedef void (CALLBACK *YaraScanCallback)(const tstring& currentFile, DWORD processed, DWORD total, void* context);

class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();

    // 设置 yara.exe 路径 (如果使用外部调用)
    void SetYaraPath(const tstring& path);

    // 设置规则目录
    void SetRulesDirectory(const tstring& path);

    // 加载规则文件
    bool LoadRule(const tstring& rulePath);

    // 加载目录下所有规则
    bool LoadRulesFromDirectory(const tstring& dirPath);

    // 获取已加载的规则
    std::vector<YaraRule> GetLoadedRules() const { return m_loadedRules; }

    // 获取已加载规则数量
    size_t GetLoadedRulesCount() const { return m_loadedRules.size(); }

    // 从文件加载规则 (别名)
    bool LoadRulesFromFile(const tstring& filePath) { return LoadRule(filePath); }

    // 扫描文件
    std::vector<YaraMatch> ScanFile(const tstring& filePath);

    // 扫描目录
    std::vector<YaraMatch> ScanDirectory(const tstring& dirPath, bool recursive = true,
        YaraScanCallback callback = NULL, void* context = NULL);

    // 扫描进程内存
    std::vector<YaraMatch> ScanProcessMemory(DWORD pid);

    // 扫描所有运行进程
    std::vector<YaraMatch> ScanAllProcesses(YaraScanCallback callback = NULL, void* context = NULL);

    // 检查 yara 是否可用
    bool IsYaraAvailable() const;

    // 获取规则目录
    tstring GetRulesDirectory() const { return m_rulesDir; }

    // 清空已加载的规则
    void ClearRules();

private:
    tstring m_yaraPath;
    tstring m_rulesDir;
    std::vector<YaraRule> m_loadedRules;
    std::vector<tstring> m_ruleFiles;

    // 初始化默认路径
    void InitDefaultPaths();

    // 执行 yara.exe
    tstring ExecuteYara(const tstring& args);

    // 解析 yara 输出
    std::vector<YaraMatch> ParseYaraOutput(const tstring& output, const tstring& targetPath);

    // 解析规则文件获取规则信息
    std::vector<YaraRule> ParseRuleFile(const tstring& rulePath);

    // 递归枚举文件
    void EnumerateFiles(const tstring& dirPath, std::vector<tstring>& files, bool recursive);
};
