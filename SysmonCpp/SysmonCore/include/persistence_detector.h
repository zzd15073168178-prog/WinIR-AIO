// persistence_detector.h - 持久化检测器
#pragma once

#include "common.h"

class PersistenceDetector {
public:
    PersistenceDetector();
    ~PersistenceDetector();

    // 获取所有持久化项
    std::vector<PersistenceItem> GetAllPersistenceItems();

    // 分类获取
    std::vector<PersistenceItem> GetRegistryRunKeys();
    std::vector<PersistenceItem> GetScheduledTasks();
    std::vector<PersistenceItem> GetServices();
    std::vector<PersistenceItem> GetStartupFolder();
    std::vector<PersistenceItem> GetWinlogon();
    std::vector<PersistenceItem> GetAppInit();
    std::vector<PersistenceItem> GetImageFileExecution();

    // 检测可疑项
    std::vector<PersistenceItem> GetSuspiciousItems();

    // 创建快照
    void TakeSnapshot();

    // 与快照比较，检测变化
    std::vector<PersistenceItem> DetectChanges();

private:
    std::vector<PersistenceItem> m_snapshot;

    // 注册表扫描
    void ScanRegistryKey(HKEY hRootKey, const tstring& subKey,
        const tstring& category, std::vector<PersistenceItem>& items);

    // 枚举注册表值
    void EnumRegistryValues(HKEY hKey, const tstring& keyPath,
        const tstring& category, std::vector<PersistenceItem>& items);

    // 分析可疑性
    void AnalyzeSuspicious(PersistenceItem& item);

    // 解析命令行中的可执行路径
    tstring ExtractExecutablePath(const tstring& cmdLine);

    // 检查路径是否可疑
    bool IsPathSuspicious(const tstring& path);
};
