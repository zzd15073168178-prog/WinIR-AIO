// monitor_manager.h - 进程监控管理器 (Procmon 集成)
#pragma once

#include "common.h"

// Procmon 事件类型
enum ProcmonEventType {
    EVENT_PROCESS_START = 0,
    EVENT_PROCESS_EXIT,
    EVENT_FILE_READ,
    EVENT_FILE_WRITE,
    EVENT_FILE_CREATE,
    EVENT_FILE_DELETE,
    EVENT_REGISTRY_READ,
    EVENT_REGISTRY_WRITE,
    EVENT_NETWORK,
    EVENT_UNKNOWN,
    // 简化分类
    PROCMON_REGISTRY,
    PROCMON_FILESYSTEM,
    PROCMON_NETWORK,
    PROCMON_PROCESS
};

// Procmon 事件
struct ProcmonEvent {
    ULONGLONG timestamp;        // 时间戳 (FILETIME 格式)
    tstring processName;
    DWORD pid;
    tstring operation;
    tstring path;
    tstring result;
    tstring detail;
    ProcmonEventType type;      // 详细类型
    ProcmonEventType eventType; // 简化分类
};

// 监控配置
struct MonitorConfig {
    bool captureProcess;
    bool captureFileSystem;     // 文件系统事件
    bool captureRegistry;
    bool captureNetwork;
    tstring filterProcessName;  // 进程名过滤
    tstring filterPath;         // 路径过滤
    DWORD maxEvents;            // 最大事件数

    MonitorConfig()
        : captureProcess(true)
        , captureFileSystem(true)
        , captureRegistry(true)
        , captureNetwork(true)
        , maxEvents(10000)
    {}
};

class MonitorManager {
public:
    MonitorManager();
    ~MonitorManager();

    // 设置 Procmon.exe 路径
    void SetProcmonPath(const tstring& path);

    // 设置输出目录
    void SetOutputDirectory(const tstring& path);

    // 设置监控配置
    void SetConfig(const MonitorConfig& config);

    // 获取配置
    MonitorConfig GetConfig() const { return m_config; }

    // 开始监控 (无参数版本使用内部配置)
    bool StartMonitoring();

    // 开始监控 (带配置参数)
    bool StartMonitoring(const MonitorConfig& config);

    // 停止监控，返回日志文件路径
    tstring StopMonitoring();

    // 检查是否正在监控
    bool IsMonitoring() const { return m_isMonitoring; }

    // 保存日志到文件
    bool SaveLog(const tstring& filePath);

    // 解析 PML 文件 (Procmon 日志)
    std::vector<ProcmonEvent> ParsePMLFile(const tstring& pmlPath);

    // 解析 CSV 文件
    std::vector<ProcmonEvent> ParseCSVFile(const tstring& csvPath);

    // 获取事件列表
    std::vector<ProcmonEvent> GetEvents() const { return m_events; }

    // 获取最近的事件
    std::vector<ProcmonEvent> GetRecentEvents(DWORD maxCount = 1000);

    // 检查 Procmon 是否可用
    bool IsProcmonAvailable() const;

    // 获取输出目录
    tstring GetOutputDirectory() const { return m_outputDir; }

private:
    tstring m_procmonPath;
    tstring m_outputDir;
    tstring m_currentLogPath;
    bool m_isMonitoring;
    HANDLE m_hProcmonProcess;
    MonitorConfig m_config;
    std::vector<ProcmonEvent> m_events;

    // 初始化默认路径
    void InitDefaultPaths();

    // 执行命令
    bool ExecuteCommand(const tstring& cmdLine, bool wait = false);

    // 解析事件类型
    ProcmonEventType ParseEventType(const tstring& operation);

    // 获取事件分类
    ProcmonEventType GetEventCategory(const tstring& operation);

    // CSV 解析辅助函数
    std::vector<tstring> ParseCSVLine(const tstring& line);
};
