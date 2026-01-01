// report_generator.h - 报告生成器
#pragma once

#include "common.h"
#include "process_manager.h"
#include "network_manager.h"
#include "persistence_detector.h"
#include "eventlog_manager.h"

// 报告类型
enum ReportFormat {
    REPORT_HTML = 0,
    REPORT_JSON,
    REPORT_CSV,
    REPORT_TEXT
};

// 报告章节
enum ReportSection {
    SECTION_SUMMARY = 0x0001,
    SECTION_PROCESSES = 0x0002,
    SECTION_NETWORK = 0x0004,
    SECTION_PERSISTENCE = 0x0008,
    SECTION_SERVICES = 0x0010,
    SECTION_EVENTS = 0x0020,
    SECTION_AUTORUNS = 0x0040,
    SECTION_SUSPICIOUS = 0x0080,
    SECTION_ALL = 0xFFFF
};

// 报告配置
struct ReportConfig {
    ReportFormat format;
    DWORD sections;         // ReportSection 位掩码
    tstring title;
    tstring author;
    tstring description;
    bool includeTimestamp;
    bool highlightSuspicious;
};

// 报告数据
struct ReportData {
    // 系统信息
    tstring computerName;
    tstring userName;
    tstring osVersion;
    FILETIME reportTime;

    // 各类数据
    std::vector<ProcessInfo> processes;
    std::vector<ProcessInfo> suspiciousProcesses;
    std::vector<NetworkConnection> connections;
    std::vector<NetworkConnection> suspiciousConnections;
    std::vector<PersistenceItem> persistenceItems;
    std::vector<PersistenceItem> suspiciousPersistence;
    std::vector<EventLogEntry> events;

    // 统计信息
    DWORD totalProcesses;
    DWORD suspiciousProcessCount;
    DWORD totalConnections;
    DWORD suspiciousConnectionCount;
    DWORD totalPersistenceItems;
    DWORD suspiciousPersistenceCount;
};

class ReportGenerator {
public:
    ReportGenerator();
    ~ReportGenerator();

    // 设置输出目录
    void SetOutputDirectory(const tstring& path);

    // 设置配置
    void SetConfig(const ReportConfig& config);

    // 设置报告数据
    void SetData(const ReportData& data);

    // 添加数据
    void AddProcesses(const std::vector<ProcessInfo>& processes);
    void AddConnections(const std::vector<NetworkConnection>& connections);
    void AddPersistenceItems(const std::vector<PersistenceItem>& items);
    void AddEvents(const std::vector<EventLogEntry>& events);

    // 生成报告
    bool GenerateReport(const tstring& outputPath = TEXT(""));

    // 生成快速报告 (自动收集数据)
    bool GenerateQuickReport(const tstring& outputPath = TEXT(""));

    // 获取上次生成的报告路径
    tstring GetLastReportPath() const { return m_lastReportPath; }

    // 获取输出目录
    tstring GetOutputDirectory() const { return m_outputDir; }

private:
    tstring m_outputDir;
    ReportConfig m_config;
    ReportData m_data;
    tstring m_lastReportPath;

    // 初始化默认配置
    void InitDefaults();

    // 收集系统信息
    void CollectSystemInfo();

    // 生成各种格式
    bool GenerateHTML(const tstring& path);
    bool GenerateJSON(const tstring& path);
    bool GenerateCSV(const tstring& path);
    bool GenerateText(const tstring& path);

    // HTML 辅助函数
    tstring EscapeHTML(const tstring& text);
    tstring GenerateHTMLHeader();
    tstring GenerateHTMLSummary();
    tstring GenerateHTMLProcesses();
    tstring GenerateHTMLNetwork();
    tstring GenerateHTMLPersistence();
    tstring GenerateHTMLEvents();
    tstring GenerateHTMLFooter();

    // JSON 辅助函数
    tstring EscapeJSON(const tstring& text);

    // 格式化时间
    tstring FormatTime(const FILETIME& ft);
    tstring FormatCurrentTime();
};
