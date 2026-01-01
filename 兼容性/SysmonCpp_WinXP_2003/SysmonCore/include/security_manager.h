// security_manager.h - 安全检测管理器 (Autoruns 集成)
#pragma once

#include "common.h"

// 启动项类型
enum AutorunType {
    AUTORUN_LOGON = 0,          // 登录启动项
    AUTORUN_EXPLORER,           // Explorer 插件
    AUTORUN_IE,                 // IE 插件
    AUTORUN_SCHEDULED_TASK,     // 计划任务
    AUTORUN_SERVICE,            // 服务
    AUTORUN_DRIVER,             // 驱动
    AUTORUN_CODEC,              // 编解码器
    AUTORUN_BOOT_EXECUTE,       // 启动执行
    AUTORUN_IMAGE_HIJACK,       // 映像劫持
    AUTORUN_APPINIT,            // AppInit DLLs
    AUTORUN_KNOWN_DLLS,         // Known DLLs
    AUTORUN_WINLOGON,           // Winlogon
    AUTORUN_WINSOCK,            // Winsock 提供程序
    AUTORUN_PRINT_MONITOR,      // 打印监视器
    AUTORUN_LSA_PROVIDER,       // LSA 提供程序
    AUTORUN_NETWORK_PROVIDER,   // 网络提供程序
    AUTORUN_WMI,                // WMI
    AUTORUN_OFFICE,             // Office 插件
    AUTORUN_SIDEBAR,            // Sidebar 小工具
    AUTORUN_CHROME,             // Chrome 扩展
    AUTORUN_FIREFOX,            // Firefox 扩展
    AUTORUN_EDGE,               // Edge 扩展
    AUTORUN_UNKNOWN
};

// 启动项信息
struct AutorunEntry {
    tstring location;           // 位置 (注册表路径或文件夹)
    tstring entryName;          // 条目名
    tstring description;        // 描述
    tstring publisher;          // 发布者
    tstring imagePath;          // 镜像路径
    tstring version;            // 版本
    tstring launchString;       // 启动字符串
    AutorunType type;           // 类型
    bool isEnabled;             // 是否启用
    bool isSigned;              // 是否签名
    bool isVerified;            // 签名是否验证通过
    bool isSuspicious;          // 是否可疑
    tstring virusTotalResult;   // VirusTotal 结果
};

class SecurityManager {
public:
    SecurityManager();
    ~SecurityManager();

    // 设置 autorunsc.exe 路径
    void SetAutorunsPath(const tstring& path);

    // 扫描所有启动项
    std::vector<AutorunEntry> ScanAllAutoruns();

    // 扫描特定类型
    std::vector<AutorunEntry> ScanAutorunsByType(AutorunType type);

    // 获取可疑启动项
    std::vector<AutorunEntry> GetSuspiciousAutoruns();

    // 禁用启动项
    bool DisableAutorun(const AutorunEntry& entry);

    // 启用启动项
    bool EnableAutorun(const AutorunEntry& entry);

    // 删除启动项
    bool DeleteAutorun(const AutorunEntry& entry);

    // 检查 autorunsc.exe 是否可用
    bool IsAutorunsAvailable() const;

    // 导出报告
    bool ExportToCSV(const tstring& filePath, const std::vector<AutorunEntry>& entries);

private:
    tstring m_autorunsPath;

    // 初始化默认路径
    void InitDefaultPaths();

    // 执行 autorunsc 并解析输出
    std::vector<AutorunEntry> ExecuteAutorunsc(const tstring& args);

    // 解析 CSV 行
    AutorunEntry ParseCSVLine(const tstring& line);

    // 解析启动项类型
    AutorunType ParseAutorunType(const tstring& location);

    // 检查是否可疑
    bool CheckSuspicious(const AutorunEntry& entry);

    // CSV 字段解析
    std::vector<tstring> SplitCSV(const tstring& line);
};
