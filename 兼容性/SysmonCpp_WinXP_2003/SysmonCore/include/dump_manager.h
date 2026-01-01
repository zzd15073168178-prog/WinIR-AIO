// dump_manager.h - 内存转储管理器
#pragma once

#include "common.h"

// 转储类型
enum DumpType {
    DUMP_MINI = 0,      // 最小转储
    DUMP_FULL = 1,      // 完整转储
    DUMP_CUSTOM = 2     // 自定义
};

// 转储结果
struct DumpResult {
    bool success;
    tstring dumpPath;
    tstring errorMessage;
    DWORD pid;
    ULONGLONG fileSize;
    FILETIME createTime;
};

class DumpManager {
public:
    DumpManager();
    ~DumpManager();

    // 设置 procdump.exe 路径
    void SetProcDumpPath(const tstring& path);

    // 设置输出目录
    void SetOutputDirectory(const tstring& path);

    // 创建进程转储
    DumpResult CreateDump(DWORD pid, DumpType type = DUMP_MINI);

    // 创建异常转储 (当进程崩溃时)
    DumpResult CreateExceptionDump(DWORD pid);

    // 列出已有的转储文件
    std::vector<DumpResult> ListDumpFiles();

    // 删除转储文件
    bool DeleteDump(const tstring& dumpPath);

    // 获取转储目录
    tstring GetOutputDirectory() const { return m_outputDir; }

    // 检查 procdump.exe 是否存在
    bool IsProcDumpAvailable() const;

private:
    tstring m_procDumpPath;
    tstring m_outputDir;

    // 执行外部命令
    bool ExecuteCommand(const tstring& cmdLine, tstring& output);

    // 获取文件大小
    ULONGLONG GetFileSize(const tstring& path);

    // 初始化默认路径
    void InitDefaultPaths();
};
