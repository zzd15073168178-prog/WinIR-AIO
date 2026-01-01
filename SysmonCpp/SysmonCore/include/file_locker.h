// file_locker.h - 文件锁定分析器
#pragma once

#include "common.h"

// 锁定文件信息
struct LockedFileInfo {
    tstring filePath;
    DWORD pid;
    tstring processName;
    tstring processPath;
    DWORD handleValue;
    tstring accessMode;
    tstring shareMode;
};

// 文件句柄信息
struct FileHandleInfo {
    DWORD pid;
    tstring processName;
    DWORD handleValue;
    tstring handleType;
    tstring accessMode;
};

class FileLocker {
public:
    FileLocker();
    ~FileLocker();

    // 设置 handle.exe 路径
    void SetHandlePath(const tstring& path);

    // 查找锁定指定文件的进程
    std::vector<LockedFileInfo> FindLockingProcesses(const tstring& filePath);

    // 查找指定进程打开的文件
    std::vector<LockedFileInfo> GetProcessFiles(DWORD pid);

    // 尝试解锁文件 (关闭远程句柄)
    bool UnlockFile(const LockedFileInfo& info);

    // 检查文件是否被锁定
    bool IsFileLocked(const tstring& filePath);

    // 获取锁定文件的简要信息
    tstring GetLockInfo(const tstring& filePath);

    // 检查 handle.exe 是否可用
    bool IsHandleAvailable() const;

    // 使用原生 API 查找锁定进程 (不依赖 handle.exe)
    std::vector<LockedFileInfo> FindLockingProcessesNative(const tstring& filePath);

private:
    tstring m_handlePath;

    // 初始化默认路径
    void InitDefaultPaths();

    // 执行 handle.exe
    tstring ExecuteHandle(const tstring& args);

    // 解析 handle.exe 输出
    std::vector<LockedFileInfo> ParseHandleOutput(const tstring& output, const tstring& targetPath);

    // 使用 Restart Manager API (Vista+)
    std::vector<LockedFileInfo> FindUsingRestartManager(const tstring& filePath);

    // 尝试打开文件测试锁定
    bool TryOpenFile(const tstring& filePath);
};
