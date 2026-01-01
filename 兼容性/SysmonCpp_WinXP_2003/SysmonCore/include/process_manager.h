// process_manager.h - 进程管理器
#pragma once

#include "common.h"
#include <tlhelp32.h>
#include <psapi.h>

class ProcessManager {
public:
    ProcessManager();
    ~ProcessManager();

    // 获取所有进程列表
    std::vector<ProcessInfo> GetAllProcesses();

    // 构建进程树
    std::map<DWORD, ProcessTreeNode> GetProcessTree();

    // 获取单个进程详情
    bool GetProcessDetails(DWORD pid, ProcessInfo& info);

    // 进程操作
    bool TerminateProcess(DWORD pid, tstring& errorMsg);
    bool SuspendProcess(DWORD pid, tstring& errorMsg);
    bool ResumeProcess(DWORD pid, tstring& errorMsg);

    // 搜索进程
    std::vector<ProcessInfo> SearchProcesses(const tstring& keyword);

    // 枚举进程 PID 列表
    std::vector<DWORD> EnumProcesses();

    // 刷新缓存
    void Refresh();

private:
    std::vector<ProcessInfo> m_processCache;
    ULONGLONG m_lastRefreshTime;

    // CPU 使用率计算相关
    struct CpuTimeInfo {
        ULONGLONG lastKernelTime;
        ULONGLONG lastUserTime;
        ULONGLONG lastSampleTime;
    };
    std::map<DWORD, CpuTimeInfo> m_cpuTimes;

    // 内部方法
    ProcessInfo GetBasicProcessInfo(const PROCESSENTRY32& pe);
    tstring GetProcessPath(DWORD pid);
    tstring GetProcessUsername(HANDLE hProcess);
    tstring GetProcessCommandLine(DWORD pid);
    double CalculateCpuUsage(DWORD pid, HANDLE hProcess);
    void AnalyzeSuspiciousProcess(ProcessInfo& info);

    // Vista+ API 动态加载
    typedef BOOL(WINAPI* PFN_QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
    PFN_QueryFullProcessImageNameW m_pfnQueryFullProcessImageName;

    // NtSuspendProcess/NtResumeProcess 动态加载
    typedef LONG(NTAPI* PFN_NtSuspendProcess)(HANDLE);
    typedef LONG(NTAPI* PFN_NtResumeProcess)(HANDLE);
    PFN_NtSuspendProcess m_pfnNtSuspendProcess;
    PFN_NtResumeProcess m_pfnNtResumeProcess;

    void LoadOptionalAPIs();
};
