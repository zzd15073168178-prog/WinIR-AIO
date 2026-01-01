// dll_manager.h - DLL 管理器
#pragma once

#include "common.h"
#include <psapi.h>

class DLLManager {
public:
    DLLManager();
    ~DLLManager();

    // 获取进程加载的所有 DLL
    std::vector<DllInfo> GetProcessDlls(DWORD pid);

    // 检测可疑 DLL
    std::vector<DllInfo> GetSuspiciousDlls(DWORD pid);

    // 获取 DLL 详细信息
    bool GetDllDetails(DWORD pid, const tstring& dllPath, DllInfo& info);

private:
    // 分析 DLL 是否可疑
    void AnalyzeSuspiciousDll(DllInfo& info, DWORD pid);

    // 获取文件版本信息
    bool GetFileVersionInfo(const tstring& path, tstring& version,
                           tstring& description, tstring& company);

    // 检查数字签名
    bool IsFileSigned(const tstring& path);

    // 已知的系统 DLL 列表
    bool IsKnownSystemDll(const tstring& dllName);
};
