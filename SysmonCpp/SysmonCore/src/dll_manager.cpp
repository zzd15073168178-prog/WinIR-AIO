// dll_manager.cpp - DLL 管理器实现
#include "../include/dll_manager.h"
#include <tchar.h>
#include <shlwapi.h>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "psapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

DLLManager::DLLManager()
{
}

DLLManager::~DLLManager()
{
}

// ============================================================================
// 获取进程加载的所有 DLL
// ============================================================================

std::vector<DllInfo> DLLManager::GetProcessDlls(DWORD pid)
{
    std::vector<DllInfo> dlls;

    // 打开进程
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        return dlls;
    }

    // 枚举模块
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);

        for (DWORD i = 0; i < moduleCount; i++) {
            DllInfo info;

            // 获取模块路径
            TCHAR modulePath[MAX_PATH] = { 0 };
            if (GetModuleFileNameEx(hProcess, hMods[i], modulePath, MAX_PATH)) {
                info.path = modulePath;
            }

            // 获取模块信息
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                info.baseAddr = modInfo.lpBaseOfDll;
                info.size = modInfo.SizeOfImage;
            }

            // 获取版本信息
            if (!info.path.empty()) {
                GetFileVersionInfo(info.path, info.version, info.description, info.company);
            }

            // 分析是否可疑
            AnalyzeSuspiciousDll(info, pid);

            dlls.push_back(info);
        }
    }

    CloseHandle(hProcess);
    return dlls;
}

// ============================================================================
// 获取可疑 DLL
// ============================================================================

std::vector<DllInfo> DLLManager::GetSuspiciousDlls(DWORD pid)
{
    std::vector<DllInfo> suspiciousDlls;
    std::vector<DllInfo> allDlls = GetProcessDlls(pid);

    for (const auto& dll : allDlls) {
        if (dll.isSuspicious) {
            suspiciousDlls.push_back(dll);
        }
    }

    return suspiciousDlls;
}

// ============================================================================
// 获取 DLL 详细信息
// ============================================================================

bool DLLManager::GetDllDetails(DWORD pid, const tstring& dllPath, DllInfo& info)
{
    std::vector<DllInfo> dlls = GetProcessDlls(pid);

    for (const auto& dll : dlls) {
        if (_tcsicmp(dll.path.c_str(), dllPath.c_str()) == 0) {
            info = dll;
            return true;
        }
    }

    return false;
}

// ============================================================================
// 分析可疑 DLL
// ============================================================================

void DLLManager::AnalyzeSuspiciousDll(DllInfo& info, DWORD pid)
{
    info.isSuspicious = false;
    info.suspiciousReason.clear();

    if (info.path.empty()) {
        return;
    }

    // 获取 DLL 文件名
    tstring dllName = PathFindFileName(info.path.c_str());

    // 1. 检查是否在非标准路径
    bool inSystemDir = Utils::IsInSystemDirectory(info.path);

    // 系统 DLL 应该在系统目录
    if (IsKnownSystemDll(dllName) && !inSystemDir) {
        info.isSuspicious = true;
        info.suspiciousReason = TEXT("系统DLL从非系统目录加载");
        return;
    }

    // 2. 检查 DLL 名称中的可疑特征
    // 检查随机名称 (大量数字或无意义字符)
    int digitCount = 0;
    for (size_t i = 0; i < dllName.length(); i++) {
        if (_istdigit(dllName[i])) {
            digitCount++;
        }
    }
    if (dllName.length() > 8 && digitCount > (int)dllName.length() / 2) {
        info.isSuspicious = true;
        info.suspiciousReason = TEXT("DLL名称疑似随机生成");
        return;
    }

    // 3. 检查临时目录中的 DLL
    TCHAR tempPath[MAX_PATH];
    GetTempPath(MAX_PATH, tempPath);
    if (_tcsnicmp(info.path.c_str(), tempPath, _tcslen(tempPath)) == 0) {
        info.isSuspicious = true;
        info.suspiciousReason = TEXT("DLL位于临时目录");
        return;
    }

    // 4. 检查用户目录中的 DLL (针对系统进程)
    TCHAR userProfile[MAX_PATH];
    if (GetEnvironmentVariable(TEXT("USERPROFILE"), userProfile, MAX_PATH)) {
        if (_tcsnicmp(info.path.c_str(), userProfile, _tcslen(userProfile)) == 0) {
            // 检查是否为常见应用目录
            if (info.path.find(TEXT("AppData\\Local\\Microsoft")) == tstring::npos &&
                info.path.find(TEXT("AppData\\Local\\Programs")) == tstring::npos) {
                // 可能需要关注但不一定可疑
            }
        }
    }

    // 5. 检查无版本信息的 DLL
    if (info.version.empty() && info.description.empty() && info.company.empty()) {
        // 非系统目录且无版本信息
        if (!inSystemDir) {
            info.isSuspicious = true;
            info.suspiciousReason = TEXT("DLL has no version info");
            return;
        }
    }

    // 6. 检查已知的恶意 DLL 名称
    const TCHAR* maliciousDlls[] = {
        TEXT("inject.dll"),
        TEXT("hook.dll"),
        TEXT("payload.dll"),
        TEXT("shellcode.dll"),
        TEXT("beacon.dll"),
        TEXT("meterpreter"),
        NULL
    };

    tstring lowerName = dllName;
    for (auto& c : lowerName) c = _totlower(c);

    for (int i = 0; maliciousDlls[i] != NULL; i++) {
        tstring malName = maliciousDlls[i];
        for (auto& c : malName) c = _totlower(c);

        if (lowerName.find(malName) != tstring::npos) {
            info.isSuspicious = true;
            info.suspiciousReason = TEXT("可疑的DLL名称");
            return;
        }
    }
}

// ============================================================================
// 获取文件版本信息
// ============================================================================

bool DLLManager::GetFileVersionInfo(const tstring& path, tstring& version,
    tstring& description, tstring& company)
{
    DWORD dummy;
    DWORD size = ::GetFileVersionInfoSize(path.c_str(), &dummy);

    if (size == 0) {
        return false;
    }

    std::vector<BYTE> buffer(size);
    if (!::GetFileVersionInfo(path.c_str(), 0, size, buffer.data())) {
        return false;
    }

    // 获取语言和代码页
    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;

    UINT cbTranslate;
    if (!VerQueryValue(buffer.data(), TEXT("\\VarFileInfo\\Translation"),
        (LPVOID*)&lpTranslate, &cbTranslate)) {
        return false;
    }

    if (cbTranslate < sizeof(LANGANDCODEPAGE)) {
        return false;
    }

    // 构建查询字符串
    TCHAR subBlock[256];

    // 获取文件版本
    _stprintf_s(subBlock, TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"),
        lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

    TCHAR* pValue;
    UINT len;
    if (VerQueryValue(buffer.data(), subBlock, (LPVOID*)&pValue, &len)) {
        version = pValue;
    }

    // 获取文件描述
    _stprintf_s(subBlock, TEXT("\\StringFileInfo\\%04x%04x\\FileDescription"),
        lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

    if (VerQueryValue(buffer.data(), subBlock, (LPVOID*)&pValue, &len)) {
        description = pValue;
    }

    // 获取公司名称
    _stprintf_s(subBlock, TEXT("\\StringFileInfo\\%04x%04x\\CompanyName"),
        lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

    if (VerQueryValue(buffer.data(), subBlock, (LPVOID*)&pValue, &len)) {
        company = pValue;
    }

    return true;
}

// ============================================================================
// 检查数字签名 (简化版本)
// ============================================================================

bool DLLManager::IsFileSigned(const tstring& path)
{
    // 完整的签名验证需要 WinTrust API
    // 这里简化处理，仅检查是否有版本信息
    tstring ver, desc, comp;
    return GetFileVersionInfo(path, ver, desc, comp) && !comp.empty();
}

// ============================================================================
// 检查是否为已知系统 DLL
// ============================================================================

bool DLLManager::IsKnownSystemDll(const tstring& dllName)
{
    const TCHAR* systemDlls[] = {
        TEXT("ntdll.dll"),
        TEXT("kernel32.dll"),
        TEXT("kernelbase.dll"),
        TEXT("user32.dll"),
        TEXT("gdi32.dll"),
        TEXT("advapi32.dll"),
        TEXT("shell32.dll"),
        TEXT("ole32.dll"),
        TEXT("oleaut32.dll"),
        TEXT("msvcrt.dll"),
        TEXT("comctl32.dll"),
        TEXT("comdlg32.dll"),
        TEXT("ws2_32.dll"),
        TEXT("wsock32.dll"),
        TEXT("wininet.dll"),
        TEXT("urlmon.dll"),
        TEXT("crypt32.dll"),
        TEXT("secur32.dll"),
        TEXT("rpcrt4.dll"),
        TEXT("shlwapi.dll"),
        TEXT("version.dll"),
        TEXT("psapi.dll"),
        TEXT("iphlpapi.dll"),
        TEXT("dbghelp.dll"),
        NULL
    };

    for (int i = 0; systemDlls[i] != NULL; i++) {
        if (_tcsicmp(dllName.c_str(), systemDlls[i]) == 0) {
            return true;
        }
    }

    return false;
}
