// persistence_detector.cpp - 持久化检测器实现
#include "../include/persistence_detector.h"
#include <tchar.h>
#include <shlobj.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

PersistenceDetector::PersistenceDetector()
{
}

PersistenceDetector::~PersistenceDetector()
{
}

// ============================================================================
// 获取所有持久化项
// ============================================================================

std::vector<PersistenceItem> PersistenceDetector::GetAllPersistenceItems()
{
    std::vector<PersistenceItem> items;

    // 合并所有来源
    auto runKeys = GetRegistryRunKeys();
    items.insert(items.end(), runKeys.begin(), runKeys.end());

    auto services = GetServices();
    items.insert(items.end(), services.begin(), services.end());

    auto startupFolder = GetStartupFolder();
    items.insert(items.end(), startupFolder.begin(), startupFolder.end());

    auto winlogon = GetWinlogon();
    items.insert(items.end(), winlogon.begin(), winlogon.end());

    auto appInit = GetAppInit();
    items.insert(items.end(), appInit.begin(), appInit.end());

    auto ifeo = GetImageFileExecution();
    items.insert(items.end(), ifeo.begin(), ifeo.end());

    auto tasks = GetScheduledTasks();
    items.insert(items.end(), tasks.begin(), tasks.end());

    return items;
}

// ============================================================================
// 注册表 Run 键
// ============================================================================

std::vector<PersistenceItem> PersistenceDetector::GetRegistryRunKeys()
{
    std::vector<PersistenceItem> items;

    // 常见的 Run 键路径
    struct RegPath {
        HKEY hRoot;
        const TCHAR* subKey;
        const TCHAR* description;
    };

    RegPath paths[] = {
        { HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), TEXT("HKLM Run") },
        { HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), TEXT("HKLM RunOnce") },
        { HKEY_CURRENT_USER, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), TEXT("HKCU Run") },
        { HKEY_CURRENT_USER, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), TEXT("HKCU RunOnce") },
        { HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"), TEXT("HKLM Run (32-bit)") },
        { HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"), TEXT("HKLM RunServices") },
        { HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"), TEXT("HKLM RunServicesOnce") },
        { HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"), TEXT("HKLM Policy Run") },
        { HKEY_CURRENT_USER, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"), TEXT("HKCU Policy Run") },
    };

    for (const auto& path : paths) {
        ScanRegistryKey(path.hRoot, path.subKey, TEXT("注册表启动项"), items);
    }

    return items;
}

// ============================================================================
// 服务
// ============================================================================

std::vector<PersistenceItem> PersistenceDetector::GetServices()
{
    std::vector<PersistenceItem> items;

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        return items;
    }

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // 获取所需缓冲区大小
    EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned,
        &resumeHandle, NULL);

    if (bytesNeeded == 0) {
        CloseServiceHandle(hSCManager);
        return items;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    LPENUM_SERVICE_STATUS_PROCESS services = (LPENUM_SERVICE_STATUS_PROCESS)buffer.data();

    if (EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer.data(), bytesNeeded, &bytesNeeded,
        &servicesReturned, &resumeHandle, NULL)) {

        for (DWORD i = 0; i < servicesReturned; i++) {
            // 获取服务详细信息
            SC_HANDLE hService = OpenService(hSCManager, services[i].lpServiceName,
                SERVICE_QUERY_CONFIG);

            if (hService) {
                DWORD configSize = 0;
                QueryServiceConfig(hService, NULL, 0, &configSize);

                if (configSize > 0) {
                    std::vector<BYTE> configBuffer(configSize);
                    LPQUERY_SERVICE_CONFIG config = (LPQUERY_SERVICE_CONFIG)configBuffer.data();

                    if (QueryServiceConfig(hService, config, configSize, &configSize)) {
                        // 只关注自动启动的服务
                        if (config->dwStartType == SERVICE_AUTO_START ||
                            config->dwStartType == SERVICE_BOOT_START ||
                            config->dwStartType == SERVICE_SYSTEM_START) {

                            PersistenceItem item;
                            item.category = TEXT("服务");
                            item.name = services[i].lpServiceName;

                            if (services[i].lpDisplayName) {
                                item.description = services[i].lpDisplayName;
                            }

                            if (config->lpBinaryPathName) {
                                item.value = config->lpBinaryPathName;
                            }

                            item.location = TEXT("服务控制管理器");

                            AnalyzeSuspicious(item);
                            items.push_back(item);
                        }
                    }
                }

                CloseServiceHandle(hService);
            }
        }
    }

    CloseServiceHandle(hSCManager);
    return items;
}

// ============================================================================
// 启动文件夹
// ============================================================================

std::vector<PersistenceItem> PersistenceDetector::GetStartupFolder()
{
    std::vector<PersistenceItem> items;

    // 启动文件夹路径
    TCHAR startupPath[MAX_PATH];

    // 当前用户启动文件夹
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
        WIN32_FIND_DATA fd;
        tstring searchPath = tstring(startupPath) + TEXT("\\*");

        HANDLE hFind = FindFirstFile(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    PersistenceItem item;
                    item.category = TEXT("启动文件夹");
                    item.name = fd.cFileName;
                    item.value = tstring(startupPath) + TEXT("\\") + fd.cFileName;
                    item.location = TEXT("用户启动文件夹");

                    AnalyzeSuspicious(item);
                    items.push_back(item);
                }
            } while (FindNextFile(hFind, &fd));
            FindClose(hFind);
        }
    }

    // 公共启动文件夹
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_STARTUP, NULL, 0, startupPath))) {
        WIN32_FIND_DATA fd;
        tstring searchPath = tstring(startupPath) + TEXT("\\*");

        HANDLE hFind = FindFirstFile(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    PersistenceItem item;
                    item.category = TEXT("启动文件夹");
                    item.name = fd.cFileName;
                    item.value = tstring(startupPath) + TEXT("\\") + fd.cFileName;
                    item.location = TEXT("公共启动文件夹");

                    AnalyzeSuspicious(item);
                    items.push_back(item);
                }
            } while (FindNextFile(hFind, &fd));
            FindClose(hFind);
        }
    }

    return items;
}

// ============================================================================
// Winlogon
// ============================================================================

std::vector<PersistenceItem> PersistenceDetector::GetWinlogon()
{
    std::vector<PersistenceItem> items;

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        // Shell
        TCHAR value[MAX_PATH];
        DWORD valueSize = sizeof(value);
        if (RegQueryValueEx(hKey, TEXT("Shell"), NULL, NULL,
            (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {

            if (_tcsicmp(value, TEXT("explorer.exe")) != 0) {
                PersistenceItem item;
                item.category = TEXT("Winlogon");
                item.name = TEXT("Shell");
                item.value = value;
                item.location = TEXT("HKLM\\...\\Winlogon\\Shell");

                AnalyzeSuspicious(item);
                items.push_back(item);
            }
        }

        // Userinit
        valueSize = sizeof(value);
        if (RegQueryValueEx(hKey, TEXT("Userinit"), NULL, NULL,
            (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {

            tstring userinit = value;
            // 标准值应该是 "C:\Windows\system32\userinit.exe,"
            if (userinit.find(TEXT("userinit.exe")) == tstring::npos ||
                userinit.find(TEXT(",")) != userinit.length() - 1) {

                PersistenceItem item;
                item.category = TEXT("Winlogon");
                item.name = TEXT("Userinit");
                item.value = value;
                item.location = TEXT("HKLM\\...\\Winlogon\\Userinit");

                AnalyzeSuspicious(item);
                items.push_back(item);
            }
        }

        RegCloseKey(hKey);
    }

    return items;
}

// ============================================================================
// AppInit DLLs
// ============================================================================

std::vector<PersistenceItem> PersistenceDetector::GetAppInit()
{
    std::vector<PersistenceItem> items;

    const TCHAR* paths[] = {
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
        TEXT("SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows")
    };

    for (const auto& path : paths) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            TCHAR value[1024];
            DWORD valueSize = sizeof(value);

            if (RegQueryValueEx(hKey, TEXT("AppInit_DLLs"), NULL, NULL,
                (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {

                if (_tcslen(value) > 0) {
                    PersistenceItem item;
                    item.category = TEXT("AppInit DLLs");
                    item.name = TEXT("AppInit_DLLs");
                    item.value = value;
                    item.location = path;
                    item.isSuspicious = true;
                    item.suspiciousReason = TEXT("AppInit DLLs 常被恶意软件利用");

                    items.push_back(item);
                }
            }

            RegCloseKey(hKey);
        }
    }

    return items;
}

// ============================================================================
// Image File Execution Options (IFEO)
// ============================================================================

std::vector<PersistenceItem> PersistenceDetector::GetImageFileExecution()
{
    std::vector<PersistenceItem> items;

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        DWORD index = 0;
        TCHAR subKeyName[256];
        DWORD subKeyNameSize = 256;

        while (RegEnumKeyEx(hKey, index++, subKeyName, &subKeyNameSize,
            NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {

            HKEY hSubKey;
            if (RegOpenKeyEx(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                TCHAR debugger[MAX_PATH];
                DWORD debuggerSize = sizeof(debugger);

                if (RegQueryValueEx(hSubKey, TEXT("Debugger"), NULL, NULL,
                    (LPBYTE)debugger, &debuggerSize) == ERROR_SUCCESS) {

                    PersistenceItem item;
                    item.category = TEXT("IFEO Debugger");
                    item.name = subKeyName;
                    item.value = debugger;
                    item.location = TEXT("HKLM\\...\\Image File Execution Options");
                    item.isSuspicious = true;
                    item.suspiciousReason = TEXT("IFEO Debugger 可用于劫持程序执行");

                    items.push_back(item);
                }

                RegCloseKey(hSubKey);
            }

            subKeyNameSize = 256;
        }

        RegCloseKey(hKey);
    }

    return items;
}

// ============================================================================
// 计划任务 (简化版本 - 通过注册表)
// ============================================================================

std::vector<PersistenceItem> PersistenceDetector::GetScheduledTasks()
{
    std::vector<PersistenceItem> items;

    // 通过注册表读取计划任务缓存
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"),
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        DWORD index = 0;
        TCHAR subKeyName[256];
        DWORD subKeyNameSize = 256;

        while (RegEnumKeyEx(hKey, index++, subKeyName, &subKeyNameSize,
            NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {

            HKEY hSubKey;
            if (RegOpenKeyEx(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                TCHAR path[MAX_PATH];
                DWORD pathSize = sizeof(path);

                if (RegQueryValueEx(hSubKey, TEXT("Path"), NULL, NULL,
                    (LPBYTE)path, &pathSize) == ERROR_SUCCESS) {

                    PersistenceItem item;
                    item.category = TEXT("计划任务");
                    item.name = path;

                    // 尝试获取执行路径
                    BYTE actions[4096];
                    DWORD actionsSize = sizeof(actions);
                    if (RegQueryValueEx(hSubKey, TEXT("Actions"), NULL, NULL,
                        actions, &actionsSize) == ERROR_SUCCESS) {
                        // Actions 是二进制格式，简化处理
                        item.value = TEXT("(见任务计划程序)");
                    }

                    item.location = TEXT("任务计划程序");

                    AnalyzeSuspicious(item);
                    items.push_back(item);
                }

                RegCloseKey(hSubKey);
            }

            subKeyNameSize = 256;
        }

        RegCloseKey(hKey);
    }

    return items;
}

// ============================================================================
// 扫描注册表键
// ============================================================================

void PersistenceDetector::ScanRegistryKey(HKEY hRootKey, const tstring& subKey,
    const tstring& category, std::vector<PersistenceItem>& items)
{
    HKEY hKey;
    if (RegOpenKeyEx(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }

    tstring rootName = (hRootKey == HKEY_LOCAL_MACHINE) ? TEXT("HKLM") : TEXT("HKCU");
    tstring keyPath = rootName + TEXT("\\") + subKey;

    EnumRegistryValues(hKey, keyPath, category, items);

    RegCloseKey(hKey);
}

// ============================================================================
// 枚举注册表值
// ============================================================================

void PersistenceDetector::EnumRegistryValues(HKEY hKey, const tstring& keyPath,
    const tstring& category, std::vector<PersistenceItem>& items)
{
    DWORD index = 0;
    TCHAR valueName[256];
    DWORD valueNameSize = 256;
    BYTE valueData[2048];
    DWORD valueDataSize = sizeof(valueData);
    DWORD valueType;

    while (RegEnumValue(hKey, index++, valueName, &valueNameSize,
        NULL, &valueType, valueData, &valueDataSize) == ERROR_SUCCESS) {

        PersistenceItem item;
        item.category = category;
        item.name = valueName;
        item.location = keyPath;

        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
            item.value = (TCHAR*)valueData;
        } else if (valueType == REG_DWORD) {
            TCHAR buf[32];
            _stprintf_s(buf, TEXT("%u"), *(DWORD*)valueData);
            item.value = buf;
        }

        AnalyzeSuspicious(item);
        items.push_back(item);

        valueNameSize = 256;
        valueDataSize = sizeof(valueData);
    }
}

// ============================================================================
// 分析可疑性
// ============================================================================

void PersistenceDetector::AnalyzeSuspicious(PersistenceItem& item)
{
    item.isSuspicious = false;
    item.suspiciousReason.clear();

    if (item.value.empty()) {
        return;
    }

    // 提取可执行路径
    tstring exePath = ExtractExecutablePath(item.value);

    if (exePath.empty()) {
        return;
    }

    // 检查路径是否可疑
    if (IsPathSuspicious(exePath)) {
        item.isSuspicious = true;
        item.suspiciousReason = TEXT("可疑的执行路径");
        return;
    }

    // 检查文件是否存在
    if (!PathFileExists(exePath.c_str())) {
        // 可能使用了环境变量
        TCHAR expandedPath[MAX_PATH];
        if (ExpandEnvironmentStrings(exePath.c_str(), expandedPath, MAX_PATH)) {
            if (!PathFileExists(expandedPath)) {
                item.isSuspicious = true;
                item.suspiciousReason = TEXT("指向的文件不存在");
            }
        }
    }

    // 检查可疑的命令行参数
    tstring lowerValue = item.value;
    for (auto& c : lowerValue) c = _totlower(c);

    const TCHAR* suspiciousParams[] = {
        TEXT("-enc"), TEXT("-encodedcommand"),
        TEXT("-nop"), TEXT("-noprofile"),
        TEXT("-exec bypass"), TEXT("-executionpolicy bypass"),
        TEXT("hidden"), TEXT("-w hidden"),
        TEXT("downloadstring"), TEXT("downloadfile"),
        TEXT("invoke-expression"), TEXT("iex"),
        NULL
    };

    for (int i = 0; suspiciousParams[i] != NULL; i++) {
        if (lowerValue.find(suspiciousParams[i]) != tstring::npos) {
            item.isSuspicious = true;
            item.suspiciousReason = TEXT("包含可疑的命令行参数");
            return;
        }
    }
}

// ============================================================================
// 提取可执行路径
// ============================================================================

tstring PersistenceDetector::ExtractExecutablePath(const tstring& cmdLine)
{
    if (cmdLine.empty()) {
        return TEXT("");
    }

    tstring path;

    // 处理引号包围的路径
    if (cmdLine[0] == TEXT('"')) {
        size_t endQuote = cmdLine.find(TEXT('"'), 1);
        if (endQuote != tstring::npos) {
            path = cmdLine.substr(1, endQuote - 1);
        }
    } else {
        // 查找第一个空格或参数
        size_t spacePos = cmdLine.find(TEXT(' '));
        if (spacePos != tstring::npos) {
            path = cmdLine.substr(0, spacePos);
        } else {
            path = cmdLine;
        }
    }

    return path;
}

// ============================================================================
// 检查路径是否可疑
// ============================================================================

bool PersistenceDetector::IsPathSuspicious(const tstring& path)
{
    if (path.empty()) {
        return false;
    }

    // 展开环境变量
    TCHAR expandedPath[MAX_PATH];
    ExpandEnvironmentStrings(path.c_str(), expandedPath, MAX_PATH);

    tstring fullPath = expandedPath;

    // 转小写
    for (auto& c : fullPath) c = _totlower(c);

    // 检查临时目录
    TCHAR tempPath[MAX_PATH];
    GetTempPath(MAX_PATH, tempPath);
    tstring tempLower = tempPath;
    for (auto& c : tempLower) c = _totlower(c);

    if (fullPath.find(tempLower) == 0) {
        return true;
    }

    // 检查用户目录中的隐藏位置
    if (fullPath.find(TEXT("\\appdata\\")) != tstring::npos) {
        // AppData\Local\Temp
        if (fullPath.find(TEXT("\\temp\\")) != tstring::npos) {
            return true;
        }
        // 排除正常的应用目录
        if (fullPath.find(TEXT("\\microsoft\\")) == tstring::npos &&
            fullPath.find(TEXT("\\programs\\")) == tstring::npos) {
            // 可能需要关注
        }
    }

    // 检查公共目录
    if (fullPath.find(TEXT("\\public\\")) != tstring::npos) {
        return true;
    }

    // 检查回收站
    if (fullPath.find(TEXT("\\$recycle.bin\\")) != tstring::npos) {
        return true;
    }

    return false;
}

// ============================================================================
// 快照功能
// ============================================================================

void PersistenceDetector::TakeSnapshot()
{
    m_snapshot = GetAllPersistenceItems();
}

std::vector<PersistenceItem> PersistenceDetector::DetectChanges()
{
    std::vector<PersistenceItem> changes;
    std::vector<PersistenceItem> current = GetAllPersistenceItems();

    // 查找新增项
    for (const auto& item : current) {
        bool found = false;
        for (const auto& snapshotItem : m_snapshot) {
            if (item.category == snapshotItem.category &&
                item.name == snapshotItem.name &&
                item.value == snapshotItem.value) {
                found = true;
                break;
            }
        }

        if (!found) {
            PersistenceItem change = item;
            change.description = TEXT("[新增] ") + item.description;
            changes.push_back(change);
        }
    }

    // 查找删除项
    for (const auto& snapshotItem : m_snapshot) {
        bool found = false;
        for (const auto& item : current) {
            if (item.category == snapshotItem.category &&
                item.name == snapshotItem.name &&
                item.value == snapshotItem.value) {
                found = true;
                break;
            }
        }

        if (!found) {
            PersistenceItem change = snapshotItem;
            change.description = TEXT("[删除] ") + snapshotItem.description;
            changes.push_back(change);
        }
    }

    return changes;
}

// ============================================================================
// 获取可疑项
// ============================================================================

std::vector<PersistenceItem> PersistenceDetector::GetSuspiciousItems()
{
    std::vector<PersistenceItem> suspicious;
    std::vector<PersistenceItem> all = GetAllPersistenceItems();

    for (const auto& item : all) {
        if (item.isSuspicious) {
            suspicious.push_back(item);
        }
    }

    return suspicious;
}
