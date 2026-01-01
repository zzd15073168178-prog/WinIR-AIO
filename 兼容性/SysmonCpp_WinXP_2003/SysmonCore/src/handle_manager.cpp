// handle_manager.cpp - 句柄管理器实现
#include "../include/handle_manager.h"
#include <tchar.h>

#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define DUPLICATE_SAME_ACCESS 0x00000002

// ============================================================================
// 构造函数和析构函数
// ============================================================================

HandleManager::HandleManager()
    : m_pfnNtQuerySystemInformation(NULL)
    , m_pfnNtQueryObject(NULL)
    , m_pfnNtDuplicateObject(NULL)
{
    LoadAPIs();
}

HandleManager::~HandleManager()
{
}

// ============================================================================
// 加载 API
// ============================================================================

void HandleManager::LoadAPIs()
{
    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll) {
        m_pfnNtQuerySystemInformation = (PFN_NtQuerySystemInformation)
            GetProcAddress(hNtdll, "NtQuerySystemInformation");
        m_pfnNtQueryObject = (PFN_NtQueryObject)
            GetProcAddress(hNtdll, "NtQueryObject");
        m_pfnNtDuplicateObject = (PFN_NtDuplicateObject)
            GetProcAddress(hNtdll, "NtDuplicateObject");
    }
}

// ============================================================================
// 获取进程的所有句柄
// ============================================================================

std::vector<HandleInfo> HandleManager::GetProcessHandles(DWORD pid)
{
    std::vector<HandleInfo> handles;

    if (!m_pfnNtQuerySystemInformation) {
        return handles;
    }

    // 分配初始缓冲区
    ULONG bufferSize = 1024 * 1024; // 1MB
    PVOID buffer = malloc(bufferSize);

    if (!buffer) {
        return handles;
    }

    NTSTATUS status;
    ULONG returnLength;

    // 循环直到缓冲区足够大
    while ((status = m_pfnNtQuerySystemInformation(
        SystemHandleInformation,
        buffer,
        bufferSize,
        &returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {

        free(buffer);
        bufferSize *= 2;

        if (bufferSize > 256 * 1024 * 1024) { // 最大 256MB
            return handles;
        }

        buffer = malloc(bufferSize);
        if (!buffer) {
            return handles;
        }
    }

    if (status != STATUS_SUCCESS) {
        free(buffer);
        return handles;
    }

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;

    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO& entry = handleInfo->Handles[i];

        // 只处理指定进程的句柄
        if (entry.UniqueProcessId != pid) {
            continue;
        }

        HandleInfo info;
        info.handleValue = (HANDLE)(ULONG_PTR)entry.HandleValue;
        info.pid = pid;

        // 获取类型名称
        if (hProcess) {
            info.type = GetObjectTypeName(hProcess, info.handleValue, entry.ObjectTypeIndex);

            // 获取对象名称 (跳过某些类型以避免死锁)
            if (info.type != TEXT("Thread") &&
                info.type != TEXT("Process") &&
                info.type != TEXT("EtwRegistration") &&
                info.type != TEXT("ALPC Port")) {
                info.name = GetObjectName(hProcess, info.handleValue);
            }
        } else {
            // 使用缓存的类型名称
            auto it = m_objectTypeCache.find(entry.ObjectTypeIndex);
            if (it != m_objectTypeCache.end()) {
                info.type = it->second;
            } else {
                TCHAR typeBuf[32];
                _stprintf_s(typeBuf, TEXT("Type_%d"), entry.ObjectTypeIndex);
                info.type = typeBuf;
            }
        }

        handles.push_back(info);
    }

    if (hProcess) {
        CloseHandle(hProcess);
    }

    free(buffer);
    return handles;
}

// ============================================================================
// 按类型过滤句柄
// ============================================================================

std::vector<HandleInfo> HandleManager::GetHandlesByType(DWORD pid, const tstring& type)
{
    std::vector<HandleInfo> result;
    std::vector<HandleInfo> allHandles = GetProcessHandles(pid);

    for (const auto& h : allHandles) {
        if (_tcsicmp(h.type.c_str(), type.c_str()) == 0) {
            result.push_back(h);
        }
    }

    return result;
}

// ============================================================================
// 获取系统中所有句柄
// ============================================================================

std::vector<HandleInfo> HandleManager::GetAllHandles()
{
    std::vector<HandleInfo> handles;

    if (!m_pfnNtQuerySystemInformation) {
        return handles;
    }

    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = malloc(bufferSize);

    if (!buffer) {
        return handles;
    }

    NTSTATUS status;
    ULONG returnLength;

    while ((status = m_pfnNtQuerySystemInformation(
        SystemHandleInformation,
        buffer,
        bufferSize,
        &returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {

        free(buffer);
        bufferSize *= 2;

        if (bufferSize > 256 * 1024 * 1024) {
            return handles;
        }

        buffer = malloc(bufferSize);
        if (!buffer) {
            return handles;
        }
    }

    if (status != STATUS_SUCCESS) {
        free(buffer);
        return handles;
    }

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;

    // 统计每个进程的句柄数
    std::map<DWORD, int> processHandleCount;

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO& entry = handleInfo->Handles[i];

        HandleInfo info;
        info.handleValue = (HANDLE)(ULONG_PTR)entry.HandleValue;
        info.pid = entry.UniqueProcessId;

        // 使用缓存的类型名称
        auto it = m_objectTypeCache.find(entry.ObjectTypeIndex);
        if (it != m_objectTypeCache.end()) {
            info.type = it->second;
        } else {
            TCHAR typeBuf[32];
            _stprintf_s(typeBuf, TEXT("Type_%d"), entry.ObjectTypeIndex);
            info.type = typeBuf;
        }

        handles.push_back(info);
    }

    free(buffer);
    return handles;
}

// ============================================================================
// 获取对象类型名称
// ============================================================================

tstring HandleManager::GetObjectTypeName(HANDLE hProcess, HANDLE hObject, UCHAR typeIndex)
{
    // 检查缓存
    auto it = m_objectTypeCache.find(typeIndex);
    if (it != m_objectTypeCache.end()) {
        return it->second;
    }

    if (!m_pfnNtQueryObject || !m_pfnNtDuplicateObject) {
        return TEXT("");
    }

    // 复制句柄到当前进程
    HANDLE hDup = NULL;
    NTSTATUS status = m_pfnNtDuplicateObject(
        hProcess,
        hObject,
        GetCurrentProcess(),
        &hDup,
        0,
        0,
        DUPLICATE_SAME_ACCESS);

    if (status != STATUS_SUCCESS || !hDup) {
        return TEXT("");
    }

    // 查询对象类型
    BYTE buffer[1024];
    ULONG returnLength;

    status = m_pfnNtQueryObject(
        hDup,
        ObjectTypeInformation,
        buffer,
        sizeof(buffer),
        &returnLength);

    CloseHandle(hDup);

    if (status != STATUS_SUCCESS) {
        return TEXT("");
    }

    POBJECT_TYPE_INFORMATION typeInfo = (POBJECT_TYPE_INFORMATION)buffer;

    tstring typeName;
#ifdef UNICODE
    if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0) {
        typeName = tstring(typeInfo->TypeName.Buffer,
            typeInfo->TypeName.Length / sizeof(WCHAR));
    }
#else
    if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0) {
        int len = WideCharToMultiByte(CP_ACP, 0,
            typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR),
            NULL, 0, NULL, NULL);
        if (len > 0) {
            typeName.resize(len);
            WideCharToMultiByte(CP_ACP, 0,
                typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR),
                &typeName[0], len, NULL, NULL);
        }
    }
#endif

    // 缓存结果
    if (!typeName.empty()) {
        m_objectTypeCache[typeIndex] = typeName;
    }

    return typeName;
}

// ============================================================================
// 获取对象名称
// ============================================================================

tstring HandleManager::GetObjectName(HANDLE hProcess, HANDLE hObject)
{
    if (!m_pfnNtQueryObject || !m_pfnNtDuplicateObject) {
        return TEXT("");
    }

    // 复制句柄到当前进程
    HANDLE hDup = NULL;
    NTSTATUS status = m_pfnNtDuplicateObject(
        hProcess,
        hObject,
        GetCurrentProcess(),
        &hDup,
        0,
        0,
        DUPLICATE_SAME_ACCESS);

    if (status != STATUS_SUCCESS || !hDup) {
        return TEXT("");
    }

    // 查询对象名称
    BYTE buffer[2048];
    ULONG returnLength;

    // 使用超时机制避免死锁 (某些句柄查询会阻塞)
    // 简化处理：直接查询
    status = m_pfnNtQueryObject(
        hDup,
        ObjectNameInformation,
        buffer,
        sizeof(buffer),
        &returnLength);

    CloseHandle(hDup);

    if (status != STATUS_SUCCESS) {
        return TEXT("");
    }

    PUNICODE_STRING nameInfo = (PUNICODE_STRING)buffer;

    tstring name;
#ifdef UNICODE
    if (nameInfo->Buffer && nameInfo->Length > 0) {
        name = tstring(nameInfo->Buffer, nameInfo->Length / sizeof(WCHAR));
    }
#else
    if (nameInfo->Buffer && nameInfo->Length > 0) {
        int len = WideCharToMultiByte(CP_ACP, 0,
            nameInfo->Buffer, nameInfo->Length / sizeof(WCHAR),
            NULL, 0, NULL, NULL);
        if (len > 0) {
            name.resize(len);
            WideCharToMultiByte(CP_ACP, 0,
                nameInfo->Buffer, nameInfo->Length / sizeof(WCHAR),
                &name[0], len, NULL, NULL);
        }
    }
#endif

    return name;
}

// ============================================================================
// 关闭远程句柄
// ============================================================================

bool HandleManager::CloseRemoteHandle(DWORD pid, HANDLE handle, tstring& errorMsg)
{
    if (!m_pfnNtDuplicateObject) {
        errorMsg = TEXT("API 不可用");
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hProcess) {
        errorMsg = TEXT("无法打开目标进程: ") + GetLastErrorString();
        return false;
    }

    // 使用 DUPLICATE_CLOSE_SOURCE 关闭源句柄
    NTSTATUS status = m_pfnNtDuplicateObject(
        hProcess,
        handle,
        NULL,
        NULL,
        0,
        0,
        1 /* DUPLICATE_CLOSE_SOURCE */);

    CloseHandle(hProcess);

    if (status != STATUS_SUCCESS) {
        errorMsg = TEXT("关闭句柄失败");
        return false;
    }

    return true;
}
