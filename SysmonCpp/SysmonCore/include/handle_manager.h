// handle_manager.h - 句柄管理器
#pragma once

#include "common.h"

// NTSTATUS 类型定义
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// UNICODE_STRING 结构体
#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

// SystemHandleInformation 常量
#define SystemHandleInformation 16

// 未文档化的结构体定义
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// 对象类型信息
typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22];
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

// NtQueryObject 的信息类
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

class HandleManager {
public:
    HandleManager();
    ~HandleManager();

    // 获取进程的所有句柄
    std::vector<HandleInfo> GetProcessHandles(DWORD pid);

    // 按类型过滤句柄
    std::vector<HandleInfo> GetHandlesByType(DWORD pid, const tstring& type);

    // 获取系统中所有句柄
    std::vector<HandleInfo> GetAllHandles();

    // 关闭句柄 (危险操作)
    bool CloseRemoteHandle(DWORD pid, HANDLE handle, tstring& errorMsg);

private:
    // NtQuerySystemInformation 函数指针
    typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

    typedef NTSTATUS(NTAPI* PFN_NtQueryObject)(
        HANDLE Handle,
        OBJECT_INFORMATION_CLASS ObjectInformationClass,
        PVOID ObjectInformation,
        ULONG ObjectInformationLength,
        PULONG ReturnLength);

    typedef NTSTATUS(NTAPI* PFN_NtDuplicateObject)(
        HANDLE SourceProcessHandle,
        HANDLE SourceHandle,
        HANDLE TargetProcessHandle,
        PHANDLE TargetHandle,
        ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Options);

    PFN_NtQuerySystemInformation m_pfnNtQuerySystemInformation;
    PFN_NtQueryObject m_pfnNtQueryObject;
    PFN_NtDuplicateObject m_pfnNtDuplicateObject;

    // 对象类型缓存
    std::map<UCHAR, tstring> m_objectTypeCache;

    // 获取对象类型名称
    tstring GetObjectTypeName(HANDLE hProcess, HANDLE hObject, UCHAR typeIndex);

    // 获取对象名称
    tstring GetObjectName(HANDLE hProcess, HANDLE hObject);

    // 加载 API
    void LoadAPIs();
};
