// common.h - 公共类型定义和常量
#pragma once

#include "targetver.h"

// winsock2.h 必须在 windows.h 之前包含
#ifndef _WINSOCKAPI_
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <windows.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <map>
#include <strsafe.h>

// ============================================================================
// 字符串类型定义
// ============================================================================

#ifdef UNICODE
typedef std::wstring tstring;
#define to_tstring std::to_wstring
#else
typedef std::string tstring;
#define to_tstring std::to_string
#endif

// ============================================================================
// 进程相关结构体
// ============================================================================

struct ProcessInfo {
    DWORD       pid;                    // 进程 ID
    DWORD       ppid;                   // 父进程 ID
    tstring     name;                   // 进程名称
    tstring     exePath;                // 可执行文件完整路径
    double      cpuPercent;             // CPU 使用率 (%)
    SIZE_T      memoryKB;               // 内存使用 (KB)
    SIZE_T      workingSetKB;           // 工作集 (KB)
    tstring     status;                 // 状态 (运行/挂起)
    tstring     username;               // 所属用户
    DWORD       threadCount;            // 线程数
    DWORD       handleCount;            // 句柄数
    tstring     commandLine;            // 命令行参数
    FILETIME    createTime;             // 创建时间
    DWORD       priority;               // 优先级
    bool        isSuspicious;           // 是否可疑
    tstring     suspiciousReason;       // 可疑原因
};

// 进程树节点
struct ProcessTreeNode {
    ProcessInfo info;
    std::vector<DWORD> children;        // 子进程 PID 列表
};

// ============================================================================
// 网络相关结构体
// ============================================================================

struct NetworkConnection {
    tstring     protocol;               // TCP / UDP
    tstring     localAddr;              // 本地地址
    WORD        localPort;              // 本地端口
    tstring     remoteAddr;             // 远程地址
    WORD        remotePort;             // 远程端口
    tstring     state;                  // 连接状态
    DWORD       pid;                    // 关联进程 PID
    tstring     processName;            // 进程名称
    bool        isSuspicious;           // 是否可疑
    tstring     suspiciousReason;       // 可疑原因
    tstring     location;               // IP 地理位置 (可选)
};

// ============================================================================
// DLL 相关结构体
// ============================================================================

struct DllInfo {
    tstring     path;                   // DLL 完整路径
    PVOID       baseAddr;               // 基地址
    SIZE_T      size;                   // 大小
    tstring     version;                // 版本信息
    tstring     description;            // 描述
    tstring     company;                // 公司
    bool        isSigned;               // 是否签名
    bool        isSuspicious;           // 是否可疑
    tstring     suspiciousReason;       // 可疑原因
};

// ============================================================================
// 句柄相关结构体
// ============================================================================

struct HandleInfo {
    HANDLE      handleValue;            // 句柄值
    tstring     type;                   // 类型 (File, Key, Process, etc.)
    tstring     name;                   // 名称/路径
    DWORD       pid;                    // 所属进程
};

// ============================================================================
// 内存扫描相关结构体
// ============================================================================

struct MemoryScanResult {
    DWORD       pid;                    // 进程 PID
    tstring     processName;            // 进程名称
    PVOID       address;                // 内存地址
    SIZE_T      regionSize;             // 区域大小
    tstring     pattern;                // 匹配的模式
    tstring     matchedContent;         // 匹配的内容 (截断)
    tstring     category;               // 分类 (IP/URL/CMD/Credential等)
    tstring     riskLevel;              // 风险级别
};

// ============================================================================
// 持久化检测相关结构体
// ============================================================================

struct PersistenceItem {
    tstring     category;               // 类别 (注册表/服务/计划任务/启动文件夹)
    tstring     name;                   // 名称
    tstring     value;                  // 值/路径
    tstring     location;               // 位置 (注册表路径等)
    tstring     description;            // 描述
    bool        isSuspicious;           // 是否可疑
    tstring     suspiciousReason;       // 可疑原因
};

// ============================================================================
// 事件日志相关结构体
// ============================================================================

struct EventLogEntry {
    DWORD       eventId;                // 事件 ID
    tstring     source;                 // 来源
    tstring     level;                  // 级别 (信息/警告/错误)
    FILETIME    timeGenerated;          // 生成时间
    tstring     message;                // 消息内容
    tstring     category;               // 分类
    tstring     computer;               // 计算机名
    tstring     username;               // 用户名
};

// ============================================================================
// 哈希计算相关结构体
// ============================================================================

struct FileHashResult {
    tstring     filePath;               // 文件路径
    tstring     md5;                    // MD5
    tstring     sha1;                   // SHA1
    tstring     sha256;                 // SHA256
    ULONGLONG   fileSize;               // 文件大小
    tstring     error;                  // 错误信息 (如有)
};

// ============================================================================
// 可疑特征常量
// ============================================================================

namespace SuspiciousIndicators {
    // 可疑端口列表 - 使用 inline 避免重复定义
    inline const WORD* GetSuspiciousPorts() {
        static const WORD ports[] = {
            4444, 4445, 5555, 6666, 7777, 8888, 9999,    // 常见后门端口
            1234, 12345, 31337,                          // 木马端口
            6667, 6668, 6669,                            // IRC (C2通信)
            3389,                                        // RDP (异常外连时可疑)
            445, 139,                                    // SMB (异常外连时可疑)
            0
        };
        return ports;
    }

    // 可疑进程名
    inline const TCHAR** GetSuspiciousProcesses() {
        static const TCHAR* processes[] = {
            TEXT("cmd.exe"),
            TEXT("powershell.exe"),
            TEXT("pwsh.exe"),
            TEXT("wscript.exe"),
            TEXT("cscript.exe"),
            TEXT("mshta.exe"),
            TEXT("regsvr32.exe"),
            TEXT("rundll32.exe"),
            TEXT("certutil.exe"),
            TEXT("bitsadmin.exe"),
            TEXT("msiexec.exe"),
            TEXT("nc.exe"),
            TEXT("ncat.exe"),
            TEXT("psexec.exe"),
            TEXT("mimikatz.exe"),
            NULL
        };
        return processes;
    }

    // 系统进程名 (不应被标记为可疑)
    inline const TCHAR** GetSystemProcesses() {
        static const TCHAR* processes[] = {
            TEXT("System"),
            TEXT("smss.exe"),
            TEXT("csrss.exe"),
            TEXT("wininit.exe"),
            TEXT("winlogon.exe"),
            TEXT("services.exe"),
            TEXT("lsass.exe"),
            TEXT("svchost.exe"),
            TEXT("explorer.exe"),
            TEXT("dwm.exe"),
            TEXT("taskhostw.exe"),
            TEXT("RuntimeBroker.exe"),
            NULL
        };
        return processes;
    }

    // 系统目录列表
    inline const TCHAR** GetSystemDirectories() {
        static const TCHAR* dirs[] = {
            TEXT("C:\\Windows\\System32"),
            TEXT("C:\\Windows\\SysWOW64"),
            TEXT("C:\\Windows"),
            TEXT("C:\\Program Files"),
            TEXT("C:\\Program Files (x86)"),
            NULL
        };
        return dirs;
    }
}

// ============================================================================
// 错误处理
// ============================================================================

// 获取 Windows 错误信息
inline tstring GetLastErrorString() {
    DWORD error = GetLastError();
    if (error == 0) return TEXT("");

    LPTSTR buffer = NULL;
    DWORD size = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&buffer, 0, NULL);

    tstring message;
    if (buffer) {
        message = buffer;
        LocalFree(buffer);
        // 移除末尾换行
        while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
            message.pop_back();
        }
    }
    return message;
}

// ============================================================================
// 工具函数
// ============================================================================

namespace Utils {
    // 检查是否为可疑端口
    inline bool IsSuspiciousPort(WORD port) {
        const WORD* ports = SuspiciousIndicators::GetSuspiciousPorts();
        for (int i = 0; ports[i] != 0; i++) {
            if (port == ports[i]) {
                return true;
            }
        }
        return false;
    }

    // 检查是否为可疑进程名
    inline bool IsSuspiciousProcessName(const tstring& name) {
        const TCHAR** processes = SuspiciousIndicators::GetSuspiciousProcesses();
        for (int i = 0; processes[i] != NULL; i++) {
            if (_tcsicmp(name.c_str(), processes[i]) == 0) {
                return true;
            }
        }
        return false;
    }

    // 检查是否为系统进程
    inline bool IsSystemProcess(const tstring& name) {
        const TCHAR** processes = SuspiciousIndicators::GetSystemProcesses();
        for (int i = 0; processes[i] != NULL; i++) {
            if (_tcsicmp(name.c_str(), processes[i]) == 0) {
                return true;
            }
        }
        return false;
    }

    // 检查路径是否在系统目录下
    inline bool IsInSystemDirectory(const tstring& path) {
        const TCHAR** dirs = SuspiciousIndicators::GetSystemDirectories();
        for (int i = 0; dirs[i] != NULL; i++) {
            if (_tcsnicmp(path.c_str(), dirs[i], _tcslen(dirs[i])) == 0) {
                return true;
            }
        }
        return false;
    }

    // FILETIME 转字符串
    inline tstring FileTimeToString(const FILETIME& ft) {
        SYSTEMTIME st;
        FILETIME localFt;
        FileTimeToLocalFileTime(&ft, &localFt);
        FileTimeToSystemTime(&localFt, &st);

        TCHAR buffer[64];
        _stprintf_s(buffer, TEXT("%04d-%02d-%02d %02d:%02d:%02d"),
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
        return buffer;
    }

    // 字节大小格式化
    inline tstring FormatSize(ULONGLONG bytes) {
        TCHAR buffer[64];
        if (bytes < 1024) {
            _stprintf_s(buffer, TEXT("%llu B"), bytes);
        } else if (bytes < 1024 * 1024) {
            _stprintf_s(buffer, TEXT("%.2f KB"), bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            _stprintf_s(buffer, TEXT("%.2f MB"), bytes / (1024.0 * 1024));
        } else {
            _stprintf_s(buffer, TEXT("%.2f GB"), bytes / (1024.0 * 1024 * 1024));
        }
        return buffer;
    }

    // IP 地址转字符串
    inline tstring IpToString(DWORD ip) {
        TCHAR buffer[32];
        _stprintf_s(buffer, TEXT("%u.%u.%u.%u"),
            (ip >> 0) & 0xFF,
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF);
        return buffer;
    }
}
