// eventlog_manager.cpp - 事件日志管理器实现
#include "../include/eventlog_manager.h"
#include <tchar.h>
#include <time.h>

#pragma comment(lib, "advapi32.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

EventLogManager::EventLogManager()
{
}

EventLogManager::~EventLogManager()
{
}

// ============================================================================
// 查询安全日志
// ============================================================================

std::vector<EventLogEntry> EventLogManager::QuerySecurityLog(DWORD hours, DWORD maxEvents)
{
    return QueryEventLogLegacy(TEXT("Security"), hours, maxEvents);
}

// ============================================================================
// 查询系统日志
// ============================================================================

std::vector<EventLogEntry> EventLogManager::QuerySystemLog(DWORD hours, DWORD maxEvents)
{
    return QueryEventLogLegacy(TEXT("System"), hours, maxEvents);
}

// ============================================================================
// 查询应用程序日志
// ============================================================================

std::vector<EventLogEntry> EventLogManager::QueryApplicationLog(DWORD hours, DWORD maxEvents)
{
    return QueryEventLogLegacy(TEXT("Application"), hours, maxEvents);
}

// ============================================================================
// 按事件 ID 过滤
// ============================================================================

std::vector<EventLogEntry> EventLogManager::QueryByEventId(const tstring& logName,
    DWORD eventId, DWORD hours, DWORD maxEvents)
{
    return QueryEventLogLegacy(logName, hours, maxEvents, eventId);
}

// ============================================================================
// 使用旧的 Event Log API (XP/2003 兼容)
// ============================================================================

std::vector<EventLogEntry> EventLogManager::QueryEventLogLegacy(const tstring& logName,
    DWORD hours, DWORD maxEvents, DWORD filterEventId)
{
    std::vector<EventLogEntry> events;

    // 打开事件日志
    HANDLE hEventLog = OpenEventLog(NULL, logName.c_str());
    if (!hEventLog) {
        return events;
    }

    // 分配缓冲区
    const DWORD BUFFER_SIZE = 64 * 1024; // 64KB
    BYTE* buffer = new BYTE[BUFFER_SIZE];

    DWORD bytesRead;
    DWORD minBytesNeeded;
    DWORD flags = EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ;

    while (events.size() < maxEvents) {
        if (!ReadEventLog(hEventLog, flags, 0, buffer, BUFFER_SIZE,
            &bytesRead, &minBytesNeeded)) {

            DWORD error = GetLastError();
            if (error == ERROR_HANDLE_EOF) {
                break; // 没有更多事件
            }
            break;
        }

        // 解析缓冲区中的事件
        EVENTLOGRECORD* pRecord = (EVENTLOGRECORD*)buffer;

        while ((BYTE*)pRecord < buffer + bytesRead) {
            // 检查时间范围
            if (!IsWithinTimeRange(pRecord->TimeGenerated, hours)) {
                // 因为是倒序读取，一旦超出时间范围就可以停止
                goto done;
            }

            // 检查事件 ID 过滤
            if (filterEventId == 0 || (pRecord->EventID & 0xFFFF) == filterEventId) {
                EventLogEntry entry = ParseEventRecord(pRecord, logName);
                events.push_back(entry);

                if (events.size() >= maxEvents) {
                    goto done;
                }
            }

            // 移动到下一条记录
            pRecord = (EVENTLOGRECORD*)((BYTE*)pRecord + pRecord->Length);
        }
    }

done:
    delete[] buffer;
    CloseEventLog(hEventLog);

    return events;
}

// ============================================================================
// 解析事件记录
// ============================================================================

EventLogEntry EventLogManager::ParseEventRecord(EVENTLOGRECORD* pRecord, const tstring& logName)
{
    EventLogEntry entry;

    entry.eventId = pRecord->EventID & 0xFFFF;
    entry.level = EventTypeToString(pRecord->EventType);

    // 时间
    entry.timeGenerated.dwLowDateTime = pRecord->TimeGenerated;
    entry.timeGenerated.dwHighDateTime = 0;

    // 转换 Unix 时间到 FILETIME
    ULONGLONG unixTime = (ULONGLONG)pRecord->TimeGenerated;
    ULONGLONG fileTime = (unixTime + 11644473600ULL) * 10000000ULL;
    entry.timeGenerated.dwLowDateTime = (DWORD)fileTime;
    entry.timeGenerated.dwHighDateTime = (DWORD)(fileTime >> 32);

    // 来源
    LPCTSTR sourceName = (LPCTSTR)((BYTE*)pRecord + sizeof(EVENTLOGRECORD));
    entry.source = sourceName;

    // 计算机名
    LPCTSTR computerName = sourceName + _tcslen(sourceName) + 1;
    entry.computer = computerName;

    // 用户 SID (如果有)
    if (pRecord->UserSidOffset > 0 && pRecord->UserSidLength > 0) {
        PSID pSid = (PSID)((BYTE*)pRecord + pRecord->UserSidOffset);

        TCHAR userName[256] = { 0 };
        TCHAR domainName[256] = { 0 };
        DWORD userNameSize = 256;
        DWORD domainNameSize = 256;
        SID_NAME_USE sidType;

        if (LookupAccountSid(NULL, pSid, userName, &userNameSize,
            domainName, &domainNameSize, &sidType)) {
            if (domainName[0] != 0) {
                entry.username = domainName;
                entry.username += TEXT("\\");
            }
            entry.username += userName;
        }
    }

    // 字符串数据
    if (pRecord->NumStrings > 0 && pRecord->StringOffset > 0) {
        LPCTSTR strings = (LPCTSTR)((BYTE*)pRecord + pRecord->StringOffset);
        std::vector<LPCTSTR> stringArray;

        for (WORD i = 0; i < pRecord->NumStrings; i++) {
            stringArray.push_back(strings);
            strings += _tcslen(strings) + 1;
        }

        // 尝试获取格式化的消息
        entry.message = GetEventMessage(sourceName, pRecord->EventID,
            stringArray.data(), (DWORD)stringArray.size());

        // 如果获取消息失败，使用原始字符串
        if (entry.message.empty() && !stringArray.empty()) {
            for (size_t i = 0; i < stringArray.size(); i++) {
                if (i > 0) entry.message += TEXT(" | ");
                entry.message += stringArray[i];
            }
        }
    }

    entry.category = logName;

    return entry;
}

// ============================================================================
// 获取事件消息
// ============================================================================

tstring EventLogManager::GetEventMessage(const tstring& sourceName, DWORD eventId,
    LPCTSTR* strings, DWORD numStrings)
{
    tstring message;

    // 查找消息文件路径
    tstring regPath = TEXT("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security\\");
    regPath += sourceName;

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        // 尝试 System 日志
        regPath = TEXT("SYSTEM\\CurrentControlSet\\Services\\EventLog\\System\\");
        regPath += sourceName;

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return message;
        }
    }

    TCHAR eventMessageFile[MAX_PATH * 2];
    DWORD size = sizeof(eventMessageFile);

    if (RegQueryValueEx(hKey, TEXT("EventMessageFile"), NULL, NULL,
        (LPBYTE)eventMessageFile, &size) == ERROR_SUCCESS) {

        // 展开环境变量
        TCHAR expandedPath[MAX_PATH * 2];
        ExpandEnvironmentStrings(eventMessageFile, expandedPath, MAX_PATH * 2);

        // 可能有多个文件路径，用分号分隔
        TCHAR* context = NULL;
        TCHAR* token = _tcstok_s(expandedPath, TEXT(";"), &context);

        while (token) {
            HMODULE hModule = LoadLibraryEx(token, NULL,
                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);

            if (hModule) {
                TCHAR* msgBuffer = NULL;

                DWORD result = FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_HMODULE |
                    FORMAT_MESSAGE_ARGUMENT_ARRAY,
                    hModule,
                    eventId,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPTSTR)&msgBuffer,
                    0,
                    (va_list*)strings);

                if (result > 0 && msgBuffer) {
                    message = msgBuffer;
                    LocalFree(msgBuffer);

                    // 移除末尾换行
                    while (!message.empty() &&
                        (message.back() == '\n' || message.back() == '\r')) {
                        message.pop_back();
                    }
                }

                FreeLibrary(hModule);

                if (!message.empty()) {
                    break;
                }
            }

            token = _tcstok_s(NULL, TEXT(";"), &context);
        }
    }

    RegCloseKey(hKey);
    return message;
}

// ============================================================================
// 事件级别转字符串
// ============================================================================

tstring EventLogManager::EventTypeToString(WORD eventType)
{
    switch (eventType) {
    case EVENTLOG_ERROR_TYPE:
        return TEXT("错误");
    case EVENTLOG_WARNING_TYPE:
        return TEXT("警告");
    case EVENTLOG_INFORMATION_TYPE:
        return TEXT("信息");
    case EVENTLOG_AUDIT_SUCCESS:
        return TEXT("审核成功");
    case EVENTLOG_AUDIT_FAILURE:
        return TEXT("审核失败");
    default:
        return TEXT("未知");
    }
}

// ============================================================================
// 检查时间范围
// ============================================================================

bool EventLogManager::IsWithinTimeRange(DWORD eventTime, DWORD hours)
{
    time_t now = time(NULL);
    time_t cutoff = now - (hours * 3600);
    return (time_t)eventTime >= cutoff;
}

// ============================================================================
// 获取登录事件
// ============================================================================

std::vector<EventLogEntry> EventLogManager::GetLoginEvents(DWORD hours)
{
    std::vector<EventLogEntry> allEvents;

    // 4624 - 登录成功
    auto success = QueryByEventId(TEXT("Security"), 4624, hours, 500);
    allEvents.insert(allEvents.end(), success.begin(), success.end());

    // 4625 - 登录失败
    auto failure = QueryByEventId(TEXT("Security"), 4625, hours, 500);
    allEvents.insert(allEvents.end(), failure.begin(), failure.end());

    return allEvents;
}

// ============================================================================
// 获取进程创建事件
// ============================================================================

std::vector<EventLogEntry> EventLogManager::GetProcessCreationEvents(DWORD hours)
{
    return QueryByEventId(TEXT("Security"), 4688, hours, 1000);
}

// ============================================================================
// 获取服务安装事件
// ============================================================================

std::vector<EventLogEntry> EventLogManager::GetServiceInstallEvents(DWORD hours)
{
    return QueryByEventId(TEXT("System"), 7045, hours, 500);
}

// ============================================================================
// 获取可疑事件
// ============================================================================

std::vector<EventLogEntry> EventLogManager::GetSuspiciousEvents(DWORD hours)
{
    std::vector<EventLogEntry> suspicious;

    // 可疑的事件 ID
    struct SuspiciousEvent {
        const TCHAR* logName;
        DWORD eventId;
        const TCHAR* description;
    };

    SuspiciousEvent suspiciousIds[] = {
        // 安全日志
        { TEXT("Security"), 4625, TEXT("登录失败") },
        { TEXT("Security"), 4648, TEXT("使用显式凭据登录") },
        { TEXT("Security"), 4672, TEXT("特权登录") },
        { TEXT("Security"), 4697, TEXT("服务安装") },
        { TEXT("Security"), 4698, TEXT("计划任务创建") },
        { TEXT("Security"), 4699, TEXT("计划任务删除") },
        { TEXT("Security"), 4720, TEXT("用户账户创建") },
        { TEXT("Security"), 4724, TEXT("密码重置") },
        { TEXT("Security"), 4728, TEXT("添加到全局组") },
        { TEXT("Security"), 4732, TEXT("添加到本地组") },
        { TEXT("Security"), 4756, TEXT("添加到通用组") },
        { TEXT("Security"), 1102, TEXT("审核日志清除") },

        // 系统日志
        { TEXT("System"), 7034, TEXT("服务意外终止") },
        { TEXT("System"), 7035, TEXT("服务控制") },
        { TEXT("System"), 7036, TEXT("服务状态变化") },
        { TEXT("System"), 7040, TEXT("服务启动类型变化") },
        { TEXT("System"), 7045, TEXT("新服务安装") },

        // 结束标记
        { NULL, 0, NULL }
    };

    for (int i = 0; suspiciousIds[i].logName != NULL; i++) {
        auto events = QueryByEventId(suspiciousIds[i].logName,
            suspiciousIds[i].eventId, hours, 100);

        for (auto& event : events) {
            event.category = suspiciousIds[i].description;
            suspicious.push_back(event);
        }
    }

    return suspicious;
}
