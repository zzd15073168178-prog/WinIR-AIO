// eventlog_manager.h - 事件日志管理器
#pragma once

#include "common.h"

class EventLogManager {
public:
    EventLogManager();
    ~EventLogManager();

    // 查询事件日志
    std::vector<EventLogEntry> QuerySecurityLog(DWORD hours = 24, DWORD maxEvents = 1000);
    std::vector<EventLogEntry> QuerySystemLog(DWORD hours = 24, DWORD maxEvents = 1000);
    std::vector<EventLogEntry> QueryApplicationLog(DWORD hours = 24, DWORD maxEvents = 1000);

    // 按事件 ID 过滤
    std::vector<EventLogEntry> QueryByEventId(const tstring& logName, DWORD eventId,
        DWORD hours = 24, DWORD maxEvents = 1000);

    // 获取登录事件 (4624, 4625)
    std::vector<EventLogEntry> GetLoginEvents(DWORD hours = 24);

    // 获取进程创建事件 (4688)
    std::vector<EventLogEntry> GetProcessCreationEvents(DWORD hours = 24);

    // 获取服务安装事件 (7045)
    std::vector<EventLogEntry> GetServiceInstallEvents(DWORD hours = 24);

    // 获取可疑事件
    std::vector<EventLogEntry> GetSuspiciousEvents(DWORD hours = 24);

private:
    // 使用旧的 Event Log API (XP/2003 兼容)
    std::vector<EventLogEntry> QueryEventLogLegacy(const tstring& logName,
        DWORD hours, DWORD maxEvents, DWORD filterEventId = 0);

    // 解析事件记录
    EventLogEntry ParseEventRecord(EVENTLOGRECORD* pRecord, const tstring& logName);

    // 获取事件消息
    tstring GetEventMessage(const tstring& sourceName, DWORD eventId,
        LPCTSTR* strings, DWORD numStrings);

    // 事件级别转字符串
    tstring EventTypeToString(WORD eventType);

    // 计算时间差
    bool IsWithinTimeRange(DWORD eventTime, DWORD hours);
};
