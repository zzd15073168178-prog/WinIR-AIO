// eventlog_tab.h - 事件日志标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/eventlog_manager.h"

class EventLogTab : public BaseTab {
public:
    EventLogTab(HWND hParentTab, EventLogManager* pManager);
    virtual ~EventLogTab();

    virtual bool Create(const RECT& rc) override;
    virtual void Refresh() override;
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    EventLogManager* m_pManager;
    std::vector<EventLogEntry> m_events;

    HWND m_hComboLog;
    HWND m_hComboPreset;
    HWND m_hEditHours;
    HWND m_hBtnQuery;

    void CreateToolbar();
    void QueryEvents();
    tstring FormatFileTime(const FILETIME& ft);

    enum Columns {
        COL_TIME = 0,
        COL_LEVEL,
        COL_SOURCE,
        COL_EVENTID,
        COL_USER,
        COL_MESSAGE,
        COL_COUNT
    };
};
