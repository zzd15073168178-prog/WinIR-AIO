// monitor_tab.h - 进程监控标签页 (Procmon)
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/monitor_manager.h"
#include "../../SysmonCore/include/process_manager.h"

class MonitorTab : public BaseTab {
public:
    MonitorTab(HWND hParentTab, MonitorManager* pMonitorMgr, ProcessManager* pProcMgr);
    ~MonitorTab();

    bool Create(const RECT& rc) override;
    void Refresh() override;
    void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    void CreateToolbar();
    void StartMonitoring();
    void StopMonitoring();
    void LoadLogFile();
    void ClearResults();
    void ApplyFilter();

    tstring FormatTimestamp(ULONGLONG timestamp);

    // 控件 ID
    enum {
        IDC_COMBO_PROCESS = 200,
        IDC_CHECK_REGISTRY,
        IDC_CHECK_FILE,
        IDC_CHECK_NETWORK,
        IDC_CHECK_PROCESS,
        IDC_BTN_START,
        IDC_BTN_STOP,
        IDC_BTN_LOAD,
        IDC_BTN_CLEAR,
        IDC_EDIT_FILTER
    };

    // ListView 列
    enum {
        COL_TIME = 0,
        COL_PROCESS,
        COL_PID,
        COL_OPERATION,
        COL_PATH,
        COL_RESULT
    };

    MonitorManager* m_pMonitorManager;
    ProcessManager* m_pProcessManager;

    HWND m_hComboProcess;
    HWND m_hCheckRegistry;
    HWND m_hCheckFile;
    HWND m_hCheckNetwork;
    HWND m_hCheckProcess;
    HWND m_hBtnStart;
    HWND m_hBtnStop;
    HWND m_hBtnLoad;
    HWND m_hEditFilter;

    std::vector<ProcmonEvent> m_events;
    bool m_isMonitoring;
};
