// report_tab.h - 报告生成标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/report_generator.h"
#include "../../SysmonCore/include/process_manager.h"
#include "../../SysmonCore/include/network_manager.h"
#include "../../SysmonCore/include/persistence_detector.h"
#include "../../SysmonCore/include/eventlog_manager.h"

class ReportTab : public BaseTab {
public:
    ReportTab(HWND hParentTab, ReportGenerator* pReportGen,
              ProcessManager* pProcMgr, NetworkManager* pNetMgr,
              PersistenceDetector* pPersistence, EventLogManager* pEventLog);
    ~ReportTab();

    bool Create(const RECT& rc) override;
    void Refresh() override;
    void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    void CreateToolbar();
    void CreateSectionCheckboxes();
    void CollectData();
    void GenerateReport();
    void PreviewReport();
    void OpenReportFolder();

    // 控件 ID
    enum {
        IDC_COMBO_FORMAT = 200,
        IDC_EDIT_TITLE,
        IDC_EDIT_AUTHOR,
        IDC_CHECK_SUMMARY,
        IDC_CHECK_PROCESSES,
        IDC_CHECK_NETWORK,
        IDC_CHECK_PERSISTENCE,
        IDC_CHECK_EVENTS,
        IDC_CHECK_SUSPICIOUS,
        IDC_BTN_GENERATE,
        IDC_BTN_PREVIEW,
        IDC_BTN_OPENFOLDER,
        IDC_EDIT_OUTPUT
    };

    // ListView 列（用于显示报告历史）
    enum {
        COL_TIME = 0,
        COL_FORMAT,
        COL_PATH,
        COL_SIZE
    };

    ReportGenerator* m_pReportGenerator;
    ProcessManager* m_pProcessManager;
    NetworkManager* m_pNetworkManager;
    PersistenceDetector* m_pPersistenceDetector;
    EventLogManager* m_pEventLogManager;

    HWND m_hComboFormat;
    HWND m_hEditTitle;
    HWND m_hEditAuthor;
    HWND m_hCheckSummary;
    HWND m_hCheckProcesses;
    HWND m_hCheckNetwork;
    HWND m_hCheckPersistence;
    HWND m_hCheckEvents;
    HWND m_hCheckSuspicious;
    HWND m_hEditOutput;

    std::vector<tstring> m_reportHistory;
};
