// persistence_tab.h - 持久化检测标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/persistence_detector.h"

class PersistenceTab : public BaseTab {
public:
    PersistenceTab(HWND hParentTab, PersistenceDetector* pDetector);
    virtual ~PersistenceTab();

    virtual bool Create(const RECT& rc) override;
    virtual void Refresh() override;
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    PersistenceDetector* m_pDetector;
    std::vector<PersistenceItem> m_items;

    HWND m_hComboCategory;
    HWND m_hChkSuspiciousOnly;
    HWND m_hBtnScan;

    void CreateToolbar();
    void ScanPersistence();
    void FilterResults();

    enum Columns {
        COL_TYPE = 0,
        COL_NAME,
        COL_VALUE,
        COL_PATH,
        COL_SUSPICIOUS,
        COL_COUNT
    };
};
