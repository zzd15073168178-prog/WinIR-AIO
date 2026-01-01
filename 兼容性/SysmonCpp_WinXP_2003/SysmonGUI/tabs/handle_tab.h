// handle_tab.h - 句柄查询标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/handle_manager.h"

class HandleTab : public BaseTab {
public:
    HandleTab(HWND hParentTab, HandleManager* pManager);
    virtual ~HandleTab();

    virtual bool Create(const RECT& rc) override;
    virtual void Refresh() override;
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    HandleManager* m_pManager;
    std::vector<HandleInfo> m_handles;
    DWORD m_currentPid;

    HWND m_hEditPid;
    HWND m_hBtnScan;
    HWND m_hComboType;

    void CreateToolbar();
    void ScanProcess();
    void FilterHandles();

    enum Columns {
        COL_HANDLE = 0,
        COL_TYPE,
        COL_NAME,
        COL_COUNT
    };
};
