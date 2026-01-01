// dll_tab.h - DLL 检测标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/dll_manager.h"

class DllTab : public BaseTab {
public:
    DllTab(HWND hParentTab, DLLManager* pManager);
    virtual ~DllTab();

    virtual bool Create(const RECT& rc) override;
    virtual void Refresh() override;
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) override;

protected:
    virtual void ShowContextMenu(int x, int y) override;

private:
    DLLManager* m_pManager;
    std::vector<DllInfo> m_dlls;
    DWORD m_currentPid;

    HWND m_hEditPid;
    HWND m_hBtnScan;
    HWND m_hChkSuspicious;

    void CreateToolbar();
    void ScanProcess();
    void FilterDlls();

    enum Columns {
        COL_PATH = 0,
        COL_BASE,
        COL_SIZE,
        COL_COMPANY,
        COL_DESCRIPTION,
        COL_COUNT
    };
};
