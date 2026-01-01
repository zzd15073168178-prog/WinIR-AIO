// security_tab.h - 安全检测标签页 (Autoruns)
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/security_manager.h"

class SecurityTab : public BaseTab {
public:
    SecurityTab(HWND hParentTab, SecurityManager* pSecurityMgr);
    ~SecurityTab();

    bool Create(const RECT& rc) override;
    void Refresh() override;
    void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    void CreateToolbar();
    void ScanAutoruns();
    void ShowOnlySuspicious();
    void ExportResults();
    void ShowDetails();

    tstring GetAutorunTypeName(AutorunType type);

    // 控件 ID
    enum {
        IDC_SEC_COMBO_TYPE = 200,
        IDC_SEC_CHECK_SUSPICIOUS,
        IDC_SEC_BTN_SCAN,
        IDC_SEC_BTN_EXPORT,
        IDC_SEC_BTN_DETAILS,
        IDC_SEC_EDIT_SEARCH
    };

    // ListView 列
    enum {
        COL_TYPE = 0,
        COL_LOCATION,
        COL_NAME,
        COL_PUBLISHER,
        COL_PATH,
        COL_SUSPICIOUS
    };

    SecurityManager* m_pSecurityManager;

    HWND m_hComboType;
    HWND m_hCheckSuspicious;
    HWND m_hBtnScan;
    HWND m_hEditSearch;

    std::vector<AutorunEntry> m_entries;
    bool m_showOnlySuspicious;
};
