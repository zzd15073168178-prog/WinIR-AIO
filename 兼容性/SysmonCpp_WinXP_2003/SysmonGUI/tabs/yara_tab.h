// yara_tab.h - YARA 扫描标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/yara_scanner.h"
#include "../../SysmonCore/include/process_manager.h"

class YaraTab : public BaseTab {
public:
    YaraTab(HWND hParentTab, YaraScanner* pYaraScanner, ProcessManager* pProcMgr);
    ~YaraTab();

    bool Create(const RECT& rc) override;
    void Refresh() override;
    void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    void CreateToolbar();
    void LoadRulesFromFile();
    void LoadRulesFromDirectory();
    void ScanFile();
    void ScanDirectory();
    void ScanProcess();
    void ClearResults();
    void ShowMatchDetails();

    void UpdateRulesStatus();

    // 控件 ID
    enum {
        IDC_EDIT_TARGET = 200,
        IDC_BTN_BROWSE_FILE,
        IDC_BTN_BROWSE_DIR,
        IDC_BTN_LOAD_RULES,
        IDC_BTN_LOAD_RULES_DIR,
        IDC_BTN_SCAN_FILE,
        IDC_BTN_SCAN_DIR,
        IDC_BTN_SCAN_PROCESS,
        IDC_BTN_CLEAR,
        IDC_COMBO_PROCESS,
        IDC_STATIC_RULES
    };

    // ListView 列
    enum {
        COL_RULE = 0,
        COL_NAMESPACE,
        COL_FILE,
        COL_STRINGS
    };

    YaraScanner* m_pYaraScanner;
    ProcessManager* m_pProcessManager;

    HWND m_hEditTarget;
    HWND m_hComboProcess;
    HWND m_hStaticRules;

    std::vector<YaraMatch> m_matches;
};
