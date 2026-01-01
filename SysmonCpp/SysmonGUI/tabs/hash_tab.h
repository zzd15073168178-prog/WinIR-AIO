// hash_tab.h - 哈希计算标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/hash_manager.h"

class HashTab : public BaseTab {
public:
    HashTab(HWND hParentTab, HashManager* pManager);
    virtual ~HashTab();

    virtual bool Create(const RECT& rc) override;
    virtual void Refresh() override;
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    HashManager* m_pManager;
    std::vector<FileHashResult> m_results;

    HWND m_hEditPath;
    HWND m_hBtnBrowse;
    HWND m_hBtnCalculate;
    HWND m_hChkMD5;
    HWND m_hChkSHA1;
    HWND m_hChkSHA256;
    HWND m_hProgress;

    void CreateToolbar();
    void BrowseFile();
    void CalculateHash();

    static void CALLBACK ProgressCallback(DWORD current, DWORD total, void* context);

    enum Columns {
        COL_FILE = 0,
        COL_SIZE,
        COL_MD5,
        COL_SHA1,
        COL_SHA256,
        COL_COUNT
    };

    enum {
        IDC_BTN_BROWSE = 2001,
        IDC_PROGRESS = 2002
    };
};
