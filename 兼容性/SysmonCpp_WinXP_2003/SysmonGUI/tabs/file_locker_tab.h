// file_locker_tab.h - 文件锁定分析标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/file_locker.h"
#include "../../SysmonCore/include/process_manager.h"

class FileLockerTab : public BaseTab {
public:
    FileLockerTab(HWND hParentTab, FileLocker* pFileLocker, ProcessManager* pProcMgr);
    ~FileLockerTab();

    bool Create(const RECT& rc) override;
    void Refresh() override;
    void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    void CreateToolbar();
    void AnalyzeFile();
    void BrowseFile();
    void KillProcess();
    void CopyPath();

    // 控件 ID
    enum {
        IDC_EDIT_PATH = 200,
        IDC_BTN_BROWSE,
        IDC_BTN_ANALYZE,
        IDC_BTN_KILL,
        IDC_BTN_COPY
    };

    // ListView 列
    enum {
        COL_PROCESS = 0,
        COL_PID,
        COL_HANDLE,
        COL_TYPE,
        COL_PATH
    };

    FileLocker* m_pFileLocker;
    ProcessManager* m_pProcessManager;

    HWND m_hEditPath;
    HWND m_hBtnBrowse;
    HWND m_hBtnAnalyze;
    HWND m_hBtnKill;

    std::vector<LockedFileInfo> m_lockedFiles;
};
