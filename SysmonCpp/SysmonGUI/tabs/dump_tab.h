// dump_tab.h - 内存转储标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/dump_manager.h"
#include "../../SysmonCore/include/process_manager.h"

class DumpTab : public BaseTab {
public:
    DumpTab(HWND hParentTab, DumpManager* pDumpMgr, ProcessManager* pProcMgr);
    virtual ~DumpTab();

    virtual bool Create(const RECT& rc) override;
    virtual void Refresh() override;
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    DumpManager* m_pDumpManager;
    ProcessManager* m_pProcessManager;
    std::vector<DumpResult> m_dumps;

    HWND m_hEditPid;
    HWND m_hComboDumpType;
    HWND m_hBtnDump;
    HWND m_hBtnDelete;
    HWND m_hBtnOpenFolder;

    void CreateToolbar();
    void CreateDump();
    void DeleteSelectedDump();
    void OpenDumpFolder();
    tstring FormatFileSize(ULONGLONG size);
    tstring FormatFileTime(const FILETIME& ft);

    enum Columns {
        COL_FILE = 0,
        COL_PID,
        COL_SIZE,
        COL_TIME,
        COL_COUNT
    };

    enum {
        IDC_BTN_DUMP = 2001,
        IDC_BTN_DELETE = 2002,
        IDC_BTN_OPENFOLDER = 2003
    };
};
