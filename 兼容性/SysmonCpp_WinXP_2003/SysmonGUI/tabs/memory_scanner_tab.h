// memory_scanner_tab.h - 内存扫描标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/memory_scanner.h"

class MemoryScannerTab : public BaseTab {
public:
    MemoryScannerTab(HWND hParentTab, MemoryScanner* pScanner);
    virtual ~MemoryScannerTab();

    virtual bool Create(const RECT& rc) override;
    virtual void Refresh() override;
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) override;

private:
    MemoryScanner* m_pScanner;
    std::vector<MemoryScanResult> m_results;
    DWORD m_currentPid;

    HWND m_hEditPid;
    HWND m_hEditPattern;
    HWND m_hBtnScan;
    HWND m_hChkStrings;
    HWND m_hChkIPs;
    HWND m_hChkURLs;

    void CreateToolbar();
    void ScanMemory();

    enum Columns {
        COL_ADDRESS = 0,
        COL_TYPE,
        COL_VALUE,
        COL_CONTEXT,
        COL_COUNT
    };
};
