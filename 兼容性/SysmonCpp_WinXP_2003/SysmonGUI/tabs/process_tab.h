// process_tab.h - 进程列表标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/process_manager.h"

class ProcessTab : public BaseTab {
public:
    ProcessTab(HWND hParentTab, ProcessManager* pManager);
    virtual ~ProcessTab();

    // 创建
    virtual bool Create(const RECT& rc) override;

    // 刷新
    virtual void Refresh() override;

    // 消息处理
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) override;
    virtual void OnNotify(LPNMHDR pnmh) override;

protected:
    // 右键菜单
    virtual void ShowContextMenu(int x, int y) override;

    // 排序
    virtual void SortListView(int column) override;

private:
    ProcessManager* m_pManager;
    std::vector<ProcessInfo> m_processes;

    // 控件
    HWND m_hBtnRefresh;
    HWND m_hBtnKill;
    HWND m_hEditSearch;
    HWND m_hBtnSearch;
    HWND m_hChkSuspicious;

    // 过滤显示
    bool m_showSuspiciousOnly;
    tstring m_searchKeyword;

    // 内部方法
    void CreateToolbar();
    void PopulateListView();
    void UpdateProcessDisplay(const ProcessInfo& proc, int index);
    void FilterProcesses();

    // 进程操作
    void OnTerminateProcess();
    void OnSuspendProcess();
    void OnResumeProcess();
    void OnViewProperties();
    void OnOpenFileLocation();

    // 获取选中的 PID
    DWORD GetSelectedPid();

    // 列索引
    enum Columns {
        COL_PID = 0,
        COL_NAME,
        COL_CPU,
        COL_MEMORY,
        COL_USER,
        COL_PATH,
        COL_STATUS,
        COL_COUNT
    };
};
