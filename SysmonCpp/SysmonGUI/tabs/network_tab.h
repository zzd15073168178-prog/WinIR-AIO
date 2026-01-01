// network_tab.h - 网络连接标签页
#pragma once

#include "base_tab.h"
#include "../../SysmonCore/include/network_manager.h"

class NetworkTab : public BaseTab {
public:
    NetworkTab(HWND hParentTab, NetworkManager* pManager);
    virtual ~NetworkTab();

    // 创建
    virtual bool Create(const RECT& rc) override;

    // 刷新
    virtual void Refresh() override;

    // 消息处理
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) override;

protected:
    // 右键菜单
    virtual void ShowContextMenu(int x, int y) override;

    // 排序
    virtual void SortListView(int column) override;

private:
    NetworkManager* m_pManager;
    std::vector<NetworkConnection> m_connections;

    // 控件
    HWND m_hBtnRefresh;
    HWND m_hComboProtocol;
    HWND m_hComboState;
    HWND m_hEditSearch;
    HWND m_hBtnSearch;
    HWND m_hChkSuspicious;

    // 过滤
    tstring m_filterProtocol;
    tstring m_filterState;
    tstring m_searchKeyword;
    bool m_showSuspiciousOnly;

    // 内部方法
    void CreateToolbar();
    void PopulateListView();
    void FilterConnections();

    // 列索引
    enum Columns {
        COL_PROTOCOL = 0,
        COL_LOCAL_ADDR,
        COL_LOCAL_PORT,
        COL_REMOTE_ADDR,
        COL_REMOTE_PORT,
        COL_STATE,
        COL_PID,
        COL_PROCESS,
        COL_COUNT
    };
};
