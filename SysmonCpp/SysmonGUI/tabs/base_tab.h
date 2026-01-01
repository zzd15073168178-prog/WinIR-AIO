// base_tab.h - Tab 页基类
#pragma once

#include "../../SysmonCore/include/common.h"
#include "../resource.h"
#include <commctrl.h>

class BaseTab {
public:
    BaseTab(HWND hParentTab, const tstring& title = TEXT(""));
    virtual ~BaseTab();

    // 创建 Tab 内容
    virtual bool Create(const RECT& rc);

    // 显示/隐藏
    void Show(bool bShow);

    // 调整大小
    virtual void Resize(const RECT& rc);

    // 刷新数据
    virtual void Refresh() = 0;

    // 获取窗口句柄
    HWND GetHwnd() const { return m_hWnd; }

    // 消息处理
    virtual void OnCommand(WORD id, WORD code, HWND hCtrl) {}
    virtual void OnNotify(LPNMHDR pnmh) {}

protected:
    HWND m_hParentTab;      // 父 Tab 控件
    HWND m_hWnd;            // Tab 内容窗口
    HWND m_hListView;       // ListView 控件
    HWND m_hToolbar;        // 工具栏
    HWND m_hSearchEdit;     // 搜索框
    tstring m_title;        // 标题

    // 窗口过程
    static LRESULT CALLBACK TabWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    virtual LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);

    // 创建 ListView
    HWND CreateListView(const RECT& rc, const std::vector<tstring>& columns,
        const std::vector<int>& widths);

    // 创建工具栏区域
    void CreateToolbarArea(int height);

    // 添加工具栏按钮
    HWND AddButton(int x, int y, int width, int height, WORD id, const tstring& text);
    HWND AddEdit(int x, int y, int width, int height, WORD id);
    HWND AddComboBox(int x, int y, int width, int height, WORD id);
    HWND AddLabel(int x, int y, int width, int height, const tstring& text);

    // ListView 操作
    void ClearListView();
    void AddColumn(int index, const tstring& text, int width);
    int AddListViewItem(const std::vector<tstring>& values);
    void SetListViewItemText(int item, int subItem, const tstring& text);
    void AutoSizeColumns();

    // 排序支持
    int m_sortColumn;
    bool m_sortAscending;
    virtual void SortListView(int column);
    static int CALLBACK CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

    // 右键菜单
    virtual void ShowContextMenu(int x, int y) {}

    // 获取选中项
    int GetSelectedItem();
    std::vector<int> GetSelectedItems();

    // 状态栏更新
    void SetStatusText(const tstring& text);

    // 使用 resource.h 中定义的 IDC_LISTVIEW (3000)
};
