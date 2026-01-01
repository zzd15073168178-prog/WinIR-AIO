// resource.h - 资源定义
#pragma once

// 图标
#define IDI_SYSMON                      100
#define IDI_SMALL                       101

// 菜单
#define IDM_MAINMENU                    200
#define IDM_FILE_EXIT                   201
#define IDM_VIEW_REFRESH                202
#define IDM_VIEW_LOG                    203
#define IDM_HELP_ABOUT                  204

// 控件 ID
#define IDC_TAB_MAIN                    1000
#define IDC_STATUSBAR                   1001
#define IDC_BTN_REFRESH                 1002
#define IDC_BTN_VIEWLOG                 1003

// Tab 页 ID
#define IDC_TAB_PROCESS                 2000
#define IDC_TAB_PROCESS_TREE            2001
#define IDC_TAB_NETWORK                 2002
#define IDC_TAB_DLL                     2003
#define IDC_TAB_HANDLE                  2004
#define IDC_TAB_DUMP                    2005
#define IDC_TAB_PROCMON                 2006
#define IDC_TAB_SECURITY                2007
#define IDC_TAB_HASH                    2008
#define IDC_TAB_FILELOCKER              2009
#define IDC_TAB_MEMORY                  2010
#define IDC_TAB_YARA                    2011
#define IDC_TAB_TRACE                   2012
#define IDC_TAB_EVENTLOG                2013

// ListView 相关
#define IDC_LISTVIEW                    3000
#define IDC_EDIT_SEARCH                 3001
#define IDC_BTN_SEARCH                  3002
#define IDC_COMBO_FILTER                3003

// 右键菜单
#define IDM_PROCESS_TERMINATE           4000
#define IDM_PROCESS_SUSPEND             4001
#define IDM_PROCESS_RESUME              4002
#define IDM_PROCESS_PROPERTIES          4003
#define IDM_PROCESS_OPENLOCATION        4004
#define IDM_PROCESS_DUMP                4005
#define IDM_PROCESS_VIEWDLL             4006
#define IDM_PROCESS_VIEWHANDLE          4007
#define IDM_PROCESS_VIEWNETWORK         4008

// 对话框
#define IDD_ABOUTBOX                    5000
#define IDD_LOGWINDOW                   5001
