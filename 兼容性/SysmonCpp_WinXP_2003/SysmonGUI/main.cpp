// main.cpp - 程序入口
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <tchar.h>
#include "main_window.h"

#pragma comment(lib, "ole32.lib")

int APIENTRY _tWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPTSTR lpCmdLine,
    _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // 初始化 COM (用于某些系统功能)
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    // 创建主窗口
    MainWindow mainWnd(hInstance);

    if (!mainWnd.Create(nCmdShow)) {
        MessageBox(NULL, TEXT("创建主窗口失败!"), TEXT("错误"), MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    // 运行消息循环
    int result = mainWnd.Run();

    CoUninitialize();
    return result;
}
