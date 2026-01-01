// targetver.h - Windows 版本目标定义
// 支持 Windows XP SP3 / Windows Server 2003 SP2 及以上

#pragma once

// Windows XP / Server 2003
#ifndef WINVER
#define WINVER 0x0501
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

// IE 6.0 (用于 Common Controls)
#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif

// 减少 Windows 头文件大小
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// 排除不常用的 API
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <sdkddkver.h>
