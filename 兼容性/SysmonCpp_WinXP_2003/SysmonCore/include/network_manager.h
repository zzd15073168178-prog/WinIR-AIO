// network_manager.h - 网络管理器
#pragma once

#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpmib.h>

#pragma comment(lib, "ws2_32.lib")

class NetworkManager {
public:
    NetworkManager();
    ~NetworkManager();

    // 获取所有网络连接
    std::vector<NetworkConnection> GetAllConnections();

    // 仅获取 TCP 连接
    std::vector<NetworkConnection> GetTcpConnections();

    // 仅获取 UDP 连接
    std::vector<NetworkConnection> GetUdpConnections();

    // 按 PID 过滤连接
    std::vector<NetworkConnection> GetConnectionsByPid(DWORD pid);

    // 按状态过滤
    std::vector<NetworkConnection> GetConnectionsByState(const tstring& state);

    // 获取可疑连接
    std::vector<NetworkConnection> GetSuspiciousConnections();

    // 刷新
    void Refresh();

private:
    std::vector<NetworkConnection> m_connectionCache;

    // TCP 状态转字符串
    tstring TcpStateToString(DWORD state);

    // 获取进程名
    tstring GetProcessNameByPid(DWORD pid);

    // 分析连接是否可疑
    void AnalyzeSuspiciousConnection(NetworkConnection& conn);

    // 进程名缓存
    std::map<DWORD, tstring> m_processNameCache;
};
