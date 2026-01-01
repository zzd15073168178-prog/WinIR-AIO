// network_manager.cpp - 网络管理器实现
#include "../include/network_manager.h"
#include <tlhelp32.h>
#include <tchar.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

NetworkManager::NetworkManager()
{
}

NetworkManager::~NetworkManager()
{
}

// ============================================================================
// TCP 状态转字符串
// ============================================================================

tstring NetworkManager::TcpStateToString(DWORD state)
{
    switch (state) {
    case MIB_TCP_STATE_CLOSED:      return TEXT("CLOSED");
    case MIB_TCP_STATE_LISTEN:      return TEXT("LISTEN");
    case MIB_TCP_STATE_SYN_SENT:    return TEXT("SYN_SENT");
    case MIB_TCP_STATE_SYN_RCVD:    return TEXT("SYN_RCVD");
    case MIB_TCP_STATE_ESTAB:       return TEXT("ESTABLISHED");
    case MIB_TCP_STATE_FIN_WAIT1:   return TEXT("FIN_WAIT1");
    case MIB_TCP_STATE_FIN_WAIT2:   return TEXT("FIN_WAIT2");
    case MIB_TCP_STATE_CLOSE_WAIT:  return TEXT("CLOSE_WAIT");
    case MIB_TCP_STATE_CLOSING:     return TEXT("CLOSING");
    case MIB_TCP_STATE_LAST_ACK:    return TEXT("LAST_ACK");
    case MIB_TCP_STATE_TIME_WAIT:   return TEXT("TIME_WAIT");
    case MIB_TCP_STATE_DELETE_TCB:  return TEXT("DELETE_TCB");
    default:                        return TEXT("UNKNOWN");
    }
}

// ============================================================================
// 获取进程名
// ============================================================================

tstring NetworkManager::GetProcessNameByPid(DWORD pid)
{
    // 特殊 PID
    if (pid == 0) return TEXT("System Idle Process");
    if (pid == 4) return TEXT("System");

    // 检查缓存
    auto it = m_processNameCache.find(pid);
    if (it != m_processNameCache.end()) {
        return it->second;
    }

    tstring name = TEXT("Unknown");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    name = pe.szExeFile;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    // 缓存结果
    m_processNameCache[pid] = name;
    return name;
}

// ============================================================================
// 获取 TCP 连接
// ============================================================================

std::vector<NetworkConnection> NetworkManager::GetTcpConnections()
{
    std::vector<NetworkConnection> connections;

    // 获取 TCP 表大小
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (size == 0) {
        return connections;
    }

    // 分配内存
    PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!tcpTable) {
        return connections;
    }

    // 获取 TCP 表
    if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID& row = tcpTable->table[i];

            NetworkConnection conn;
            conn.protocol = TEXT("TCP");
            conn.localAddr = Utils::IpToString(row.dwLocalAddr);
            conn.localPort = ntohs((WORD)row.dwLocalPort);
            conn.remoteAddr = Utils::IpToString(row.dwRemoteAddr);
            conn.remotePort = ntohs((WORD)row.dwRemotePort);
            conn.state = TcpStateToString(row.dwState);
            conn.pid = row.dwOwningPid;
            conn.processName = GetProcessNameByPid(row.dwOwningPid);
            conn.isSuspicious = false;

            // 分析可疑连接
            AnalyzeSuspiciousConnection(conn);

            connections.push_back(conn);
        }
    }

    free(tcpTable);
    return connections;
}

// ============================================================================
// 获取 UDP 连接
// ============================================================================

std::vector<NetworkConnection> NetworkManager::GetUdpConnections()
{
    std::vector<NetworkConnection> connections;

    // 获取 UDP 表大小
    DWORD size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);

    if (size == 0) {
        return connections;
    }

    // 分配内存
    PMIB_UDPTABLE_OWNER_PID udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (!udpTable) {
        return connections;
    }

    // 获取 UDP 表
    if (GetExtendedUdpTable(udpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID& row = udpTable->table[i];

            NetworkConnection conn;
            conn.protocol = TEXT("UDP");
            conn.localAddr = Utils::IpToString(row.dwLocalAddr);
            conn.localPort = ntohs((WORD)row.dwLocalPort);
            conn.remoteAddr = TEXT("*");
            conn.remotePort = 0;
            conn.state = TEXT("*");
            conn.pid = row.dwOwningPid;
            conn.processName = GetProcessNameByPid(row.dwOwningPid);
            conn.isSuspicious = false;

            // 分析可疑连接
            AnalyzeSuspiciousConnection(conn);

            connections.push_back(conn);
        }
    }

    free(udpTable);
    return connections;
}

// ============================================================================
// 获取所有连接
// ============================================================================

std::vector<NetworkConnection> NetworkManager::GetAllConnections()
{
    // 清空进程名缓存
    m_processNameCache.clear();

    std::vector<NetworkConnection> allConnections;

    // 获取 TCP 连接
    std::vector<NetworkConnection> tcpConns = GetTcpConnections();
    allConnections.insert(allConnections.end(), tcpConns.begin(), tcpConns.end());

    // 获取 UDP 连接
    std::vector<NetworkConnection> udpConns = GetUdpConnections();
    allConnections.insert(allConnections.end(), udpConns.begin(), udpConns.end());

    // 更新缓存
    m_connectionCache = allConnections;

    return allConnections;
}

// ============================================================================
// 按 PID 过滤连接
// ============================================================================

std::vector<NetworkConnection> NetworkManager::GetConnectionsByPid(DWORD pid)
{
    std::vector<NetworkConnection> results;

    for (const auto& conn : m_connectionCache) {
        if (conn.pid == pid) {
            results.push_back(conn);
        }
    }

    return results;
}

// ============================================================================
// 按状态过滤
// ============================================================================

std::vector<NetworkConnection> NetworkManager::GetConnectionsByState(const tstring& state)
{
    std::vector<NetworkConnection> results;

    for (const auto& conn : m_connectionCache) {
        if (conn.state == state) {
            results.push_back(conn);
        }
    }

    return results;
}

// ============================================================================
// 分析可疑连接
// ============================================================================

void NetworkManager::AnalyzeSuspiciousConnection(NetworkConnection& conn)
{
    conn.isSuspicious = false;
    conn.suspiciousReason.clear();

    // 1. 检查可疑端口
    if (Utils::IsSuspiciousPort(conn.localPort)) {
        conn.isSuspicious = true;
        conn.suspiciousReason = TEXT("本地端口可疑: ");
        conn.suspiciousReason += to_tstring(conn.localPort);
        return;
    }

    if (conn.remotePort > 0 && Utils::IsSuspiciousPort(conn.remotePort)) {
        conn.isSuspicious = true;
        conn.suspiciousReason = TEXT("远程端口可疑: ");
        conn.suspiciousReason += to_tstring(conn.remotePort);
        return;
    }

    // 2. 检查非标准端口的外连 (排除常见端口)
    if (conn.state == TEXT("ESTABLISHED") && conn.remoteAddr != TEXT("127.0.0.1")) {
        WORD commonPorts[] = { 80, 443, 8080, 8443, 53, 25, 110, 143, 993, 995, 0 };
        bool isCommon = false;
        for (int i = 0; commonPorts[i] != 0; i++) {
            if (conn.remotePort == commonPorts[i]) {
                isCommon = true;
                break;
            }
        }

        if (!isCommon && conn.remotePort > 0) {
            // 非常见端口的外连，需要关注
            // 但不直接标记为可疑，除非是已知恶意端口
        }
    }

    // 3. 检查可疑进程的网络连接
    if (Utils::IsSuspiciousProcessName(conn.processName)) {
        // cmd.exe / powershell.exe 有网络连接是可疑的
        if (conn.state == TEXT("ESTABLISHED") || conn.state == TEXT("SYN_SENT")) {
            conn.isSuspicious = true;
            conn.suspiciousReason = TEXT("敏感进程存在网络连接");
            return;
        }
    }

    // 4. 检查到内网其他主机的连接 (可能是横向移动)
    if (conn.state == TEXT("ESTABLISHED")) {
        // 检查 RFC1918 私有地址
        DWORD remoteIp = 0;
        if (!conn.remoteAddr.empty() && conn.remoteAddr != TEXT("*")) {
            // 解析 IP
            int a, b, c, d;
            if (_stscanf_s(conn.remoteAddr.c_str(), TEXT("%d.%d.%d.%d"), &a, &b, &c, &d) == 4) {
                // 10.0.0.0/8
                if (a == 10) {
                    // 内网连接，不一定可疑
                }
                // 172.16.0.0/12
                else if (a == 172 && b >= 16 && b <= 31) {
                    // 内网连接
                }
                // 192.168.0.0/16
                else if (a == 192 && b == 168) {
                    // 内网连接
                }
            }
        }
    }
}

// ============================================================================
// 获取可疑连接
// ============================================================================

std::vector<NetworkConnection> NetworkManager::GetSuspiciousConnections()
{
    std::vector<NetworkConnection> results;

    for (const auto& conn : m_connectionCache) {
        if (conn.isSuspicious) {
            results.push_back(conn);
        }
    }

    return results;
}

// ============================================================================
// 刷新
// ============================================================================

void NetworkManager::Refresh()
{
    GetAllConnections();
}
