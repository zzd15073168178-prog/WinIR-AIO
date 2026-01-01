import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Search, RefreshCw, AlertCircle } from 'lucide-react';
import './ProcessTable.css';

const API_BASE = 'http://127.0.0.1:8001/api';

// 配置 axios 超时
const apiClient = axios.create({
    baseURL: API_BASE,
    timeout: 10000, // 10秒超时
});

const ProcessTable = () => {
    const [processes, setProcesses] = useState({});
    const [rootProcs, setRootProcs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [filter, setFilter] = useState('');
    const [killingPid, setKillingPid] = useState(null); // 正在终止的进程

    const fetchData = async () => {
        try {
            const res = await apiClient.get('/processes');
            setProcesses(res.data.all_procs);
            setRootProcs(res.data.root_procs);
            setLoading(false);
            setError(null);
        } catch (err) {
            console.error(err);
            const errorMsg = err.code === 'ECONNABORTED'
                ? '请求超时，请检查后端服务'
                : err.response?.data?.detail || '获取进程数据失败';
            setError(errorMsg);
            setLoading(false);
        }
    };

    // 终止进程
    const handleKillProcess = async (pid, processName) => {
        if (killingPid) return; // 防止重复点击

        const confirmed = window.confirm(`确定要终止进程 ${processName} (PID: ${pid}) 吗？`);
        if (!confirmed) return;

        setKillingPid(pid);
        try {
            await apiClient.post(`/processes/${pid}/kill`);
            // 成功后刷新列表
            await fetchData();
        } catch (err) {
            const errorMsg = err.response?.status === 404
                ? '进程不存在或已退出'
                : err.response?.data?.detail || '终止进程失败';
            alert(`错误: ${errorMsg}`);
        } finally {
            setKillingPid(null);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 5000); // 改为5秒轮询，减少服务器压力
        return () => clearInterval(interval);
    }, []);

    // 过滤进程列表
    const flatList = Object.values(processes).filter(p =>
        !filter || p.name.toLowerCase().includes(filter.toLowerCase())
    );

    return (
        <div className="process-table-container glass-panel">
            <div className="table-toolbar">
                <div className="search-bar">
                    <Search size={18} />
                    <input
                        type="text"
                        placeholder="搜索进程..."
                        value={filter}
                        onChange={e => setFilter(e.target.value)}
                    />
                </div>
                <button className="icon-btn" onClick={fetchData} title="刷新">
                    <RefreshCw size={18} />
                </button>
            </div>

            {/* 错误提示 */}
            {error && (
                <div className="error-banner">
                    <AlertCircle size={16} />
                    <span>{error}</span>
                    <button onClick={() => setError(null)}>×</button>
                </div>
            )}

            <div className="table-content">
                <table>
                    <thead>
                        <tr>
                            <th>进程名称</th>
                            <th>CPU</th>
                            <th>内存</th>
                            <th>用户</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading ? (
                            <tr><td colSpan="5" className="text-center">加载中...</td></tr>
                        ) : flatList.length === 0 ? (
                            <tr><td colSpan="5" className="text-center">
                                {filter ? '没有匹配的进程' : '没有进程数据'}
                            </td></tr>
                        ) : (
                            flatList.slice(0, 100).map(proc => (
                                <tr key={proc.pid} className="process-row">
                                    <td>
                                        <div className="proc-name-cell">
                                            <span className="pid-badge">{proc.pid}</span>
                                            {proc.name}
                                        </div>
                                    </td>
                                    <td>
                                        <span className={`text-secondary ${(proc.cpu_percent || 0) > 50 ? 'text-warning' : ''}`}>
                                            {proc.cpu_percent !== undefined ? `${proc.cpu_percent.toFixed(1)}%` : '-'}
                                        </span>
                                    </td>
                                    <td>
                                        <span className="text-secondary">
                                            {proc.memory_mb !== undefined ? `${proc.memory_mb.toFixed(1)} MB` : '-'}
                                        </span>
                                    </td>
                                    <td>
                                        <span className="text-secondary">
                                            {proc.username || '-'}
                                        </span>
                                    </td>
                                    <td>
                                        <button
                                            className="action-btn text-danger"
                                            onClick={() => handleKillProcess(proc.pid, proc.name)}
                                            disabled={killingPid === proc.pid}
                                        >
                                            {killingPid === proc.pid ? '终止中...' : '终止'}
                                        </button>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>

            {/* 统计信息 */}
            <div className="table-footer">
                <span>共 {flatList.length} 个进程</span>
                {filter && <span> (已过滤)</span>}
            </div>
        </div>
    );
};

export default ProcessTable;
