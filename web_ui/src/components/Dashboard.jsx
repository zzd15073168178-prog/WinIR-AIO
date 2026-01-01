import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Cpu, Database, HardDrive, Activity, AlertCircle } from 'lucide-react';
import './Dashboard.css';

const API_BASE = 'http://127.0.0.1:8001/api';

// 配置 axios 超时
const apiClient = axios.create({
    baseURL: API_BASE,
    timeout: 10000,
});

const StatCard = ({ title, value, subtext, icon: Icon, color, loading }) => (
    <div className="stat-card glass-panel">
        <div className="stat-header">
            <span className="stat-title">{title}</span>
            <Icon size={20} color={color} />
        </div>
        <div className="stat-content">
            <div className="stat-value">{loading ? '...' : value}</div>
            <div className="stat-subtext">{loading ? '加载中' : subtext}</div>
        </div>
        <div className="stat-chart-placeholder" style={{ borderColor: color }}>
            {/* Mini chart placeholder */}
        </div>
    </div>
);

const Dashboard = () => {
    const [stats, setStats] = useState({
        cpu_percent: 0,
        memory: { percent: 0, used: 0, total: 0 },
        disk: { percent: 0 }
    });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const res = await apiClient.get('/system/stats');
                setStats(res.data);
                setError(null);
                setLoading(false);
            } catch (e) {
                console.error(e);
                const errorMsg = e.code === 'ECONNABORTED'
                    ? '请求超时'
                    : e.response?.data?.detail || '获取系统状态失败';
                setError(errorMsg);
                setLoading(false);
            }
        };
        fetchStats();
        const interval = setInterval(fetchStats, 3000); // 改为3秒
        return () => clearInterval(interval);
    }, []);

    const memUsedGB = (stats.memory.used / (1024 ** 3)).toFixed(1);
    const memTotalGB = (stats.memory.total / (1024 ** 3)).toFixed(1);

    // 获取 CPU 核心数
    const cpuCores = navigator.hardwareConcurrency || '?';

    return (
        <div className="dashboard-container">
            {/* 错误提示 */}
            {error && (
                <div className="dashboard-error">
                    <AlertCircle size={16} />
                    <span>{error}</span>
                    <button onClick={() => setError(null)}>×</button>
                </div>
            )}

            <div className="stats-grid">
                <StatCard
                    title="CPU 使用率"
                    value={`${stats.cpu_percent?.toFixed(1) || 0}%`}
                    subtext={`${cpuCores} 核心`}
                    icon={Cpu}
                    color="#f85149"
                    loading={loading}
                />
                <StatCard
                    title="内存"
                    value={`${stats.memory.percent?.toFixed(1) || 0}%`}
                    subtext={`${memUsedGB} / ${memTotalGB} GB`}
                    icon={Database}
                    color="#58a6ff"
                    loading={loading}
                />
                <StatCard
                    title="磁盘"
                    value={`${stats.disk.percent?.toFixed(1) || 0}%`}
                    subtext="系统盘"
                    icon={HardDrive}
                    color="#238636"
                    loading={loading}
                />
                <StatCard
                    title="网络"
                    value="-"
                    subtext="监控中"
                    icon={Activity}
                    color="#a371f7"
                    loading={loading}
                />
            </div>

            <div className="dashboard-charts glass-panel">
                <h3>系统性能历史</h3>
                <div className="chart-area flex-center text-secondary">
                    (图表功能开发中)
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
