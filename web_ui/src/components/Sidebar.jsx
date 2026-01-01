import React from 'react';
import { LayoutDashboard, Activity, Network, FileText, Lock, Shield, Cpu } from 'lucide-react';
import './Sidebar.css';

const Sidebar = ({ activeTab, onTabChange }) => {
    const menuItems = [
        { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { id: 'processes', label: 'Processes', icon: Activity },
        { id: 'network', label: 'Network', icon: Network },
        { id: 'files', label: 'Files & Handles', icon: FileText },
        { id: 'security', label: 'Security', icon: Shield },
        { id: 'memory', label: 'Memory', icon: Cpu },
    ];

    return (
        <aside className="sidebar glass-panel">
            <div className="sidebar-header">
                <div className="logo-icon">S</div>
            </div>
            <nav className="sidebar-nav">
                {menuItems.map((item) => {
                    const Icon = item.icon;
                    return (
                        <button
                            key={item.id}
                            className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
                            onClick={() => onTabChange(item.id)}
                        >
                            <Icon size={20} />
                            <span className="nav-label">{item.label}</span>
                            {activeTab === item.id && <div className="active-indicator" />}
                        </button>
                    );
                })}
            </nav>
            <div className="sidebar-footer">
                <div className="user-profile">
                    <div className="avatar">A</div>
                    <div className="user-info">
                        <span className="name">Admin</span>
                        <span className="role">Root</span>
                    </div>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;
