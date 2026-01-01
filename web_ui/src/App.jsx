import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import ProcessTable from './components/ProcessTable';
import Dashboard from './components/Dashboard';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard />;
      case 'processes':
        return <ProcessTable />;
      default:
        return <div className="p-8">Work in Progress: {activeTab}</div>;
    }
  };

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />
      <main className="main-content">
        <header className="top-bar glass-panel">
          <h1>Sysmon <span className="text-accent">Web</span></h1>
          <div className="status-badge">System Online</div>
        </header>
        <div className="content-area">
          {renderContent()}
        </div>
      </main>
    </div>
  );
}

export default App;
