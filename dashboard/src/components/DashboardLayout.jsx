import React, { useState } from 'react';
import Sidebar from './Sidebar';
import StatsGrid from './StatsGrid';
import LiveFeed from './LiveFeed';
import SecurityControls from './SecurityControls';
import PolicyManager from './PolicyManager';
import KnowledgeBase from './KnowledgeBase';
import AuditLogs from './AuditLogs';
import SettingsView from './SettingsView';
import ManageOrgs from './ManageOrgs';
import Simulator from './Simulator';
import { useAuth } from '../context/AuthContext';

const DashboardLayout = () => {
    const [currentView, setCurrentView] = useState('dashboard');
    const { user, logout } = useAuth();

    const handleNavigate = (view) => {
        if (view === 'logout') {
            logout();
        } else {
            setCurrentView(view);
        }
    };

    const renderContent = () => {
        switch (currentView) {
            case 'dashboard':
                return (
                    <>
                        <StatsGrid />
                        <div className="mb-8">
                            <h3 className="text-xl font-semibold text-slate-200 mb-4 px-1">Active Protections</h3>
                            <SecurityControls />
                        </div>
                        <LiveFeed />
                    </>
                );
            case 'policies':
                return <PolicyManager />;
            case 'vector_admin':
                return <KnowledgeBase />;
            case 'audit_logs':
                return <AuditLogs />;
            case 'manage_orgs':
                return <ManageOrgs />;
            case 'settings':
                return <SettingsView />;
            case 'simulator':
                return <Simulator />;
            default:
                return <div className="text-slate-500">View not found</div>;
        }
    };

    return (
        <div className="flex h-screen bg-slate-950 text-slate-100 font-sans">
            <Sidebar activeView={currentView} onNavigate={handleNavigate} />

            <main className="flex-1 overflow-y-auto">
                <div className="p-8 max-w-7xl mx-auto">
                    <header className="mb-8 flex justify-between items-center">
                        <div>
                            <h2 className="text-3xl font-bold text-slate-100">
                                {currentView === 'dashboard' ? 'Security Dashboard' :
                                    currentView === 'policies' ? 'Policy Configuration' :
                                        currentView === 'vector_admin' ? 'Vector Admin' :
                                            currentView === 'simulator' ? 'Security Simulator' :
                                                currentView === 'settings' ? 'System Settings' : 'Audit Logs'}
                            </h2>
                            <p className="text-slate-500 mt-2">
                                {currentView === 'dashboard' ? 'Real-time monitoring and policy enforcement' :
                                    currentView === 'policies' ? 'Manage global security rules' :
                                        currentView === 'vector_admin' ? 'Manage RAG knowledge base' :
                                            currentView === 'simulator' ? 'Test filters in a sandbox' :
                                                currentView === 'settings' ? 'System status and configuration' : 'Review historical events'}
                            </p>
                        </div>

                        {/* User Info / Logout could go here, or in Sidebar */}
                        <div className="text-right">
                            <div className="text-sm text-emerald-400 font-medium">{user?.email || 'Admin'}</div>
                            <div className="text-xs text-slate-500 uppercase">{user?.role || 'User'}</div>
                        </div>
                    </header>

                    {renderContent()}
                </div>
            </main>
        </div>
    );
};

export default DashboardLayout;
