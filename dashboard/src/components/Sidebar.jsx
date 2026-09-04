import React from 'react';
import { LayoutDashboard, FileText, Shield, Database, Settings, Play } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const Sidebar = ({ activeView, onNavigate }) => {
    const { user } = useAuth();
    const menuItems = [
        { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard' },
        { id: 'audit_logs', icon: FileText, label: 'Audit Logs' },
        { id: 'policies', icon: Shield, label: 'Policy Manager' },
        { id: 'vector_admin', icon: Database, label: 'Vector Admin' },
        { id: 'simulator', icon: Play, label: 'Simulator' },
    ];

    if (activeView === 'manage_orgs' || (user?.role === 'super_admin')) {
        const insertIndex = 1;
        // Check if not exists
        if (!menuItems.find(i => i.id === 'manage_orgs')) {
            menuItems.splice(insertIndex, 0, { id: 'manage_orgs', label: 'Organizations', icon: Settings }); // Using Settings icon as placeholder or import Building2
        }
    }

    return (
        <div className="h-screen w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
            <div className="p-6">
                <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
                    ClearGate
                </h1>
                <p className="text-xs text-slate-500 mt-1">Sovereign AI Proxy</p>
            </div>

            <nav className="flex-1 px-4 space-y-2">
                {menuItems.map((item) => (
                    <button
                        key={item.id}
                        onClick={() => onNavigate(item.id)}
                        className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${activeView === item.id
                            ? 'bg-blue-600/10 text-blue-400'
                            : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                            }`}
                    >
                        <item.icon size={20} />
                        <span className="font-medium">{item.label}</span>
                    </button>
                ))}
            </nav>

            <div className="p-4 border-t border-slate-800 space-y-2">
                <button
                    onClick={() => onNavigate('settings')}
                    className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${activeView === 'settings'
                        ? 'bg-blue-600/10 text-blue-400'
                        : 'text-slate-400 hover:text-slate-200'}`}
                >
                    <Settings size={20} />
                    <span className="font-medium">Settings</span>
                </button>
                <button
                    onClick={() => onNavigate && onNavigate('logout')}
                    className="w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-red-400 hover:bg-slate-800 transition-colors"
                >
                    <FileText size={20} />
                    <span className="font-medium">Sign Out</span>
                </button>
            </div>
        </div>
    );
};

export default Sidebar;
