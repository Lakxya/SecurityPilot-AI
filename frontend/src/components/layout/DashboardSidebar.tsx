import { useState } from 'react';
import { Badge } from '../common/Badge';

export interface DashboardSidebarProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
  onNewProjectClick: () => void;
}

export function DashboardSidebar({ activeTab, onTabChange, onNewProjectClick }: DashboardSidebarProps) {
  const [collapsed, setCollapsed] = useState(false);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊' },
    { id: 'projects', label: 'Projects', icon: '📁', count: '3' },
    { id: 'threats', label: 'Threat Engine', icon: '🛡️' },
    { id: 'iac', label: 'IaC Modules', icon: '☸️' },
    { id: 'history', label: 'Audit History', icon: '📜' },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
  ];

  return (
    <aside
      className={`bg-slate-950 border-r border-slate-800/80 flex flex-col justify-between transition-all duration-300 shrink-0 ${
        collapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Top Header & Navigation */}
      <div className="space-y-6">
        {/* Brand Bar */}
        <div className="h-16 px-4 flex items-center justify-between border-b border-slate-800/80">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-8 h-8 rounded-lg bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 flex items-center justify-center font-bold text-base shrink-0">
              🛡️
            </div>
            {!collapsed && (
              <span className="font-bold text-base text-white tracking-tight truncate">
                SecurityPilot<span className="text-indigo-400">AI</span>
              </span>
            )}
          </div>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-slate-900 transition-colors"
            title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              {collapsed ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M5 5l7 7-7 7" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
              )}
            </svg>
          </button>
        </div>

        {/* New Project Quick Action Button */}
        <div className="px-3">
          <button
            onClick={onNewProjectClick}
            className={`w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-lg transition-all duration-200 shadow-lg shadow-emerald-600/20 flex items-center justify-center gap-2 ${
              collapsed ? 'p-2.5' : 'px-4 py-2.5 text-xs'
            }`}
            title="Create Security Project"
          >
            <span className="text-sm">+</span>
            {!collapsed && <span>New Project</span>}
          </button>
        </div>

        {/* Navigation Menu */}
        <nav className="px-2 space-y-1">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
                    : 'text-slate-400 hover:text-white hover:bg-slate-900'
                }`}
                title={collapsed ? item.label : undefined}
              >
                <div className="flex items-center gap-3">
                  <span className="text-base shrink-0">{item.icon}</span>
                  {!collapsed && <span className="truncate">{item.label}</span>}
                </div>
                {!collapsed && item.count && (
                  <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-slate-900 text-slate-400 border border-slate-800">
                    {item.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status Card */}
      <div className="p-3 border-t border-slate-800/80">
        {!collapsed ? (
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-400">Threat Engine</span>
              <Badge variant="emerald" size="sm">
                Active
              </Badge>
            </div>
            <p className="text-[11px] text-slate-300 font-medium truncate">STRIDE v3.1 Engine</p>
          </div>
        ) : (
          <div className="flex justify-center" title="STRIDE v3.1 Threat Engine Active">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
          </div>
        )}
      </div>
    </aside>
  );
}
