import { useState } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { Badge } from '../common/Badge';
import { Button } from '../ui/Button';
import { VaultModal } from '../vault/VaultModal';

export interface DashboardHeaderProps {
  onOpenCommandSearch: () => void;
  currentPath?: string;
}

export function DashboardHeader({ onOpenCommandSearch, currentPath = 'Workspace / Dashboard' }: DashboardHeaderProps) {
  const { user, logout } = useAuth();
  const [profileOpen, setProfileOpen] = useState(false);
  const [isVaultOpen, setIsVaultOpen] = useState(false);

  return (
    <>
      <header className="h-16 bg-slate-950/80 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between shrink-0 relative z-30">
        {/* Breadcrumbs */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400">{currentPath}</span>
        </div>

        {/* Center Command Palette Search Trigger */}
        <div className="hidden sm:flex items-center">
          <button
            onClick={onOpenCommandSearch}
            className="bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 rounded-lg px-4 py-1.5 text-xs text-slate-400 hover:text-slate-200 flex items-center gap-6 transition-all shadow-inner cursor-pointer"
          >
            <div className="flex items-center gap-2">
              <svg className="w-3.5 h-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <span>Search projects, docs, or AI commands...</span>
            </div>
            <kbd className="bg-slate-950 border border-slate-800 px-1.5 py-0.5 rounded text-[10px] text-slate-400 font-mono">
              ⌘K
            </kbd>
          </button>
        </div>

        {/* Right Controls */}
        <div className="flex items-center gap-3">
          {/* AI Vault Button */}
          <Button variant="outline" size="sm" onClick={() => setIsVaultOpen(true)} icon={<span>🔑</span>}>
            AI Vault
          </Button>

          {/* AI Model Indicator */}
          <Badge variant="indigo" size="sm" className="hidden lg:inline-flex">
            Claude 3.5 Sonnet
          </Badge>

        {/* Notifications Icon */}
        <button
          className="relative text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-slate-900 transition-colors"
          title="Notifications"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-emerald-400" />
        </button>

        {/* User Profile Menu */}
        <div className="relative">
          <button
            onClick={() => setProfileOpen(!profileOpen)}
            className="flex items-center gap-2.5 p-1.5 rounded-lg hover:bg-slate-900 transition-colors text-left"
          >
            <div className="w-8 h-8 rounded-full bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 font-bold flex items-center justify-center text-xs">
              {user?.full_name ? user.full_name.charAt(0).toUpperCase() : user?.email.charAt(0).toUpperCase() || 'U'}
            </div>
            <div className="hidden md:block">
              <p className="text-xs font-semibold text-white leading-tight max-w-[120px] truncate">
                {user?.full_name || user?.email}
              </p>
              <p className="text-[10px] text-slate-400 font-mono leading-tight truncate">{user?.role}</p>
            </div>
          </button>

          {/* Profile Dropdown */}
          {profileOpen && (
            <div className="absolute right-0 mt-2 w-56 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl py-2 z-50">
              <div className="px-4 py-2 border-b border-slate-800">
                <p className="text-xs font-semibold text-white truncate">{user?.full_name || 'Security User'}</p>
                <p className="text-[11px] text-slate-400 truncate">{user?.email}</p>
              </div>
              <div className="py-1">
                <button
                  onClick={logout}
                  className="w-full text-left px-4 py-2 text-xs text-rose-400 hover:bg-rose-500/10 transition-colors flex items-center gap-2"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                  </svg>
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
    <VaultModal isOpen={isVaultOpen} onClose={() => setIsVaultOpen(false)} />
    </>
  );
}
