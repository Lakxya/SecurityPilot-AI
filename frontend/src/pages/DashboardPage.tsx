import { useState, useEffect } from 'react';
import { useAuth } from '../hooks/useAuth';
import { DashboardSidebar } from '../components/layout/DashboardSidebar';
import { DashboardHeader } from '../components/layout/DashboardHeader';
import { DashboardFooter } from '../components/layout/DashboardFooter';
import { DashboardStats } from '../components/dashboard/DashboardStats';
import { RecentProjectsGrid } from '../components/dashboard/RecentProjectsGrid';
import { CreateProjectModal } from '../components/dashboard/CreateProjectModal';
import { CommandSearchModal } from '../components/dashboard/CommandSearchModal';
import { DocumentWorkspace } from '../components/workspace/DocumentWorkspace';
import { Badge } from '../components/common/Badge';
import { CyberShield3D } from '../components/common/CyberShield3D';
import { CyberGridBackground } from '../components/common/CyberGridBackground';

export function DashboardPage() {
  const { user } = useAuth();

  const [activeTab, setActiveTab] = useState('dashboard');
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isCommandSearchOpen, setIsCommandSearchOpen] = useState(false);

  // Active Project Workspace View State
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [selectedProjectName, setSelectedProjectName] = useState<string>('');

  // Global Keyboard Shortcut (Cmd+K / Ctrl+K) Listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsCommandSearchOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleOpenWorkspace = (id: string, name: string) => {
    setSelectedProjectId(id);
    setSelectedProjectName(name);
  };

  if (selectedProjectId) {
    return (
      <DocumentWorkspace
        projectId={selectedProjectId}
        projectName={selectedProjectName}
        onBackToDashboard={() => setSelectedProjectId(null)}
      />
    );
  }

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-100 font-sans selection:bg-indigo-500/30 animate-page-entry relative">
      {/* Ambient Animated Cyber Grid & Cursor Spotlight */}
      <CyberGridBackground />

      {/* Collapsible Left Sidebar */}
      <DashboardSidebar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onNewProjectClick={() => setIsCreateModalOpen(true)}
      />

      {/* Main Workspace Column */}
      <div className="flex flex-col flex-1 overflow-hidden relative">
        {/* Authenticated Top Navigation Header */}
        <DashboardHeader
          currentPath={`Workspace / ${activeTab.charAt(0).toUpperCase() + activeTab.slice(1)}`}
          onOpenCommandSearch={() => setIsCommandSearchOpen(true)}
        />

        {/* Scrollable Workspace Body */}
        <main className="flex-1 overflow-y-auto p-6 space-y-8">
          {/* Welcome User Banner */}
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-md rounded-xl p-6 relative overflow-hidden space-y-4">
            {/* Background Glow */}
            <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-600/10 blur-[100px] rounded-full pointer-events-none" />

            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 relative z-10">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Badge variant="emerald" size="sm" pulse>
                    Autonomous Security Engine Active
                  </Badge>
                  <span className="text-[11px] font-mono text-slate-400">
                    Role Scope: {user?.role || 'SECURITY_ENGINEER'}
                  </span>
                </div>
                <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                  Welcome back, {user?.full_name || 'Security Engineer'}
                </h1>
                <p className="text-xs sm:text-sm text-slate-400 max-w-2xl leading-relaxed">
                  Your authenticated SecurityPilotAI workspace is initialized. Ready to generate, inspect, and audit your 13 security architecture blueprints.
                </p>
              </div>

              <CyberShield3D size={75} className="shrink-0 hidden sm:block opacity-90" />
            </div>
          </div>

          {/* Quick Metrics Stats Section */}
          <DashboardStats />

          {/* Recent Security Projects Grid */}
          <RecentProjectsGrid
            onNewProjectClick={() => setIsCreateModalOpen(true)}
            onOpenWorkspace={handleOpenWorkspace}
          />
        </main>

        {/* Status Footer */}
        <DashboardFooter />
      </div>

      {/* 3-Step Project Creation Wizard Modal */}
      <CreateProjectModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSuccess={(newProj) => {
          setActiveTab('projects');
          if (newProj) {
            handleOpenWorkspace(newProj.id, newProj.name);
          }
        }}
      />

      {/* Command Search Palette Modal (Cmd+K / Ctrl+K) */}
      <CommandSearchModal
        isOpen={isCommandSearchOpen}
        onClose={() => setIsCommandSearchOpen(false)}
      />
    </div>
  );
}
