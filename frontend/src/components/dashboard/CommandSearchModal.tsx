import { useState } from 'react';
import { Plus, Package, Save, Bot, Folder, ShieldAlert, Building2, Settings } from 'lucide-react';
import { Dialog } from '../ui/Dialog';

export interface CommandSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function CommandSearchModal({ isOpen, onClose }: CommandSearchModalProps) {
  const [query, setQuery] = useState('');

  const commands = [
    { title: 'Create Security Project', desc: 'Open 3-step project wizard', icon: <Plus className="w-4 h-4 text-indigo-400" />, category: 'Action', shortcut: '⌘N' },
    { title: 'Export Package Archive', desc: 'Compile ZIP, Markdown, PDF or JSON', icon: <Package className="w-4 h-4 text-emerald-400" />, category: 'Export', shortcut: '⌘⇧E' },
    { title: 'Save Active Security Document', desc: 'Persist current artifact to database', icon: <Save className="w-4 h-4 text-cyan-400" />, category: 'Workspace', shortcut: '⌘S' },
    { title: 'Toggle AI Copilot Assistant', desc: 'Context-aware security assistant', icon: <Bot className="w-4 h-4 text-purple-400" />, category: 'AI', shortcut: '⌘I' },
    { title: 'E-Commerce Cloud Microservices', desc: 'Open project workspace', icon: <Folder className="w-4 h-4 text-slate-400" />, category: 'Projects', shortcut: '' },
    { title: 'Healthcare Patient Portal Spec', desc: 'Open project workspace', icon: <Folder className="w-4 h-4 text-slate-400" />, category: 'Projects', shortcut: '' },
    { title: 'FinTech Banking Auth Engine', desc: 'Open project workspace', icon: <Folder className="w-4 h-4 text-slate-400" />, category: 'Projects', shortcut: '' },
    { title: 'STRIDE Threat Model Engine', desc: 'Inspect threat vectors', icon: <ShieldAlert className="w-4 h-4 text-rose-400" />, category: 'Tools', shortcut: '' },
    { title: 'Terraform IaC Generator', desc: 'Inspect IaC blueprints', icon: <Building2 className="w-4 h-4 text-amber-400" />, category: 'Tools', shortcut: '' },
    { title: 'User Profile & API Keys', desc: 'Manage account security', icon: <Settings className="w-4 h-4 text-slate-400" />, category: 'Settings', shortcut: '' },
  ];

  const filtered = commands.filter(
    (c) =>
      c.title.toLowerCase().includes(query.toLowerCase()) ||
      c.desc.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <Dialog isOpen={isOpen} onClose={onClose} maxWidth="lg" className="p-0 overflow-hidden">
      <div className="space-y-0">
        {/* Command Search Header Input */}
        <div className="p-4 border-b border-slate-800 flex items-center gap-3">
          <svg className="w-5 h-5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            placeholder="Search commands, projects, actions... [⌘K]"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-sm text-white placeholder-slate-500 focus:outline-none font-mono"
            autoFocus
          />
        </div>

        {/* Command Results List */}
        <div className="max-h-80 overflow-y-auto p-2 space-y-1 font-mono">
          {filtered.length > 0 ? (
            filtered.map((cmd) => (
              <button
                key={cmd.title}
                onClick={onClose}
                className="w-full p-2.5 rounded-lg flex items-center justify-between hover:bg-slate-900 transition-colors text-left group cursor-pointer"
              >
                <div className="flex items-center gap-3">
                  <span className="shrink-0">{cmd.icon}</span>
                  <div>
                    <p className="text-xs font-semibold text-white group-hover:text-indigo-400 transition-colors">
                      {cmd.title}
                    </p>
                    <p className="text-[11px] text-slate-400">{cmd.desc}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {cmd.shortcut && (
                    <kbd className="text-[10px] font-mono text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                      {cmd.shortcut}
                    </kbd>
                  )}
                  <span className="text-[10px] font-mono text-slate-500 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                    {cmd.category}
                  </span>
                </div>
              </button>
            ))
          ) : (
            <div className="py-8 text-center text-xs text-slate-500 font-mono">
              No matching commands or projects found.
            </div>
          )}
        </div>
      </div>
    </Dialog>
  );
}
