import { useState, useEffect, useCallback } from 'react';
import { Button } from '../ui/Button';
import { Badge } from '../common/Badge';
import { Dialog } from '../ui/Dialog';
import { ExportModal } from './ExportModal';
import { CopilotPanel } from '../copilot/CopilotPanel';
import { CodeViewer } from '../common/CodeViewer';
import { EmptyState } from '../common/EmptyState';
import { useSSEStream } from '../../hooks/useSSEStream';
import { useToast } from '../../hooks/useToast';
import { generationService } from '../../services/generationService';
import { GeneratedDocumentSpec } from '../../types/project';

const getLanguageForTab = (tab: string): string => {
  switch (tab) {
    case 'DOCKERFILE':
      return 'dockerfile';
    case 'DOCKER_COMPOSE':
    case 'KUBERNETES':
    case 'GITHUB_ACTIONS':
      return 'yaml';
    case 'TERRAFORM':
      return 'hcl';
    case 'DATABASE_DESIGN':
    case 'API_SPEC':
      return 'json';
    default:
      return 'markdown';
  }
};

export interface DocumentWorkspaceProps {
  projectId: string;
  projectName: string;
  onBackToDashboard: () => void;
}

export function DocumentWorkspace({ projectId, projectName, onBackToDashboard }: DocumentWorkspaceProps) {
  const { showToast } = useToast();
  const [activeTab, setActiveTab] = useState('README');
  const [documentContent, setDocumentContent] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [autosaveStatus, setAutosaveStatus] = useState<'idle' | 'saving' | 'saved'>('idle');

  // Version History State
  const [versions, setVersions] = useState<GeneratedDocumentSpec[]>([]);
  const [isVersionPanelOpen, setIsVersionPanelOpen] = useState(false);
  const [compareVersion, setCompareVersion] = useState<GeneratedDocumentSpec | null>(null);
  const [isDiffMode, setIsDiffMode] = useState(false);

  // Single Document Regeneration Modal State
  const [isRegenModalOpen, setIsRegenModalOpen] = useState(false);
  const [customInstructions, setCustomInstructions] = useState('');

  // Generated documents lookup map for file tree
  const [generatedMap, setGeneratedMap] = useState<Record<string, number>>({});

  const { isStreaming, streamContent, startStream } = useSSEStream();

  // 1.5s Debounced Autosave Effect
  useEffect(() => {
    if (!isEditing || !documentContent || documentContent.includes('is not yet generated')) return;
    const timer = setTimeout(async () => {
      try {
        await generationService.saveDocument(projectId, activeTab, documentContent);
        setAutosaveStatus('saved');
        showToast('success', 'Autosaved', `Edits saved to ${activeTab}`);
      } catch {
        setAutosaveStatus('idle');
      }
    }, 1500);

    return () => clearTimeout(timer);
  }, [documentContent, isEditing, projectId, activeTab, showToast]);

  const docCategories = [
    {
      name: 'Requirements & Specs',
      items: [
        { id: 'README', label: 'README.md', icon: '📄' },
        { id: 'SRS', label: 'SRS.md', icon: '📋' },
        { id: 'SDS', label: 'SDS.md', icon: '📐' },
      ],
    },
    {
      name: 'Architecture & Data',
      items: [
        { id: 'ARCHITECTURE', label: 'Architecture.md', icon: '🏗️' },
        { id: 'DATABASE_DESIGN', label: 'Database ER.md', icon: '🗄️' },
        { id: 'API_SPEC', label: 'OpenAPI Spec.yaml', icon: '🔌' },
      ],
    },
    {
      name: 'Security & Compliance',
      items: [
        { id: 'THREAT_MODEL', label: 'STRIDE Model.md', icon: '🛡️' },
        { id: 'OWASP_REVIEW', label: 'OWASP Top 10.md', icon: '⚖️' },
      ],
    },
    {
      name: 'DevOps & Infrastructure',
      items: [
        { id: 'DOCKERFILE', label: 'Dockerfile', icon: '🐳' },
        { id: 'DOCKER_COMPOSE', label: 'docker-compose.yml', icon: '📦' },
        { id: 'KUBERNETES', label: 'deployment.yaml', icon: '☸️' },
        { id: 'TERRAFORM', label: 'main.tf', icon: '🏛️' },
        { id: 'GITHUB_ACTIONS', label: 'ci.yml', icon: '⚡' },
      ],
    },
  ];

  // Refresh generated documents list
  const refreshProjectDocs = useCallback(async () => {
    try {
      const docs = await generationService.listProjectDocuments(projectId);
      const map: Record<string, number> = {};
      docs.forEach((d) => {
        map[d.doc_type] = d.version;
      });
      setGeneratedMap(map);
    } catch {
      // Ignore initial empty list error
    }
  }, [projectId]);

  // Load document content & versions
  const loadDocument = useCallback(async (docType: string) => {
    try {
      const doc = await generationService.fetchDocument(projectId, docType);
      setDocumentContent(doc.content);
      const vers = await generationService.fetchDocumentVersions(projectId, docType);
      setVersions(vers);
    } catch {
      setDocumentContent(`> Document \`${docType}\` is not yet generated for **${projectName}**.\n\nClick **"⚡ Generate with AI"** above to stream security artifact generation.`);
      setVersions([]);
    }
    setCompareVersion(null);
    setIsDiffMode(false);
  }, [projectId, projectName]);

  useEffect(() => {
    refreshProjectDocs();
    loadDocument(activeTab);
  }, [activeTab, loadDocument, refreshProjectDocs]);

  useEffect(() => {
    if (isStreaming) {
      setDocumentContent(streamContent);
    }
  }, [isStreaming, streamContent]);

  const handleGenerate = (instructions?: string) => {
    setIsRegenModalOpen(false);
    startStream(projectId, {
      doc_type: activeTab,
      custom_instructions: instructions,
      provider: 'mock',
    }).then(() => {
      refreshProjectDocs();
      loadDocument(activeTab);
    });
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await generationService.saveDocument(projectId, activeTab, documentContent);
      setSaveSuccess(true);
      showToast('success', 'Document Saved', `Artifact ${activeTab} updated in database.`);
      setTimeout(() => setSaveSuccess(false), 2000);
      refreshProjectDocs();
      loadDocument(activeTab);
    } catch (err) {
      showToast('error', 'Save Failed', 'Could not persist document edits.');
      console.error(err);
    } finally {
      setIsSaving(false);
      setIsEditing(false);
    }
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans overflow-hidden">
      {/* Left File Explorer Sidebar */}
      <aside className="w-64 bg-slate-950 border-r border-slate-800/80 flex flex-col shrink-0">
        {/* Workspace Brand & Back Header */}
        <div className="h-14 px-4 flex items-center justify-between border-b border-slate-800/80">
          <button
            onClick={onBackToDashboard}
            className="text-xs text-slate-400 hover:text-white flex items-center gap-2 transition-colors font-medium"
          >
            <span>←</span>
            <span className="truncate max-w-[150px] font-bold text-white">{projectName}</span>
          </button>
          <Badge variant="indigo" size="sm">
            IDE
          </Badge>
        </div>

        {/* Categories File Tree */}
        <div className="flex-1 overflow-y-auto p-3 space-y-4 text-xs font-mono">
          {docCategories.map((cat) => (
            <div key={cat.name} className="space-y-1">
              <span className="text-[10px] uppercase tracking-wider text-slate-400 font-bold px-2">
                {cat.name}
              </span>
              <div className="space-y-0.5">
                {cat.items.map((item) => {
                  const isActive = activeTab === item.id;
                  const version = generatedMap[item.id];
                  return (
                    <button
                      key={item.id}
                      onClick={() => setActiveTab(item.id)}
                      className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg transition-all ${
                        isActive
                          ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 font-bold'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                      }`}
                    >
                      <div className="flex items-center gap-2 truncate">
                        <span>{item.icon}</span>
                        <span className="truncate">{item.label}</span>
                      </div>
                      {version ? (
                        <span className="px-1.5 py-0.2 rounded text-[9px] bg-slate-900 text-emerald-400 border border-slate-800">
                          v{version}
                        </span>
                      ) : (
                        <span className="w-1.5 h-1.5 rounded-full bg-slate-700" />
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Sidebar Status Footer */}
        <div className="p-3 border-t border-slate-800/80 bg-slate-900/40 text-[10px] font-mono text-slate-400 flex items-center justify-between">
          <span>Active: {activeTab}</span>
          <span className="text-emerald-400">13 Artifacts Scope</span>
        </div>
      </aside>

      {/* Main Workspace Column */}
      <div className="flex flex-col flex-1 overflow-hidden relative">
        {/* Top Actions & Controls Bar */}
        <header className="h-14 bg-slate-950/80 border-b border-slate-800/80 px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-slate-400">
              Artifact: <span className="text-white font-bold">{activeTab}</span>
            </span>
            {versions.length > 0 && (
              <Badge variant="indigo" size="sm">
                Latest: v{versions[0]?.version || 1}
              </Badge>
            )}
            {isStreaming && (
              <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                Streaming Tokens...
              </span>
            )}
          </div>

          <div className="flex items-center gap-3">
            {saveSuccess && (
              <span className="text-xs text-emerald-400 font-mono animate-pulse">✓ Saved to DB</span>
            )}

            {/* Version History Drawer Trigger */}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsVersionPanelOpen(!isVersionPanelOpen)}
            >
              📜 History ({versions.length})
            </Button>

            {/* Diff View Toggle */}
            {versions.length > 1 && (
              <Button
                variant={isDiffMode ? 'emerald' : 'ghost'}
                size="sm"
                onClick={() => setIsDiffMode(!isDiffMode)}
              >
                {isDiffMode ? 'Exit Diff Mode' : '🔍 Compare Versions'}
              </Button>
            )}

            {/* Edit / Preview Toggle */}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsEditing(!isEditing)}
              disabled={isStreaming}
            >
              {isEditing ? 'Preview Mode' : '✏️ Edit'}
            </Button>

            {isEditing && (
              <Button variant="emerald" size="sm" onClick={handleSave} disabled={isSaving}>
                {isSaving ? 'Saving...' : 'Save Edits'}
              </Button>
            )}

            {/* Export Package Button */}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsExportModalOpen(true)}
              icon={<span>📦</span>}
            >
              Export
            </Button>

            {/* Regenerate Single Document Button */}
            <Button
              variant="emerald"
              size="sm"
              onClick={() => setIsRegenModalOpen(true)}
              disabled={isStreaming}
              icon={<span>⚡</span>}
            >
              Regenerate
            </Button>
          </div>
        </header>

        {/* Content Viewer / Editor / Split-Screen Diff */}
        <main className="flex-1 overflow-y-auto p-6 bg-slate-950">
          {isDiffMode && compareVersion ? (
            /* Split-Screen Diff View */
            <div className="grid grid-cols-2 gap-6 h-full min-h-[550px]">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col">
                <div className="pb-2 border-b border-slate-800 mb-3 flex items-center justify-between">
                  <span className="text-xs font-mono text-emerald-400">
                    Current Version (v{versions[0]?.version})
                  </span>
                </div>
                <pre className="font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed overflow-y-auto flex-1">
                  {documentContent}
                </pre>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col">
                <div className="pb-2 border-b border-slate-800 mb-3 flex items-center justify-between">
                  <span className="text-xs font-mono text-indigo-400">
                    Comparison Version (v{compareVersion.version})
                  </span>
                </div>
                <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed overflow-y-auto flex-1">
                  {compareVersion.content}
                </pre>
              </div>
            </div>
          ) : (
            /* Single Document View / Editor */
            <div className="max-w-5xl mx-auto min-h-[550px] flex flex-col">
              {documentContent.includes('is not yet generated') ? (
                <EmptyState
                  icon="🛡️"
                  title={`Artifact ${activeTab} Not Generated`}
                  description={`The ${activeTab} security specification is not yet compiled for ${projectName}.`}
                  actionLabel="⚡ Generate with AI"
                  onAction={() => handleGenerate()}
                  className="my-auto"
                />
              ) : isEditing ? (
                <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 space-y-3 flex-1 flex flex-col">
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span>Editing Artifact: {activeTab}</span>
                    <Badge variant={autosaveStatus === 'saved' ? 'emerald' : 'amber'} size="sm" pulse={autosaveStatus === 'saving'}>
                      {autosaveStatus === 'saving' ? 'Autosaving in 1.5s...' : autosaveStatus === 'saved' ? 'Autosaved to DB' : 'Unsaved edits'}
                    </Badge>
                  </div>
                  <textarea
                    value={documentContent}
                    onChange={(e) => {
                      setDocumentContent(e.target.value);
                      setAutosaveStatus('saving');
                    }}
                    rows={22}
                    className="w-full flex-1 bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500 leading-relaxed resize-none"
                  />
                </div>
              ) : (
                <CodeViewer content={documentContent} language={getLanguageForTab(activeTab)} />
              )}
            </div>
          )}
        </main>
      </div>

      {/* Dockable AI Copilot Panel */}
      <CopilotPanel
        projectId={projectId}
        projectName={projectName}
        activeDocType={activeTab}
        currentDocContent={documentContent}
      />

      {/* Version History Drawer / Panel */}
      {isVersionPanelOpen && (
        <aside className="w-80 bg-slate-900 border-l border-slate-800 p-4 space-y-4 z-40 overflow-y-auto">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-xs font-bold text-white font-mono">Version Snapshot History</h3>
            <button
              onClick={() => setIsVersionPanelOpen(false)}
              className="text-slate-400 hover:text-white text-xs"
            >
              ✕
            </button>
          </div>

          <div className="space-y-2">
            {versions.map((ver) => (
              <div
                key={ver.id}
                className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <span className="text-indigo-300 font-bold">Version v{ver.version}</span>
                  {ver.is_latest && <Badge variant="emerald" size="sm">Current</Badge>}
                </div>
                <p className="text-[10px] text-slate-500">
                  Created: {new Date(ver.created_at).toLocaleString()}
                </p>
                <div className="pt-1 flex items-center gap-2">
                  <button
                    onClick={() => {
                      setDocumentContent(ver.content);
                      setIsVersionPanelOpen(false);
                    }}
                    className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-[10px] text-slate-300 rounded border border-slate-800"
                  >
                    Restore
                  </button>
                  <button
                    onClick={() => {
                      setCompareVersion(ver);
                      setIsDiffMode(true);
                      setIsVersionPanelOpen(false);
                    }}
                    className="px-2 py-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-[10px] text-indigo-300 rounded border border-indigo-500/30"
                  >
                    Compare Diff
                  </button>
                </div>
              </div>
            ))}
          </div>
        </aside>
      )}

      {/* Single Document Regeneration Modal */}
      <Dialog
        isOpen={isRegenModalOpen}
        onClose={() => setIsRegenModalOpen(false)}
        title={`Regenerate Security Artifact: ${activeTab}`}
        description="Provide optional custom instructions to refine the AI security generation engine output."
      >
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Custom AI Prompt Refinements / Security Directives
            </label>
            <textarea
              rows={4}
              value={customInstructions}
              onChange={(e) => setCustomInstructions(e.target.value)}
              placeholder="e.g. Focus on OAuth 2.0 PKCE flows, add AWS KMS encryption rules, or enforce PCI-DSS v4.0 audit logging..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
            />
          </div>
          <div className="pt-2 flex justify-end gap-3 border-t border-slate-800">
            <Button variant="ghost" size="sm" onClick={() => setIsRegenModalOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="emerald"
              size="sm"
              onClick={() => handleGenerate(customInstructions)}
              icon={<span>⚡</span>}
            >
              Regenerate Document
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Package Export Modal */}
      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        projectId={projectId}
        projectName={projectName}
      />
    </div>
  );
}
