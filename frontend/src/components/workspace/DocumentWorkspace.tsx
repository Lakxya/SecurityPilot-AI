import { useState, useEffect, useCallback } from 'react';
import { Button } from '../ui/Button';
import { Badge } from '../common/Badge';
import { useSSEStream } from '../../hooks/useSSEStream';
import { generationService } from '../../services/generationService';

export interface DocumentWorkspaceProps {
  projectId: string;
  projectName: string;
  onBackToDashboard: () => void;
}

export function DocumentWorkspace({ projectId, projectName, onBackToDashboard }: DocumentWorkspaceProps) {
  const [activeTab, setActiveTab] = useState('README');
  const [documentContent, setDocumentContent] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const { isStreaming, streamContent, startStream } = useSSEStream();

  const docTabs = [
    { id: 'README', label: 'README.md', icon: '📄' },
    { id: 'SRS', label: 'SRS.md', icon: '📋' },
    { id: 'SDS', label: 'SDS.md', icon: '📐' },
    { id: 'ARCHITECTURE', label: 'Architecture', icon: '🏗️' },
    { id: 'DATABASE_DESIGN', label: 'Database ER', icon: '🗄️' },
    { id: 'API_SPEC', label: 'OpenAPI Spec', icon: '🔌' },
    { id: 'THREAT_MODEL', label: 'STRIDE Model', icon: '🛡️' },
    { id: 'OWASP_REVIEW', label: 'OWASP Top 10', icon: '⚖️' },
    { id: 'DOCKERFILE', label: 'Dockerfile', icon: '🐳' },
    { id: 'DOCKER_COMPOSE', label: 'docker-compose', icon: '📦' },
    { id: 'KUBERNETES', label: 'K8s Deployment', icon: '☸️' },
    { id: 'TERRAFORM', label: 'Terraform HCL', icon: '🏛️' },
    { id: 'GITHUB_ACTIONS', label: 'GitHub CI/CD', icon: '⚡' },
  ];

  const loadDocument = useCallback(async (docType: string) => {
    try {
      const doc = await generationService.fetchDocument(projectId, docType);
      setDocumentContent(doc.content);
    } catch {
      setDocumentContent(`> Document \`${docType}\` is not yet generated for **${projectName}**.\n\nClick **"⚡ Generate with AI"** above to stream security artifact generation.`);
    }
  }, [projectId, projectName]);

  useEffect(() => {
    loadDocument(activeTab);
  }, [activeTab, loadDocument]);

  useEffect(() => {
    if (isStreaming) {
      setDocumentContent(streamContent);
    }
  }, [isStreaming, streamContent]);

  const handleGenerate = () => {
    startStream(projectId, {
      doc_type: activeTab,
      provider: 'mock',
    });
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await generationService.saveDocument(projectId, activeTab, documentContent);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2000);
    } catch (err) {
      console.error(err);
    } finally {
      setIsSaving(false);
      setIsEditing(false);
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-100 font-sans overflow-hidden">
      {/* Top Controls Header */}
      <div className="h-14 bg-slate-900 border-b border-slate-800 px-6 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-4">
          <button
            onClick={onBackToDashboard}
            className="text-xs text-slate-400 hover:text-white flex items-center gap-1.5 transition-colors"
          >
            <span>←</span>
            <span>Dashboard</span>
          </button>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold text-white tracking-tight">{projectName}</span>
            <Badge variant="indigo" size="sm">
              Document Workspace
            </Badge>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {saveSuccess && (
            <span className="text-xs text-emerald-400 font-mono animate-pulse">✓ Saved to Database</span>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsEditing(!isEditing)}
            disabled={isStreaming}
          >
            {isEditing ? 'Preview Mode' : 'Edit Document'}
          </Button>
          {isEditing && (
            <Button
              variant="emerald"
              size="sm"
              onClick={handleSave}
              disabled={isSaving}
            >
              {isSaving ? 'Saving...' : 'Save Edits'}
            </Button>
          )}
          <Button
            variant="emerald"
            size="sm"
            onClick={handleGenerate}
            disabled={isStreaming}
            icon={<span className="text-xs">⚡</span>}
          >
            {isStreaming ? 'Streaming AI Tokens...' : 'Generate with AI'}
          </Button>
        </div>
      </div>

      {/* 13 Multi-Tab Navigation Rail */}
      <div className="bg-slate-950 border-b border-slate-800 px-4 flex items-center gap-1 overflow-x-auto shrink-0 scrollbar-none py-1.5">
        {docTabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-all shrink-0 ${
                isActive
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Editor & Viewer Pane */}
      <div className="flex-1 overflow-y-auto p-6 bg-slate-950">
        <div className="max-w-5xl mx-auto bg-slate-900/60 border border-slate-800 rounded-xl shadow-2xl overflow-hidden min-h-[500px] flex flex-col">
          {/* Header Banner */}
          <div className="px-6 py-3 bg-slate-900 border-b border-slate-800/80 flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">
              Artifact: <span className="text-indigo-400">{activeTab}</span>
            </span>
            {isStreaming && (
              <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                Live SSE Stream Engine Active
              </span>
            )}
          </div>

          {/* Content Body */}
          <div className="p-6 flex-1">
            {isEditing ? (
              <textarea
                value={documentContent}
                onChange={(e) => setDocumentContent(e.target.value)}
                rows={22}
                className="w-full h-full bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500 leading-relaxed resize-none"
              />
            ) : (
              <pre className="font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed overflow-x-auto">
                {documentContent}
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
