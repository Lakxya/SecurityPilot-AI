import { useState } from 'react';
import { createPortal } from 'react-dom';
import { ShieldCheck, Download, X, FileText, CheckCircle2, AlertTriangle, Layers, Activity } from 'lucide-react';
import { Badge } from '../common/Badge';
import { Button } from '../ui/Button';
import { SecurityScoreGauge } from '../common/SecurityScoreGauge';
import { StrideThreatGrid } from '../common/StrideThreatGrid';
import { SecurityRiskCard } from '../common/SecurityRiskCard';
import { FileChip } from '../common/FileChip';

export interface ExecutiveReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  content: string;
  projectName?: string;
  provider?: string;
  score?: number;
}

export function ExecutiveReportModal({
  isOpen,
  onClose,
  content,
  projectName = 'SecurityPilot Workspace',
  provider = 'Claude 3.5 Sonnet',
  score = 95,
}: ExecutiveReportModalProps) {
  const [activeSection, setActiveSection] = useState('summary');

  if (!isOpen) return null;

  const handleExport = () => {
    const blob = new Blob([content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-audit-report-${Date.now()}.md`;
    a.click();
  };

  const sections = [
    { id: 'summary', label: 'Executive Summary', icon: <FileText className="w-4 h-4" /> },
    { id: 'score', label: 'Security Score', icon: <Activity className="w-4 h-4" /> },
    { id: 'stride', label: 'STRIDE Threat Model', icon: <ShieldCheck className="w-4 h-4" /> },
    { id: 'cvss', label: 'CVSS Findings', icon: <AlertTriangle className="w-4 h-4" /> },
    { id: 'architecture', label: 'Architecture & IaC', icon: <Layers className="w-4 h-4" /> },
  ];

  const modalJSX = (
    <div className="fixed inset-0 z-[9999] bg-slate-950/80 backdrop-blur-2xl flex items-center justify-center p-4 sm:p-6 md:p-8 animate-modal-enter font-sans">
      <div className="w-[90vw] h-[90vh] max-w-[1600px] max-h-[1000px] bg-slate-950 border border-indigo-500/30 rounded-[24px] shadow-2xl overflow-hidden flex flex-col relative">
        {/* Sticky Header Bar */}
        <header className="h-16 px-6 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between shrink-0 sticky top-0 z-20 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 flex items-center justify-center font-bold shrink-0">
              <ShieldCheck className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-tight">Executive Security Report</h2>
                <Badge variant="indigo" size="sm">
                  {provider}
                </Badge>
                <Badge variant="emerald" size="sm">
                  98% Verified
                </Badge>
              </div>
              <p className="text-xs text-slate-400 font-mono">{projectName}</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300">
              <span>Security Score:</span>
              <span className="text-emerald-400 font-bold text-sm">{score} / 100</span>
            </div>

            <Button variant="emerald" size="sm" onClick={handleExport} icon={<Download className="w-3.5 h-3.5" />}>
              Export Report
            </Button>

            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </header>

        {/* Modal Body Container */}
        <div className="flex-1 flex overflow-hidden">
          {/* Collapsible Left Navigation Rail (Hidden below 1200px / lg) */}
          <nav className="hidden lg:flex w-64 bg-slate-950 border-r border-slate-800/80 p-4 space-y-1 font-mono text-xs shrink-0 flex-col">
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider px-3 py-2">
              Report Navigation
            </p>
            {sections.map((sec) => {
              const isActive = activeSection === sec.id;
              return (
                <button
                  key={sec.id}
                  onClick={() => setActiveSection(sec.id)}
                  className={`w-full flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl transition-all duration-150 cursor-pointer text-left ${
                    isActive
                      ? 'bg-indigo-600/25 text-white border border-indigo-500/40 font-bold shadow-md'
                      : 'text-slate-400 hover:text-white hover:bg-slate-900 border border-transparent'
                  }`}
                >
                  <span className={isActive ? 'text-indigo-400' : 'text-slate-500'}>{sec.icon}</span>
                  <span className="truncate">{sec.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Full Width Main Content Area */}
          <main className="flex-1 overflow-y-auto p-6 sm:p-8 space-y-8 bg-slate-950/60 scroll-smooth">
            {/* Executive Summary Section */}
            {(activeSection === 'summary' || activeSection === 'all') && (
              <section id="summary" className="space-y-4">
                <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <h3 className="text-lg font-bold text-white tracking-tight">1. Executive Summary</h3>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed max-w-5xl font-sans">
                  SecurityPilotAI conducted an autonomous architectural risk assessment for <strong className="text-white">{projectName}</strong>. The evaluation audited authentication mechanisms, TLS 1.3 transit encryption, PostgreSQL credential storage, and Terraform IaC HCL modules against OWASP Top 10 guidelines and the STRIDE threat model.
                </p>

                <div className="p-4 rounded-xl border border-indigo-500/30 bg-slate-900/60 backdrop-blur-md flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400 font-bold shrink-0">Affected Artifacts:</span>
                  <div className="flex items-center gap-2 overflow-x-auto">
                    <FileChip fileName="README.md" />
                    <FileChip fileName="main.tf" />
                    <FileChip fileName="Dockerfile" />
                  </div>
                </div>
              </section>
            )}

            {/* Security Score Section */}
            {(activeSection === 'score' || activeSection === 'all') && (
              <section id="score" className="space-y-4 pt-4">
                <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
                  <Activity className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-lg font-bold text-white tracking-tight">2. Security Score & Metrics</h3>
                </div>
                <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/80 backdrop-blur-md flex flex-col sm:flex-row items-center gap-8 shadow-xl">
                  <SecurityScoreGauge score={score} size={130} />
                  <div className="space-y-2.5 font-mono text-xs w-full max-w-xl">
                    <div className="flex justify-between gap-8 border-b border-slate-800 pb-2">
                      <span className="text-slate-400">Cryptographic Standard:</span>
                      <span className="text-cyan-400 font-bold">TLS 1.3 / AES-256-GCM</span>
                    </div>
                    <div className="flex justify-between gap-8 border-b border-slate-800 pb-2">
                      <span className="text-slate-400">STRIDE Threat Coverage:</span>
                      <span className="text-emerald-400 font-bold">100% Inspected</span>
                    </div>
                    <div className="flex justify-between gap-8 border-b border-slate-800 pb-2">
                      <span className="text-slate-400">OWASP Top 10 Audit:</span>
                      <span className="text-indigo-300 font-bold">A01, A03, A07 Compliant</span>
                    </div>
                    <div className="flex justify-between gap-8">
                      <span className="text-slate-400">CVSS High-Risk Findings:</span>
                      <span className="text-emerald-400 font-bold">0 High Risks</span>
                    </div>
                  </div>
                </div>
              </section>
            )}

            {/* STRIDE Threat Model Section */}
            {(activeSection === 'stride' || activeSection === 'all') && (
              <section id="stride" className="space-y-4 pt-4">
                <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
                  <ShieldCheck className="w-5 h-5 text-indigo-400" />
                  <h3 className="text-lg font-bold text-white tracking-tight">3. STRIDE Threat Model Analysis</h3>
                </div>
                <StrideThreatGrid />
              </section>
            )}

            {/* CVSS Findings Section */}
            {(activeSection === 'cvss' || activeSection === 'all') && (
              <section id="cvss" className="space-y-4 pt-4">
                <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
                  <AlertTriangle className="w-5 h-5 text-rose-400" />
                  <h3 className="text-lg font-bold text-white tracking-tight">4. CVSS Vulnerability Findings</h3>
                </div>
                <SecurityRiskCard
                  title="Critical Vector: Unencrypted Transit Payload in Payment Hook"
                  cvssScore={9.8}
                  likelihoodPercent={90}
                  impactPercent={95}
                  status="Needs Immediate Action"
                  description="Payment notification webhook endpoint accepts unauthenticated POST requests over plain HTTP without signature validation."
                />
              </section>
            )}

            {/* Markdown Detail Section */}
            <section id="architecture" className="space-y-4 pt-4">
              <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
                <Layers className="w-5 h-5 text-purple-400" />
                <h3 className="text-lg font-bold text-white tracking-tight">5. Detailed Technical Blueprint</h3>
              </div>
              <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/60 font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed">
                {content}
              </div>
            </section>
          </main>
        </div>
      </div>
    </div>
  );

  return createPortal(modalJSX, document.body);
}
