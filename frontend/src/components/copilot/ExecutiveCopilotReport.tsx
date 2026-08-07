import { useState } from 'react';
import { ShieldCheck, ChevronDown, ChevronUp, FileText, CheckCircle2 } from 'lucide-react';
import { SecurityScoreGauge } from '../common/SecurityScoreGauge';
import { StrideThreatGrid } from '../common/StrideThreatGrid';
import { SecurityRiskCard } from '../common/SecurityRiskCard';
import { FileChip } from '../common/FileChip';
import { Badge } from '../common/Badge';

export interface ExecutiveCopilotReportProps {
  content: string;
  onFileClick?: (filename: string) => void;
  className?: string;
}

export function ExecutiveCopilotReport({
  content,
  onFileClick,
  className = '',
}: ExecutiveCopilotReportProps) {
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    summary: true,
    stride: true,
    findings: true,
    code: true,
  });

  const toggleSection = (section: string) => {
    setOpenSections((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  // Detect file references in content string
  const knownFiles = [
    'README.md',
    'Dockerfile',
    'docker-compose.yml',
    'main.tf',
    'deployment.yaml',
    'ci.yml',
    'SRS.md',
    'SDS.md',
    'Architecture.md',
    'Database ER.md',
    'OpenAPI Spec.yaml',
    'OWASP Top 10.md',
    'STRIDE Model.md',
  ];

  const referencedFiles = knownFiles.filter((f) => content.includes(f));

  // Detect high risk keywords
  const hasRisk = content.toLowerCase().includes('cvss') || content.toLowerCase().includes('critical') || content.toLowerCase().includes('vulnerability');

  return (
    <div className={`space-y-4 font-sans ${className}`}>
      {/* Top Executive Summary Header Bar */}
      <div className="p-4 rounded-xl border border-indigo-500/30 bg-slate-900/80 backdrop-blur-md shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Badge variant="indigo" size="sm" icon={<ShieldCheck className="w-3.5 h-3.5" />}>
              Executive Security Audit Report
            </Badge>
            <Badge variant="emerald" size="sm">
              98% Verified
            </Badge>
          </div>
          <h3 className="text-base font-extrabold text-white tracking-tight">
            Security Architecture Audit & Mitigation Analysis
          </h3>
          <p className="text-xs text-slate-400 font-sans leading-relaxed">
            Automated compliance review evaluating encryption standards, STRIDE threat vectors, and OWASP Top 10 guidelines.
          </p>
        </div>

        {/* Circular Progress Gauge */}
        <SecurityScoreGauge score={hasRisk ? 78 : 95} size={90} className="shrink-0 mx-auto sm:mx-0" />
      </div>

      {/* Referenced File Chips Bar */}
      {referencedFiles.length > 0 && (
        <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/80 flex items-center gap-2 overflow-x-auto">
          <span className="text-[11px] font-mono text-slate-400 font-bold shrink-0 flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-indigo-400" />
            <span>Referenced Artifacts:</span>
          </span>
          <div className="flex items-center gap-2">
            {referencedFiles.map((file) => (
              <FileChip key={file} fileName={file} onClick={onFileClick} />
            ))}
          </div>
        </div>
      )}

      {/* Section 1: Executive Summary */}
      <div className="rounded-xl border border-slate-800/90 bg-slate-900/60 backdrop-blur-md overflow-hidden">
        <button
          onClick={() => toggleSection('summary')}
          className="w-full p-3.5 bg-slate-950/80 border-b border-slate-800/80 flex items-center justify-between text-xs font-mono font-bold text-white cursor-pointer hover:bg-slate-900 transition-colors"
        >
          <span className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Executive Summary & Security Scope</span>
          </span>
          {openSections.summary ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </button>

        {openSections.summary && (
          <div className="p-4 text-xs text-slate-300 leading-relaxed font-sans space-y-2">
            <p>
              This report compiles verified architectural mitigations for payment, auth, and database persistence layers. All cryptographic keys are encrypted at rest using AES-256-GCM credentials stored in the AI Vault.
            </p>
          </div>
        )}
      </div>

      {/* Section 2: STRIDE Threat Model Overview */}
      <div className="rounded-xl border border-slate-800/90 bg-slate-900/60 backdrop-blur-md overflow-hidden">
        <button
          onClick={() => toggleSection('stride')}
          className="w-full p-3.5 bg-slate-950/80 border-b border-slate-800/80 flex items-center justify-between text-xs font-mono font-bold text-white cursor-pointer hover:bg-slate-900 transition-colors"
        >
          <span className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-indigo-400" />
            <span>STRIDE Threat Vectors Analysis</span>
          </span>
          {openSections.stride ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </button>

        {openSections.stride && (
          <div className="p-4">
            <StrideThreatGrid />
          </div>
        )}
      </div>

      {/* Section 3: Risk Finding Cards (If Risk Detected) */}
      {hasRisk && (
        <div className="rounded-xl border border-slate-800/90 bg-slate-900/60 backdrop-blur-md overflow-hidden">
          <button
            onClick={() => toggleSection('findings')}
            className="w-full p-3.5 bg-slate-950/80 border-b border-slate-800/80 flex items-center justify-between text-xs font-mono font-bold text-white cursor-pointer hover:bg-slate-900 transition-colors"
          >
            <span className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-rose-400" />
              <span>Vulnerability Findings & CVSS Ratings</span>
            </span>
            {openSections.findings ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
          </button>

          {openSections.findings && (
            <div className="p-4">
              <SecurityRiskCard
                title="Critical Vector: Unencrypted Transit Payload in Callback Hook"
                cvssScore={9.8}
                likelihoodPercent={90}
                impactPercent={95}
                status="Needs Immediate Action"
                description="Payment notification webhook endpoint accepts unauthenticated POST requests over plain HTTP without signature validation."
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
