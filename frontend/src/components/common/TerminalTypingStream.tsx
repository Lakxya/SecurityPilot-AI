import { useState, useEffect } from 'react';
import { Terminal, CheckCircle2 } from 'lucide-react';

export interface TerminalTypingStreamProps {
  logs?: string[];
  title?: string;
  className?: string;
}

const DEFAULT_LOGS = [
  'Initializing SecurityPilotAI Autonomous Engine v0.11.4...',
  'Connecting to Enterprise Encrypted BYOK Vault...',
  'Evaluating STRIDE threat vectors across API endpoints...',
  'Enforcing TLS 1.3 with AES-256-GCM cipher suite...',
  'Validating OWASP Top 10 A01, A03, A07 compliance rules...',
  'Generating hardened Terraform HCL & Kubernetes Helm charts...',
  'Security audit completed cleanly. Zero vulnerabilities found.',
];

export function TerminalTypingStream({
  logs = DEFAULT_LOGS,
  title = 'securitypilot-audit.log',
  className = '',
}: TerminalTypingStreamProps) {
  const [displayedLines, setDisplayedLines] = useState<string[]>([]);
  const [currentLineIndex, setCurrentLineIndex] = useState(0);
  const [currentCharIndex, setCurrentCharIndex] = useState(0);

  useEffect(() => {
    // Respect prefers-reduced-motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setDisplayedLines(logs);
      return;
    }

    if (currentLineIndex >= logs.length) return;

    const targetLine = logs[currentLineIndex];

    if (currentCharIndex < targetLine.length) {
      const timeout = setTimeout(() => {
        setDisplayedLines((prev) => {
          const next = [...prev];
          next[currentLineIndex] = targetLine.substring(0, currentCharIndex + 1);
          return next;
        });
        setCurrentCharIndex((c) => c + 1);
      }, 18);

      return () => clearTimeout(timeout);
    } else {
      const nextLineTimeout = setTimeout(() => {
        setCurrentLineIndex((l) => l + 1);
        setCurrentCharIndex(0);
      }, 250);

      return () => clearTimeout(nextLineTimeout);
    }
  }, [currentLineIndex, currentCharIndex, logs]);

  return (
    <div className={`bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl font-mono text-xs ${className}`}>
      {/* Terminal Title Bar */}
      <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
          <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
          <span className="ml-2 text-[10px] text-slate-400 font-bold flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-indigo-400" />
            <span>{title}</span>
          </span>
        </div>
        <span className="text-[9px] text-emerald-400 font-bold animate-pulse">● LIVE AUDIT</span>
      </div>

      {/* Terminal Body */}
      <div className="p-4 space-y-1.5 max-h-64 overflow-y-auto leading-relaxed text-slate-300">
        {displayedLines.map((line, idx) => (
          <div key={idx} className="flex items-start gap-2">
            <span className="text-indigo-400 select-none">$</span>
            <span className="flex-1">
              {line}
              {idx === currentLineIndex && currentLineIndex < logs.length && (
                <span className="inline-block w-2 h-4 ml-0.5 bg-emerald-400 animate-pulse align-middle" />
              )}
            </span>
            {idx < currentLineIndex && (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
