import { useState } from 'react';
import { Copy, Check, CheckSquare, Square } from 'lucide-react';
import { useToast } from '../../hooks/useToast';

export interface RichMarkdownViewerProps {
  content: string;
  className?: string;
}

export function RichMarkdownViewer({ content, className = '' }: RichMarkdownViewerProps) {
  const { showToast } = useToast();
  const [copied, setCopied] = useState(false);

  const handleCopyAll = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    showToast('info', 'Copied to Clipboard', 'Full response copied.');
    setTimeout(() => setCopied(false), 2000);
  };

  const lines = content.split('\n');

  return (
    <div className={`font-mono text-xs text-slate-200 leading-relaxed space-y-2 selection:bg-indigo-500/30 ${className}`}>
      {/* Top Toolbar Action Header */}
      <div className="flex items-center justify-between bg-slate-900/60 border border-slate-800 rounded-lg px-3 py-1.5 text-[10px] text-slate-400">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>Markdown GFM Rendered</span>
        </div>
        <button
          onClick={handleCopyAll}
          className="hover:text-white flex items-center gap-1.5 font-bold transition-colors cursor-pointer"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied' : 'Copy Output'}</span>
        </button>
      </div>

      {/* Structured Code / Markdown Presentation */}
      <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-4 overflow-x-auto space-y-1">
        {lines.map((line, idx) => {
          if (line.startsWith('# ')) {
            return <h1 key={idx} className="text-base font-bold text-white pt-2 pb-1 border-b border-slate-800">{line.slice(2)}</h1>;
          } else if (line.startsWith('## ')) {
            return <h2 key={idx} className="text-sm font-bold text-indigo-300 pt-2">{line.slice(3)}</h2>;
          } else if (line.startsWith('### ')) {
            return <h3 key={idx} className="text-xs font-bold text-emerald-400 pt-1">{line.slice(4)}</h3>;
          } else if (line.startsWith('- [ ] ') || line.startsWith('- [x] ')) {
            const isChecked = line.startsWith('- [x] ');
            return (
              <div key={idx} className="flex items-center gap-2 pl-2 text-slate-300">
                {isChecked ? (
                  <CheckSquare className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                ) : (
                  <Square className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                )}
                <span>{line.slice(6)}</span>
              </div>
            );
          } else if (line.startsWith('> ')) {
            return (
              <blockquote key={idx} className="border-l-2 border-indigo-500 pl-3 py-1 bg-indigo-950/20 text-indigo-200 italic my-1 rounded-r">
                {line.slice(2)}
              </blockquote>
            );
          } else if (line.trim().startsWith('|')) {
            return (
              <div key={idx} className="bg-slate-900/40 font-mono text-[11px] text-slate-300 px-2 py-0.5 border-b border-slate-800/50">
                {line}
              </div>
            );
          } else {
            return (
              <p key={idx} className="text-slate-300 whitespace-pre-wrap">
                {line}
              </p>
            );
          }
        })}
      </div>
    </div>
  );
}
