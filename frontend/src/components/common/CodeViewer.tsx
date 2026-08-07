import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { useToast } from '../../hooks/useToast';

export interface CodeViewerProps {
  content: string;
  language?: string;
  showLineNumbers?: boolean;
}

export function CodeViewer({ content, language = 'markdown', showLineNumbers = true }: CodeViewerProps) {
  const { showToast } = useToast();
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    showToast('info', 'Copied to Clipboard', 'Content snippet copied.');
    setTimeout(() => setCopied(false), 2000);
  };

  const lines = content.split('\n');

  // Simple token highlighter for high-contrast presentation
  const renderHighlightedLine = (line: string) => {
    if (!line.trim()) return <span>&nbsp;</span>;

    // Headers (#, ##, ###)
    if (line.startsWith('#')) {
      return <span className="text-indigo-300 font-bold">{line}</span>;
    }
    // Comments (# or // or --)
    if (line.trim().startsWith('#') || line.trim().startsWith('//') || line.trim().startsWith('--')) {
      return <span className="text-slate-400 italic">{line}</span>;
    }
    // Key-value pairs (YAML/JSON/Terraform keys: value)
    if (line.includes(': ') && !line.startsWith('http')) {
      const parts = line.split(': ');
      return (
        <span>
          <span className="text-emerald-400 font-semibold">{parts[0]}: </span>
          <span className="text-slate-200">{parts.slice(1).join(': ')}</span>
        </span>
      );
    }
    // Code fences
    if (line.startsWith('```')) {
      return <span className="text-cyan-400 font-mono">{line}</span>;
    }
    // Lists (- or *)
    if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
      return (
        <span>
          <span className="text-indigo-400 font-bold">{line.substring(0, line.indexOf(line.trim().charAt(0)) + 2)}</span>
          <span className="text-slate-200">{line.substring(line.indexOf(line.trim().charAt(0)) + 2)}</span>
        </span>
      );
    }

    return <span className="text-slate-200">{line}</span>;
  };

  return (
    <div className="relative group bg-slate-950 border border-slate-800/90 rounded-xl overflow-hidden shadow-2xl font-mono text-xs backdrop-blur-md">
      {/* Soft Top Gradient Overlay */}
      <div className="absolute top-0 inset-x-0 h-1 bg-gradient-to-r from-indigo-500/40 via-cyan-500/40 to-indigo-500/40 pointer-events-none" />

      {/* Code Header Bar */}
      <div className="bg-slate-900/95 border-b border-slate-800 px-4 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-rose-500/60" />
          <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
          <span className="ml-2 text-[10px] uppercase tracking-wider text-indigo-300 font-bold px-2 py-0.5 rounded bg-indigo-950/80 border border-indigo-500/30 shadow-sm shadow-indigo-500/20">
            {language}
          </span>
        </div>

        <button
          onClick={handleCopy}
          className="px-2.5 py-1 rounded-md bg-slate-800/90 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] transition-all duration-200 flex items-center gap-1.5 border border-slate-700/80 hover:border-indigo-500/40 cursor-pointer active:scale-95"
        >
          {copied ? (
            <Check className="w-3 h-3 text-emerald-400 animate-in fade-in zoom-in duration-150" />
          ) : (
            <Copy className="w-3 h-3 text-slate-400 group-hover:text-indigo-400 transition-colors" />
          )}
          <span className={copied ? 'text-emerald-400 font-bold' : ''}>{copied ? 'Copied!' : 'Copy Code'}</span>
        </button>
      </div>

      {/* Code Body Area */}
      <div className="p-4 overflow-x-auto leading-relaxed max-h-[600px] overflow-y-auto font-mono scrollbar-thin">
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line, idx) => (
              <tr key={idx} className="hover:bg-indigo-950/20 transition-colors duration-150 rounded">
                {showLineNumbers && (
                  <td className="pr-4 text-right select-none text-slate-500 text-[10px] w-8 font-mono border-r border-slate-800/60">
                    {idx + 1}
                  </td>
                )}
                <td className="pl-4 whitespace-pre">
                  {renderHighlightedLine(line)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
