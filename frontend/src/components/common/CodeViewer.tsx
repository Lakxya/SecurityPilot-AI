import { useState } from 'react';
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
    <div className="relative group bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl font-mono text-xs">
      {/* Code Header Bar */}
      <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-slate-700" />
          <div className="w-2.5 h-2.5 rounded-full bg-slate-700" />
          <div className="w-2.5 h-2.5 rounded-full bg-slate-700" />
          <span className="ml-2 text-[10px] uppercase tracking-wider text-slate-400 font-bold">
            {language}
          </span>
        </div>

        <button
          onClick={handleCopy}
          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[10px] transition-colors flex items-center gap-1.5"
        >
          {copied ? '✓ Copied' : '📋 Copy Code'}
        </button>
      </div>

      {/* Code Body Area */}
      <div className="p-4 overflow-x-auto leading-relaxed max-h-[600px] overflow-y-auto font-mono">
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line, idx) => (
              <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
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
