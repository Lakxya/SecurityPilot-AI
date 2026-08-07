import { FileText, Container, Package, Boxes, Building2, Zap, Plug } from 'lucide-react';

export interface FileChipProps {
  fileName: string;
  onClick?: (filename: string) => void;
  className?: string;
}

export function FileChip({ fileName, onClick, className = '' }: FileChipProps) {
  const getFileIcon = (name: string) => {
    const lower = name.toLowerCase();
    if (lower.includes('dockerfile')) {
      return <Container className="w-3.5 h-3.5 text-blue-400" />;
    }
    if (lower.includes('docker-compose') || lower.endsWith('.yml') || lower.endsWith('.yaml')) {
      if (lower.includes('ci') || lower.includes('github')) {
        return <Zap className="w-3.5 h-3.5 text-emerald-400" />;
      }
      if (lower.includes('openapi') || lower.includes('api')) {
        return <Plug className="w-3.5 h-3.5 text-cyan-400" />;
      }
      return <Package className="w-3.5 h-3.5 text-indigo-400" />;
    }
    if (lower.includes('deployment') || lower.includes('k8s') || lower.includes('kubernetes')) {
      return <Boxes className="w-3.5 h-3.5 text-cyan-400" />;
    }
    if (lower.endsWith('.tf') || lower.includes('terraform')) {
      return <Building2 className="w-3.5 h-3.5 text-amber-400" />;
    }
    return <FileText className="w-3.5 h-3.5 text-indigo-400" />;
  };

  return (
    <button
      onClick={() => onClick && onClick(fileName)}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-indigo-500/40 text-xs font-mono text-slate-200 transition-all duration-150 cursor-pointer active:scale-95 group shadow-sm ${className}`}
    >
      <span className="shrink-0 group-hover:scale-110 transition-transform">{getFileIcon(fileName)}</span>
      <span className="font-bold tracking-tight text-white group-hover:text-indigo-300 transition-colors">
        {fileName}
      </span>
    </button>
  );
}
