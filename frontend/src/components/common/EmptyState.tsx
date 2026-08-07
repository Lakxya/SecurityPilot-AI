import React from 'react';
import { ShieldCheck, Zap } from 'lucide-react';
import { Button } from '../ui/Button';

export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  secondaryHint?: string;
  className?: string;
}

export function EmptyState({
  icon = <ShieldCheck className="w-7 h-7 text-indigo-400" />,
  title,
  description,
  actionLabel,
  onAction,
  secondaryHint = 'Tip: Select connected BYOK model or AI Vault provider to accelerate stream generation.',
  className = '',
}: EmptyStateProps) {
  return (
    <div
      className={`bg-slate-900/50 border border-slate-800/90 backdrop-blur-xl rounded-2xl p-8 sm:p-12 text-center flex flex-col items-center justify-center space-y-4 max-w-lg mx-auto shadow-2xl ${className}`}
    >
      <div className="w-16 h-16 rounded-2xl bg-indigo-600/10 border border-indigo-500/30 text-indigo-400 flex items-center justify-center shadow-inner relative group">
        <div className="absolute inset-0 rounded-2xl bg-indigo-500/10 blur-md group-hover:blur-lg transition-all" />
        <span className="relative z-10">{icon}</span>
      </div>

      <div className="space-y-1.5 max-w-sm">
        <h3 className="text-base font-bold text-white tracking-tight">{title}</h3>
        <p className="text-xs text-slate-400 leading-relaxed font-sans">{description}</p>
      </div>

      {actionLabel && onAction && (
        <div className="pt-2 flex flex-col items-center gap-2">
          <Button variant="emerald" size="sm" onClick={onAction} icon={<Zap className="w-3.5 h-3.5" />}>
            {actionLabel}
          </Button>

          {secondaryHint && (
            <span className="text-[10px] font-mono text-slate-500 bg-slate-950 px-2.5 py-1 rounded-full border border-slate-800 max-w-xs truncate">
              {secondaryHint}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
