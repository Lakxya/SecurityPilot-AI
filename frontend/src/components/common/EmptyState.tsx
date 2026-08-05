import { Button } from '../ui/Button';

export interface EmptyStateProps {
  icon?: string;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export function EmptyState({
  icon = '🛡️',
  title,
  description,
  actionLabel,
  onAction,
  className = '',
}: EmptyStateProps) {
  return (
    <div
      className={`bg-slate-900/40 border border-slate-800/80 backdrop-blur-md rounded-xl p-8 sm:p-12 text-center flex flex-col items-center justify-center space-y-4 max-w-lg mx-auto ${className}`}
    >
      <div className="w-14 h-14 rounded-2xl bg-indigo-600/10 border border-indigo-500/20 text-indigo-400 flex items-center justify-center text-2xl shadow-inner">
        {icon}
      </div>

      <div className="space-y-1 max-w-sm">
        <h3 className="text-base font-bold text-white tracking-tight">{title}</h3>
        <p className="text-xs text-slate-400 leading-relaxed font-sans">{description}</p>
      </div>

      {actionLabel && onAction && (
        <div className="pt-2">
          <Button variant="emerald" size="sm" onClick={onAction} icon={<span>⚡</span>}>
            {actionLabel}
          </Button>
        </div>
      )}
    </div>
  );
}
