import { CheckCircle2, AlertTriangle, Info, X } from 'lucide-react';
import { ToastMessage } from '../../context/ToastContext';

export interface ToastContainerProps {
  toasts: ToastMessage[];
  onRemove: (id: string) => void;
}

export function ToastContainer({ toasts, onRemove }: ToastContainerProps) {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2.5 max-w-sm w-full pointer-events-none font-sans">
      {toasts.map((toast) => {
        const borderVariant =
          toast.type === 'success'
            ? 'border-emerald-500/50 bg-emerald-950/90 text-emerald-100 shadow-emerald-900/20'
            : toast.type === 'error'
            ? 'border-rose-500/50 bg-rose-950/90 text-rose-100 shadow-rose-900/20'
            : 'border-indigo-500/50 bg-indigo-950/90 text-indigo-100 shadow-indigo-900/20';

        const icon =
          toast.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          ) : toast.type === 'error' ? (
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          ) : (
            <Info className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
          );

        return (
          <div
            key={toast.id}
            className={`pointer-events-auto p-3.5 rounded-xl border backdrop-blur-md shadow-2xl flex items-start justify-between gap-3 animate-in fade-in slide-in-from-bottom-4 transition-all ${borderVariant}`}
          >
            <div className="flex items-start gap-2.5">
              {icon}
              <div className="space-y-0.5">
                <h4 className="text-xs font-bold leading-tight">{toast.title}</h4>
                {toast.description && (
                  <p className="text-[11px] opacity-80 leading-relaxed font-mono">{toast.description}</p>
                )}
              </div>
            </div>

            <button
              onClick={() => onRemove(toast.id)}
              className="text-xs opacity-60 hover:opacity-100 transition-opacity p-0.5 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
