import { useState, useEffect } from 'react';
import { CheckCircle2, Zap, Circle } from 'lucide-react';
import { Badge } from '../common/Badge';

export interface GenerationTimelineProps {
  isStreaming: boolean;
  artifact: string;
}

const TIMELINE_STEPS = [
  'Reading Project Specs',
  'Checking Tech Stack',
  'Selecting Provider Assignment',
  'Generating Security Artifact',
  'Reviewing STRIDE & OWASP Risk',
  'Final Validation',
];

export function GenerationTimeline({ isStreaming, artifact }: GenerationTimelineProps) {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  useEffect(() => {
    if (!isStreaming) {
      setCurrentStepIndex(TIMELINE_STEPS.length - 1);
      return;
    }

    setCurrentStepIndex(0);
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < TIMELINE_STEPS.length - 1 ? prev + 1 : prev));
    }, 700);

    return () => clearInterval(interval);
  }, [isStreaming]);

  const progressPercent = Math.round(((currentStepIndex + 1) / TIMELINE_STEPS.length) * 100);

  return (
    <div className="bg-slate-900/90 border border-slate-800/90 rounded-2xl p-5 space-y-4 font-mono text-xs backdrop-blur-xl shadow-2xl relative overflow-hidden">
      {/* Top Animated Progress Bar */}
      <div className="absolute top-0 inset-x-0 h-1 bg-slate-900">
        <div
          className="h-full bg-gradient-to-r from-indigo-500 via-cyan-400 to-emerald-400 transition-all duration-300 ease-out"
          style={{ width: `${isStreaming ? progressPercent : 100}%` }}
        />
      </div>

      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 pt-1">
        <div className="flex items-center gap-2">
          <Badge variant="indigo" size="sm" pulse={isStreaming}>
            {isStreaming ? 'AI Stream Pipeline Active' : 'Pipeline Complete'}
          </Badge>
          <span className="font-bold text-white tracking-tight">{artifact}</span>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-slate-400">
          <span>Progress: <strong className="text-emerald-400">{isStreaming ? `${progressPercent}%` : '100%'}</strong></span>
          <span>•</span>
          <span>Step {currentStepIndex + 1} / {TIMELINE_STEPS.length}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
        {TIMELINE_STEPS.map((step, idx) => {
          const isDone = idx < currentStepIndex || !isStreaming;
          const isCurrent = idx === currentStepIndex && isStreaming;

          return (
            <div
              key={step}
              className={`p-2.5 rounded-xl border text-[11px] flex items-center gap-2.5 transition-all duration-200 ${
                isDone
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300 font-medium'
                  : isCurrent
                  ? 'bg-indigo-600/20 border-indigo-500/60 text-indigo-200 animate-pulse font-bold shadow-md shadow-indigo-500/10'
                  : 'bg-slate-950/80 border-slate-800/80 text-slate-500'
              }`}
            >
              <span className="shrink-0">
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : isCurrent ? (
                  <Zap className="w-4 h-4 text-indigo-400 animate-bounce" />
                ) : (
                  <Circle className="w-4 h-4 text-slate-700" />
                )}
              </span>
              <span className="truncate">{step}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
