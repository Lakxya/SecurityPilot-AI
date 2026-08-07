import { useState, useEffect } from 'react';
import { Badge } from '../common/Badge';

export interface GenerationTimelineProps {
  isStreaming: boolean;
  artifact: string;
}

const TIMELINE_STEPS = [
  'Reading Project Blueprint',
  'Understanding Requirements',
  'Building Context Vectors',
  'Selecting AI Providers',
  'Generating Parallel Streams',
  'Compliance Validation',
  'Comparative Security Review',
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
    }, 800);

    return () => clearInterval(interval);
  }, [isStreaming]);

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs backdrop-blur-md shadow-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center gap-2">
          <Badge variant="indigo" size="sm" pulse={isStreaming}>
            {isStreaming ? 'Streaming AI Pipeline' : 'Stream Complete'}
          </Badge>
          <span className="font-bold text-white tracking-tight">{artifact}</span>
        </div>
        <span className="text-[10px] text-slate-400">
          Step {currentStepIndex + 1} of {TIMELINE_STEPS.length}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-1">
        {TIMELINE_STEPS.map((step, idx) => {
          const isDone = idx < currentStepIndex || !isStreaming;
          const isCurrent = idx === currentStepIndex && isStreaming;

          return (
            <div
              key={step}
              className={`p-2 rounded-lg border text-[10px] flex items-center gap-2 transition-all ${
                isDone
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                  : isCurrent
                  ? 'bg-indigo-600/20 border-indigo-500/50 text-indigo-200 animate-pulse font-bold'
                  : 'bg-slate-950 border-slate-850 text-slate-500'
              }`}
            >
              <span>{isDone ? '✓' : isCurrent ? '⚡' : '○'}</span>
              <span className="truncate">{step}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
