import { useState, useEffect } from 'react';
import { Brain, CheckCircle2, ShieldCheck, Zap, Circle } from 'lucide-react';
import { Badge } from './Badge';

export interface AIThinkingPipelineProps {
  isLoading: boolean;
  onComplete?: () => void;
  className?: string;
}

const PIPELINE_STEPS = [
  { id: 'context', label: 'Reading Context', desc: 'Analyzing project specs & architecture parameters' },
  { id: 'threat', label: 'Threat Modeling', desc: 'Evaluating STRIDE attack vectors & OWASP risks' },
  { id: 'provider', label: 'Selecting Provider', desc: 'Routing payload via BYOK AI Vault provider' },
  { id: 'blueprint', label: 'Generating Blueprint', desc: 'Streaming security specs & Terraform IaC modules' },
  { id: 'validation', label: 'Security Validation', desc: 'Running CVSS vulnerability scoring & compliance check' },
  { id: 'complete', label: 'Complete', desc: 'Artifact compiled cleanly with 0 high-risk vectors' },
];

export function AIThinkingPipeline({ isLoading, onComplete, className = '' }: AIThinkingPipelineProps) {
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    if (!isLoading) {
      setCurrentStep(PIPELINE_STEPS.length - 1);
      return;
    }

    setCurrentStep(0);
    const interval = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev < PIPELINE_STEPS.length - 1) {
          return prev + 1;
        } else {
          clearInterval(interval);
          if (onComplete) onComplete();
          return prev;
        }
      });
    }, 600);

    return () => clearInterval(interval);
  }, [isLoading, onComplete]);

  const progressPercent = Math.round(((currentStep + 1) / PIPELINE_STEPS.length) * 100);

  return (
    <div className={`bg-slate-900/90 border border-slate-800/90 backdrop-blur-xl rounded-2xl p-6 shadow-2xl font-sans space-y-5 ${className}`}>
      {/* Top Header & Progress Ring */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 flex items-center justify-center font-bold shrink-0 shadow-inner">
            <Brain className="w-5 h-5 text-indigo-400 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
              <span>AI Thinking Pipeline</span>
              <Badge variant="indigo" size="sm" pulse={isLoading}>
                {isLoading ? 'Active Pipeline' : 'Complete'}
              </Badge>
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Step {currentStep + 1} of {PIPELINE_STEPS.length}: {PIPELINE_STEPS[currentStep]?.label}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-slate-400">Progress:</span>
          <span className="text-emerald-400 font-bold text-sm">{progressPercent}%</span>
        </div>
      </div>

      {/* Pipeline Progress Steps List */}
      <div className="space-y-2.5">
        {PIPELINE_STEPS.map((step, idx) => {
          const isDone = idx < currentStep || !isLoading;
          const isCurrent = idx === currentStep && isLoading;

          return (
            <div
              key={step.id}
              className={`p-3 rounded-xl border transition-all duration-200 flex items-center justify-between ${
                isDone
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-slate-200'
                  : isCurrent
                  ? 'bg-indigo-600/20 border-indigo-500/60 text-white shadow-lg shadow-indigo-500/10 font-bold'
                  : 'bg-slate-950/60 border-slate-800/80 text-slate-500 opacity-60'
              }`}
            >
              <div className="flex items-center gap-3">
                <div className="shrink-0">
                  {isDone ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : isCurrent ? (
                    <Zap className="w-4 h-4 text-indigo-400 animate-bounce" />
                  ) : (
                    <Circle className="w-4 h-4 text-slate-700" />
                  )}
                </div>

                <div>
                  <p className="text-xs font-bold font-mono">{step.label}</p>
                  <p className="text-[11px] font-sans text-slate-400 leading-snug">{step.desc}</p>
                </div>
              </div>

              {isDone && (
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
