import { useState, useEffect } from 'react';
import { Badge } from '../common/Badge';
import { Button } from '../ui/Button';
import { recommendationService, ModelRecommendation } from '../../services/recommendationService';
import { useToast } from '../../hooks/useToast';

export interface RecommendationCardProps {
  projectId: string;
  docType: string;
  onApplyModel?: (modelName: string) => void;
}

export function RecommendationCard({ projectId, docType, onApplyModel }: RecommendationCardProps) {
  const { showToast } = useToast();
  const [recommendation, setRecommendation] = useState<ModelRecommendation | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    recommendationService
      .getRecommendation(projectId, docType)
      .then((rec) => {
        if (isMounted) {
          setRecommendation(rec);
          setIsLoading(false);
        }
      })
      .catch(() => {
        if (isMounted) setIsLoading(false);
      });
    return () => {
      isMounted = false;
    };
  }, [projectId, docType]);

  if (isLoading) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 animate-pulse space-y-3 font-mono">
        <div className="h-4 bg-slate-800 rounded w-1/3" />
        <div className="h-3 bg-slate-800/60 rounded w-2/3" />
        <div className="h-10 bg-slate-950/80 rounded" />
      </div>
    );
  }

  if (!recommendation) return null;

  const handleUseModel = () => {
    if (onApplyModel) {
      onApplyModel(recommendation.recommended_model);
    }
    showToast('success', 'AI Model Selected', `Set workspace engine to ${recommendation.recommended_model}`);
  };

  return (
    <div className="bg-slate-900/80 border border-indigo-500/30 backdrop-blur-md rounded-xl p-4 space-y-4 font-mono shadow-xl relative overflow-hidden">
      {/* Background Accent Glow */}
      <div className="absolute -top-12 -right-12 w-40 h-40 bg-indigo-600/10 blur-[50px] rounded-full pointer-events-none" />

      <div className="flex items-start justify-between gap-3 relative z-10">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs uppercase tracking-wider text-indigo-400 font-bold">Recommended Model</span>
            <Badge variant="emerald" size="sm">
              {Math.round(recommendation.confidence_score * 100)}% Match
            </Badge>
          </div>
          <h3 className="text-lg font-extrabold text-white flex items-center gap-2">
            <span>{recommendation.recommended_provider === 'ANTHROPIC' ? '🧠' : '⚡'}</span>
            <span>{recommendation.recommended_model}</span>
            <span className="text-amber-400 text-xs tracking-tighter">
              {'★'.repeat(recommendation.rating_stars)}
            </span>
          </h3>
        </div>

        <Badge variant="indigo" size="sm">
          Security Score: {recommendation.security_suitability_score}/100
        </Badge>
      </div>

      <p className="text-xs text-slate-300 leading-relaxed relative z-10">{recommendation.reason}</p>

      {/* Metrics Row */}
      <div className="grid grid-cols-3 gap-2 bg-slate-950/80 border border-slate-800/80 rounded-lg p-2.5 text-[10px] text-slate-400">
        <div>
          <span className="block text-slate-500 font-medium">Est. Latency</span>
          <span className="text-slate-200 font-bold">{recommendation.estimated_latency}</span>
        </div>
        <div>
          <span className="block text-slate-500 font-medium">Est. Cost</span>
          <span className="text-emerald-400 font-bold">{recommendation.estimated_cost}</span>
        </div>
        <div>
          <span className="block text-slate-500 font-medium">Context Window</span>
          <span className="text-indigo-300 font-bold">{recommendation.context_window}</span>
        </div>
      </div>

      {/* Best For Tags */}
      <div className="space-y-1">
        <span className="text-[10px] text-slate-400 uppercase font-bold">Optimal For:</span>
        <div className="flex flex-wrap gap-1">
          {recommendation.best_for_artifacts.map((art) => (
            <span key={art} className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded border border-slate-700">
              ✓ {art}
            </span>
          ))}
        </div>
      </div>

      {/* Action Controls */}
      <div className="pt-2 border-t border-slate-800/80 flex items-center justify-end gap-2">
        <Button variant="emerald" size="sm" onClick={handleUseModel} icon={<span>⚡</span>}>
          Use Recommended Model
        </Button>
      </div>
    </div>
  );
}
