import { ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { Badge } from './Badge';

export interface SecurityRiskCardProps {
  title?: string;
  cvssScore?: number;
  likelihoodPercent?: number;
  impactPercent?: number;
  status?: 'Needs Immediate Action' | 'Action Recommended' | 'Compliant';
  description?: string;
  className?: string;
}

export function SecurityRiskCard({
  title = 'Critical Risk: Unencrypted API Credential Exposure',
  cvssScore = 9.8,
  likelihoodPercent = 90,
  impactPercent = 95,
  status = 'Needs Immediate Action',
  description = 'High vulnerability finding identified in transit state authorization headers.',
  className = '',
}: SecurityRiskCardProps) {
  const getCvssBadgeVariant = (score: number) => {
    if (score >= 8.5) return 'rose';
    if (score >= 6.0) return 'amber';
    return 'emerald';
  };

  const getStatusBadge = (st: string) => {
    if (st === 'Needs Immediate Action') {
      return (
        <Badge variant="rose" size="sm" pulse>
          <AlertTriangle className="w-3 h-3" />
          <span>Needs Immediate Action</span>
        </Badge>
      );
    }
    if (st === 'Action Recommended') {
      return (
        <Badge variant="amber" size="sm">
          <span>Action Recommended</span>
        </Badge>
      );
    }
    return (
      <Badge variant="emerald" size="sm">
        <CheckCircle2 className="w-3 h-3" />
        <span>Compliant</span>
      </Badge>
    );
  };

  return (
    <div
      className={`p-4 rounded-xl border border-slate-800/90 bg-slate-900/80 backdrop-blur-md space-y-3 font-sans shadow-xl my-3 ${className}`}
    >
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
          <h4 className="text-xs font-bold text-white tracking-tight">{title}</h4>
        </div>

        <div className="flex items-center gap-2 font-mono">
          <Badge variant={getCvssBadgeVariant(cvssScore)} size="sm">
            CVSS {cvssScore}
          </Badge>
          {getStatusBadge(status)}
        </div>
      </div>

      <p className="text-xs text-slate-300 leading-relaxed font-sans">{description}</p>

      {/* Metric Visual Bars */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1 font-mono text-[11px]">
        {/* Likelihood Bar */}
        <div className="space-y-1">
          <div className="flex justify-between text-slate-400">
            <span>Likelihood:</span>
            <span className="text-amber-400 font-bold">{likelihoodPercent}%</span>
          </div>
          <div className="w-full h-2 rounded-full bg-slate-950 overflow-hidden border border-slate-800">
            <div
              className="h-full bg-gradient-to-r from-amber-500 to-rose-500 transition-all duration-500"
              style={{ width: `${likelihoodPercent}%` }}
            />
          </div>
        </div>

        {/* Impact Bar */}
        <div className="space-y-1">
          <div className="flex justify-between text-slate-400">
            <span>Impact:</span>
            <span className="text-rose-400 font-bold">{impactPercent}%</span>
          </div>
          <div className="w-full h-2 rounded-full bg-slate-950 overflow-hidden border border-slate-800">
            <div
              className="h-full bg-gradient-to-r from-rose-500 to-indigo-500 transition-all duration-500"
              style={{ width: `${impactPercent}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
