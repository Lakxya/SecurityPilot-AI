import { ShieldAlert, UserCheck, FileCheck, Eye, Zap, Lock } from 'lucide-react';
import { Badge } from './Badge';

export interface StrideThreatCategory {
  title: 'Spoofing' | 'Tampering' | 'Repudiation' | 'Information Disclosure' | 'Denial of Service' | 'Elevation of Privilege';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  mitigation: string;
}

export interface StrideThreatGridProps {
  threats?: StrideThreatCategory[];
  className?: string;
}

const DEFAULT_STRIDE_THREATS: StrideThreatCategory[] = [
  {
    title: 'Spoofing',
    severity: 'MEDIUM',
    description: 'User identity spoofing in payment callback hook.',
    mitigation: 'Enforce RS256 JWT signature verification.',
  },
  {
    title: 'Tampering',
    severity: 'LOW',
    description: 'Parameter tampering in transit payload.',
    mitigation: 'Enforce TLS 1.3 encryption & payload HMAC hash check.',
  },
  {
    title: 'Repudiation',
    severity: 'LOW',
    description: 'Unsigned SecOps activity log entry.',
    mitigation: 'Implement immutable PostgreSQL audit log stream.',
  },
  {
    title: 'Information Disclosure',
    severity: 'HIGH',
    description: 'Unencrypted API key string in transit state.',
    mitigation: 'Encrypt credentials using AES-256-GCM in AI Vault.',
  },
  {
    title: 'Denial of Service',
    severity: 'MEDIUM',
    description: 'API rate limit exhaustion vulnerability.',
    mitigation: 'Configure Redis Token Bucket rate limiter (100 req/min).',
  },
  {
    title: 'Elevation of Privilege',
    severity: 'CRITICAL',
    description: 'Horizontal RBAC bypass vector on project routes.',
    mitigation: 'Enforce user_id tenancy check on DB queries.',
  },
];

export function StrideThreatGrid({
  threats = DEFAULT_STRIDE_THREATS,
  className = '',
}: StrideThreatGridProps) {
  const getCategoryMeta = (title: string) => {
    switch (title) {
      case 'Spoofing':
        return { icon: <UserCheck className="w-4 h-4 text-indigo-400" />, color: 'text-indigo-400' };
      case 'Tampering':
        return { icon: <FileCheck className="w-4 h-4 text-amber-400" />, color: 'text-amber-400' };
      case 'Repudiation':
        return { icon: <ShieldAlert className="w-4 h-4 text-cyan-400" />, color: 'text-cyan-400' };
      case 'Information Disclosure':
        return { icon: <Eye className="w-4 h-4 text-purple-400" />, color: 'text-purple-400' };
      case 'Denial of Service':
        return { icon: <Zap className="w-4 h-4 text-rose-400" />, color: 'text-rose-400' };
      case 'Elevation of Privilege':
        return { icon: <Lock className="w-4 h-4 text-emerald-400" />, color: 'text-emerald-400' };
      default:
        return { icon: <ShieldAlert className="w-4 h-4 text-indigo-400" />, color: 'text-indigo-400' };
    }
  };

  const getSeverityBadgeVariant = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return 'rose';
      case 'MEDIUM':
        return 'amber';
      default:
        return 'emerald';
    }
  };

  return (
    <div className={`space-y-3 font-sans ${className}`}>
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-indigo-400" />
          <span>STRIDE Threat Vectors Overview</span>
        </h4>
        <span className="text-[10px] font-mono text-slate-400">6 Security Categories</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {threats.map((threat) => {
          const meta = getCategoryMeta(threat.title);
          return (
            <div
              key={threat.title}
              className="p-3.5 rounded-xl border border-slate-800/90 bg-slate-900/60 backdrop-blur-md transition-all duration-200 hover:-translate-y-0.5 hover:border-indigo-500/40 hover:shadow-lg hover:shadow-indigo-500/10 space-y-2 group"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 shrink-0 group-hover:scale-105 transition-transform">
                    {meta.icon}
                  </div>
                  <span className="text-xs font-bold text-white font-mono tracking-tight">
                    {threat.title}
                  </span>
                </div>
                <Badge variant={getSeverityBadgeVariant(threat.severity)} size="sm">
                  {threat.severity}
                </Badge>
              </div>

              <p className="text-[11px] text-slate-300 leading-snug line-clamp-2">
                {threat.description}
              </p>

              <div className="pt-1.5 border-t border-slate-800/60 text-[10px] font-mono text-slate-400">
                <span className="text-indigo-300 font-bold">Fix: </span>
                <span>{threat.mitigation}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
