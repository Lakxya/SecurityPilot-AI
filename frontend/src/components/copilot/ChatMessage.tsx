import { useState } from 'react';
import { User, ShieldCheck, ArrowRight, Wrench, HelpCircle } from 'lucide-react';
import { ChatMessageItem } from '../../services/chatService';
import { Badge } from '../common/Badge';
import { FileChip } from '../common/FileChip';

export interface ChatMessageProps {
  message: ChatMessageItem;
  onOpenReportModal?: (content: string) => void;
}

export function ChatMessage({ message, onOpenReportModal }: ChatMessageProps) {
  const [isApplyingFix, setIsApplyingFix] = useState(false);
  const isUser = message.role === 'user';

  const handleApplyFix = () => {
    setIsApplyingFix(true);
    setTimeout(() => setIsApplyingFix(false), 1500);
  };

  return (
    <div
      className={`p-4 rounded-xl text-xs leading-relaxed transition-all duration-200 ${
        isUser
          ? 'bg-slate-900/90 border border-slate-800 text-slate-100 ml-4 shadow-md'
          : 'bg-slate-900/70 border border-indigo-500/20 text-slate-200 mr-2 shadow-lg backdrop-blur-md space-y-3'
      }`}
    >
      {/* Role & Provider Header Bar */}
      <div className="flex items-center justify-between border-b border-slate-800/60 pb-2.5">
        <div className="flex items-center gap-2">
          <div
            className={`w-6 h-6 rounded-md flex items-center justify-center font-bold text-xs shrink-0 ${
              isUser ? 'bg-slate-800 text-slate-300' : 'bg-indigo-600/90 text-white shadow-md'
            }`}
          >
            {isUser ? <User className="w-3.5 h-3.5" /> : <ShieldCheck className="w-3.5 h-3.5 text-white" />}
          </div>
          <span className="font-bold text-[11px] font-mono text-white">
            {isUser ? 'Security Engineer' : 'SecurityPilot Copilot'}
          </span>
          {!isUser && (
            <Badge variant="indigo" size="sm">
              Claude 3.5 Sonnet
            </Badge>
          )}
        </div>

        {!isUser && (
          <div className="flex items-center gap-2 font-mono text-[10px]">
            <Badge variant="emerald" size="sm">
              98% Verified
            </Badge>
            <span className="text-emerald-400 font-bold bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
              95 / 100
            </span>
          </div>
        )}
      </div>

      {/* User Message vs Assistant Response Content */}
      {isUser ? (
        <div className="whitespace-pre-wrap font-sans text-slate-200 text-xs">
          {message.content}
        </div>
      ) : (
        <div className="space-y-3 font-sans">
          {/* Quick Clean Summary */}
          <div className="space-y-1">
            <p className="text-xs font-semibold text-slate-200 leading-normal">
              Architecture reviewed successfully against STRIDE and OWASP Top 10 guidelines.
            </p>
            <div className="flex items-center gap-2 font-mono text-[10px] text-slate-400 pt-1">
              <span className="text-rose-400 font-bold">3 High</span>
              <span>•</span>
              <span className="text-amber-400 font-bold">2 Medium</span>
              <span>•</span>
              <span className="text-emerald-400 font-bold">5 Low findings</span>
            </div>
          </div>

          {/* Affected Files Chips */}
          <div className="space-y-1">
            <p className="text-[10px] font-mono text-slate-400 font-bold">Affected Files:</p>
            <div className="flex flex-wrap items-center gap-1.5">
              <FileChip fileName="README.md" />
              <FileChip fileName="main.tf" />
              <FileChip fileName="Dockerfile" />
            </div>
          </div>

          {/* Primary Recommendations */}
          <div className="space-y-1 text-[11px] text-slate-300 font-sans border-t border-slate-800/60 pt-2">
            <p className="font-mono text-[10px] text-slate-400 font-bold">Primary Recommendations:</p>
            <ul className="list-disc list-inside space-y-0.5 text-slate-300">
              <li>Enable Multi-Factor Authentication (MFA)</li>
              <li>Harden IAM Role Least Privilege Policies</li>
              <li>Enable AWS CloudTrail Immutable Logging</li>
            </ul>
          </div>

          {/* Action Bar */}
          <div className="pt-2 border-t border-slate-800/60 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2 font-mono">
            {/* View Full Report CTA */}
            <button
              onClick={() => onOpenReportModal && onOpenReportModal(message.content)}
              className="w-full sm:w-auto px-3 py-1.5 rounded-lg bg-indigo-600/90 hover:bg-indigo-500 text-white font-bold text-[11px] transition-all flex items-center justify-center gap-1.5 cursor-pointer shadow-md shadow-indigo-600/20 active:scale-95"
            >
              <span>View Full Security Report</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>

            <div className="flex items-center justify-end gap-1.5">
              <button
                onClick={handleApplyFix}
                className="px-2.5 py-1 rounded-md bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-white text-[10px] transition-colors flex items-center gap-1 cursor-pointer"
              >
                <Wrench className="w-3 h-3 text-emerald-400" />
                <span>{isApplyingFix ? 'Applying...' : 'Apply Fix'}</span>
              </button>
              <button
                onClick={() => onOpenReportModal && onOpenReportModal(message.content)}
                className="px-2.5 py-1 rounded-md bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-white text-[10px] transition-colors flex items-center gap-1 cursor-pointer"
              >
                <HelpCircle className="w-3 h-3 text-indigo-400" />
                <span>Explain</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
