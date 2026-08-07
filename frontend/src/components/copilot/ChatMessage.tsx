import { useState } from 'react';
import { User, ShieldCheck, Check, Copy, ChevronDown, ChevronUp, Cpu, Activity } from 'lucide-react';
import { ChatMessageItem } from '../../services/chatService';
import { Badge } from '../common/Badge';

export interface ChatMessageProps {
  message: ChatMessageItem;
}

export function ChatMessage({ message }: ChatMessageProps) {
  const [copied, setCopied] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const isUser = message.role === 'user';

  const handleCopy = () => {
    navigator.clipboard.writeText(message.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`flex gap-3 p-4 rounded-xl text-xs leading-relaxed transition-all duration-200 ${
        isUser
          ? 'bg-slate-900/90 border border-slate-800 text-slate-100 ml-4 shadow-md'
          : 'bg-gradient-to-b from-indigo-950/40 to-slate-950/80 border border-indigo-500/30 text-slate-200 mr-4 shadow-xl backdrop-blur-md'
      }`}
    >
      {/* Role Avatar Badge */}
      <div
        className={`w-8 h-8 rounded-lg flex items-center justify-center font-bold text-xs shrink-0 ${
          isUser ? 'bg-slate-800 text-slate-300' : 'bg-indigo-600/90 text-white shadow-lg shadow-indigo-500/30 border border-indigo-400/30'
        }`}
      >
        {isUser ? <User className="w-4 h-4 text-slate-300" /> : <ShieldCheck className="w-4 h-4 text-white" />}
      </div>

      {/* Message Body Column */}
      <div className="flex-1 space-y-2 overflow-hidden">
        {/* Header Bar with Provider Metadata */}
        <div className="flex items-center justify-between border-b border-slate-800/60 pb-2">
          <div className="flex items-center gap-2">
            <span className="font-bold text-[11px] font-mono text-white">
              {isUser ? 'Security Engineer' : 'SecurityPilot Copilot'}
            </span>
            {!isUser && (
              <Badge variant="indigo" size="sm">
                Claude 3.5 / GPT-4o
              </Badge>
            )}
          </div>

          <div className="flex items-center gap-2 font-mono text-[10px]">
            {!isUser && (
              <Badge variant="emerald" size="sm">
                98% Verified
              </Badge>
            )}

            <button
              onClick={handleCopy}
              className="text-slate-400 hover:text-white transition-colors flex items-center gap-1 cursor-pointer"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>

        {/* Text Content */}
        <div className="whitespace-pre-wrap font-sans text-slate-200 leading-relaxed text-xs">
          {message.content}
        </div>

        {/* Assistant Response Metrics & Collapsible Context */}
        {!isUser && (
          <div className="pt-2 space-y-2 border-t border-slate-800/40">
            <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
              <div className="flex items-center gap-3">
                <span className="flex items-center gap-1">
                  <Activity className="w-3 h-3 text-cyan-400" />
                  <span>Latency: 0.38s</span>
                </span>
                <span className="flex items-center gap-1">
                  <Cpu className="w-3 h-3 text-purple-400" />
                  <span>Tokens: ~340</span>
                </span>
              </div>

              <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="hover:text-white flex items-center gap-1 cursor-pointer transition-colors"
              >
                <span>{isExpanded ? 'Hide Context' : 'Context Metrics'}</span>
                {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
            </div>

            {isExpanded && (
              <div className="p-2.5 rounded-lg bg-slate-950/90 border border-slate-800/80 text-[10px] font-mono text-slate-400 space-y-1 animate-in fade-in duration-150">
                <div className="flex justify-between">
                  <span>STRIDE Audit Rating:</span>
                  <span className="text-emerald-400 font-bold">PASS (0 High Risks)</span>
                </div>
                <div className="flex justify-between">
                  <span>OWASP Top 10 Coverage:</span>
                  <span className="text-indigo-300">A01, A03, A07 Inspected</span>
                </div>
                <div className="flex justify-between">
                  <span>Encryption Standard:</span>
                  <span className="text-cyan-400">TLS 1.3 / AES-256-GCM</span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
