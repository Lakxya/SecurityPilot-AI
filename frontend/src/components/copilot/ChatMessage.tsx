import { useState } from 'react';
import { User, ShieldCheck, Check, Copy } from 'lucide-react';
import { ChatMessageItem } from '../../services/chatService';

export interface ChatMessageProps {
  message: ChatMessageItem;
}

export function ChatMessage({ message }: ChatMessageProps) {
  const [copied, setCopied] = useState(false);
  const isUser = message.role === 'user';

  const handleCopy = () => {
    navigator.clipboard.writeText(message.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`flex gap-3 p-3.5 rounded-xl text-xs leading-relaxed transition-all ${
        isUser
          ? 'bg-slate-900 border border-slate-800 text-slate-100 ml-6'
          : 'bg-indigo-950/40 border border-indigo-500/20 text-slate-200 mr-6'
      }`}
    >
      {/* Role Avatar Badge */}
      <div
        className={`w-7 h-7 rounded-lg flex items-center justify-center font-bold text-xs shrink-0 ${
          isUser ? 'bg-slate-800 text-slate-300' : 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/30'
        }`}
      >
        {isUser ? <User className="w-4 h-4 text-slate-300" /> : <ShieldCheck className="w-4 h-4 text-white" />}
      </div>

      {/* Message Body Column */}
      <div className="flex-1 space-y-1 overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="font-bold text-[11px] font-mono text-slate-300">
            {isUser ? 'Security Engineer' : 'SecurityPilot Copilot'}
          </span>
          <button
            onClick={handleCopy}
            className="text-[10px] text-slate-500 hover:text-slate-300 transition-colors font-mono flex items-center gap-1 cursor-pointer"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>

        <div className="whitespace-pre-wrap font-sans text-slate-200">
          {message.content}
        </div>
      </div>
    </div>
  );
}
