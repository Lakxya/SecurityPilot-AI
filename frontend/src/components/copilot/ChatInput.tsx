import { useState } from 'react';
import { Button } from '../ui/Button';

export interface ChatInputProps {
  onSendMessage: (text: string) => void;
  disabled?: boolean;
}

export function ChatInput({ onSendMessage, disabled }: ChatInputProps) {
  const [text, setText] = useState('');

  const shortcutChips = [
    'Audit OWASP Top 10',
    'Review STRIDE Threats',
    'Suggest Secure Code Fix',
    'Explain CVSS Score',
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (text.trim() && !disabled) {
      onSendMessage(text.trim());
      setText('');
    }
  };

  const handleChipClick = (chipText: string) => {
    if (!disabled) {
      onSendMessage(chipText);
    }
  };

  return (
    <div className="p-3 border-t border-slate-800 bg-slate-950 space-y-3 shrink-0">
      {/* Quick Prompt Shortcut Chips */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 no-scrollbar font-mono text-[10px]">
        {shortcutChips.map((chip) => (
          <button
            key={chip}
            type="button"
            disabled={disabled}
            onClick={() => handleChipClick(chip)}
            className="px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400 hover:text-indigo-300 hover:border-indigo-500/40 transition-colors whitespace-nowrap"
          >
            ⚡ {chip}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="flex items-center gap-2">
        <input
          type="text"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Ask Security Copilot (e.g. Audit JWT auth, fix CORS rules)..."
          disabled={disabled}
          className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-all font-sans"
        />
        <Button
          type="submit"
          variant="emerald"
          size="sm"
          disabled={disabled || !text.trim()}
          icon={<span>➔</span>}
        >
          Send
        </Button>
      </form>
    </div>
  );
}
