import { useState, useRef, useEffect, useCallback } from 'react';
import { ShieldCheck, Bot, Trash2, X, ArrowDown } from 'lucide-react';
import { useChat } from '../../hooks/useChat';
import { ChatMessage } from './ChatMessage';
import { ChatInput } from './ChatInput';
import { Badge } from '../common/Badge';

export interface CopilotPanelProps {
  projectId: string;
  projectName: string;
  activeDocType?: string;
  currentDocContent?: string;
}

export function CopilotPanel({
  projectId,
  projectName,
  activeDocType,
  currentDocContent,
}: CopilotPanelProps) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const [showJumpToLatest, setShowJumpToLatest] = useState(false);

  const {
    messages,
    isLoadingHistory,
    isStreaming,
    streamingText,
    messagesEndRef,
    sendMessage,
    clearHistory,
  } = useChat(projectId, activeDocType, currentDocContent);

  const handleScroll = () => {
    if (!scrollAreaRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollAreaRef.current;
    const isBottom = scrollHeight - scrollTop - clientHeight < 40;
    setShowJumpToLatest(!isBottom);
  };

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messagesEndRef]);

  useEffect(() => {
    if (isStreaming && !showJumpToLatest) {
      scrollToBottom();
    }
  }, [streamingText, isStreaming, showJumpToLatest, scrollToBottom]);

  if (isCollapsed) {
    return (
      <button
        onClick={() => setIsCollapsed(false)}
        className="fixed bottom-6 right-6 z-50 bg-indigo-600 hover:bg-indigo-500 text-white p-3.5 rounded-full shadow-2xl flex items-center gap-2 border border-indigo-400/40 transition-all font-mono text-xs cursor-pointer"
      >
        <ShieldCheck className="w-4 h-4 text-white" />
        <span className="font-bold">Security Copilot</span>
      </button>
    );
  }

  return (
    <aside className="w-80 sm:w-96 bg-slate-950 border-l border-slate-800 flex flex-col h-full shrink-0 relative z-30">
      {/* Header Bar */}
      <header className="h-14 px-4 border-b border-slate-800 flex items-center justify-between shrink-0 bg-slate-950">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-indigo-400" />
          <div>
            <h3 className="text-xs font-bold text-white tracking-tight">Security Copilot</h3>
            <p className="text-[10px] text-slate-500 font-mono">Context-Aware AI Architect</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="indigo" size="sm">
            {activeDocType || 'Global Context'}
          </Badge>

          <button
            onClick={clearHistory}
            title="Clear Chat History"
            className="p-1 text-slate-500 hover:text-rose-400 text-xs transition-colors cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={() => setIsCollapsed(true)}
            className="p-1 text-slate-500 hover:text-white text-xs transition-colors cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      {/* Messages Scroll Area */}
      <div
        ref={scrollAreaRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-4 space-y-3.5 bg-slate-950/60 scroll-smooth relative"
      >
        {isLoadingHistory ? (
          <div className="text-center py-12 text-xs font-mono text-slate-500 animate-pulse">
            Loading context history...
          </div>
        ) : messages.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <Bot className="w-8 h-8 text-indigo-400 mx-auto" />
            <h4 className="text-xs font-bold text-slate-300">Context-Aware Assistant Active</h4>
            <p className="text-[11px] text-slate-500 max-w-xs mx-auto">
              Ask Security Copilot to audit OWASP Top 10 vulnerabilities, review STRIDE threats, or generate secure code snippets for <strong className="text-slate-300">{projectName}</strong>.
            </p>
          </div>
        ) : (
          messages.map((msg, idx) => <ChatMessage key={msg.id || idx} message={msg} />)
        )}

        {/* Live Streaming Response Bubble */}
        {isStreaming && (
          <div className="bg-indigo-950/40 border border-indigo-500/20 rounded-xl p-3.5 text-xs text-slate-200 mr-6 space-y-1">
            <div className="flex items-center gap-2 text-[11px] font-mono text-emerald-400 font-bold">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span>Copilot is typing...</span>
            </div>
            <div className="whitespace-pre-wrap font-sans text-slate-200">
              {streamingText}
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />

        {/* Floating Jump to Latest Button */}
        {showJumpToLatest && (
          <button
            onClick={scrollToBottom}
            className="sticky bottom-2 left-1/2 -translate-x-1/2 bg-indigo-600/90 hover:bg-indigo-500 text-white font-mono text-[10px] px-3 py-1 rounded-full shadow-lg border border-indigo-400/30 backdrop-blur-md transition-all animate-bounce flex items-center gap-1.5 cursor-pointer"
          >
            <ArrowDown className="w-3 h-3" />
            <span>Jump to Latest</span>
          </button>
        )}
      </div>

      {/* Input Footer */}
      <ChatInput onSendMessage={sendMessage} disabled={isStreaming} />
    </aside>
  );
}
