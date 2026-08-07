import { useState, useEffect, useRef } from 'react';
import { GitCompare, Trophy, Zap, Brain, Link2 } from 'lucide-react';
import { Button } from '../ui/Button';
import { Badge } from '../common/Badge';
import { CodeViewer } from '../common/CodeViewer';
import { GenerationTimeline } from './GenerationTimeline';
import { compareService, CompareSummary } from '../../services/compareService';
import { useToast } from '../../hooks/useToast';

export interface CompareViewProps {
  projectId: string;
  artifact: string;
  onClose: () => void;
  onSelectWinnerContent?: (content: string) => void;
}

export function CompareView({ projectId, artifact, onClose, onSelectWinnerContent }: CompareViewProps) {
  const { showToast } = useToast();
  const [isStreaming, setIsStreaming] = useState(true);
  const [streamA, setStreamA] = useState('');
  const [streamB, setStreamB] = useState('');
  const [summary, setSummary] = useState<CompareSummary | null>(null);
  const [isSyncScroll, setIsSyncScroll] = useState(true);

  const paneARef = useRef<HTMLDivElement>(null);
  const paneBRef = useRef<HTMLDivElement>(null);

  const handleSyncScrollA = () => {
    if (!isSyncScroll || !paneARef.current || !paneBRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = paneARef.current;
    const ratio = scrollTop / (scrollHeight - clientHeight || 1);
    paneBRef.current.scrollTop = ratio * (paneBRef.current.scrollHeight - paneBRef.current.clientHeight);
  };

  const handleSyncScrollB = () => {
    if (!isSyncScroll || !paneARef.current || !paneBRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = paneBRef.current;
    const ratio = scrollTop / (scrollHeight - clientHeight || 1);
    paneARef.current.scrollTop = ratio * (paneARef.current.scrollHeight - paneARef.current.clientHeight);
  };

  useEffect(() => {
    setIsStreaming(true);
    setStreamA('');
    setStreamB('');
    setSummary(null);

    compareService.streamCompare(
      projectId,
      artifact,
      ['openai', 'anthropic'],
      (provider, chunk) => {
        if (provider === 'openai') {
          setStreamA((prev) => prev + chunk);
        } else {
          setStreamB((prev) => prev + chunk);
        }
      },
      (sum) => {
        setSummary(sum);
        setIsStreaming(false);
        showToast('success', 'Compare Complete', `Winner: ${sum.winner_provider.toUpperCase()}`);
      },
      (err) => {
        setIsStreaming(false);
        showToast('error', 'Compare Stream Failed', err.message);
      }
    );
  }, [projectId, artifact, showToast]);

  const handleApplyWinner = () => {
    const winnerContent = summary?.winner_provider === 'openai' ? streamA : streamB;
    if (onSelectWinnerContent && winnerContent) {
      onSelectWinnerContent(winnerContent);
      showToast('success', 'Winner Applied', `Applied ${summary?.winner_provider.toUpperCase()} output to workspace.`);
    }
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-slate-950/95 backdrop-blur-xl z-50 flex flex-col font-sans overflow-hidden">
      {/* Top Controls Header */}
      <header className="h-16 border-b border-slate-800 px-6 flex items-center justify-between shrink-0 bg-slate-900/80">
        <div className="flex items-center gap-3">
          <Badge variant="indigo" size="md" icon={<GitCompare className="w-3.5 h-3.5" />}>
            Dual AI Compare Mode
          </Badge>
          <span className="text-xs font-mono text-slate-300 font-bold">Artifact: {artifact}</span>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsSyncScroll(!isSyncScroll)}
            icon={<Link2 className="w-3.5 h-3.5" />}
          >
            Sync Scroll: {isSyncScroll ? 'ON' : 'OFF'}
          </Button>

          {summary && (
            <Button variant="emerald" size="sm" onClick={handleApplyWinner} icon={<Trophy className="w-3.5 h-3.5" />}>
              Apply Winner Output
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close Compare Mode [Esc]
          </Button>
        </div>
      </header>

      {/* Main Body */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Animated Progress Timeline */}
        <GenerationTimeline isStreaming={isStreaming} artifact={artifact} />

        {/* Winner Highlight Callout */}
        {summary && (
          <div className="bg-emerald-950/30 border border-emerald-500/40 rounded-xl p-4 flex items-center justify-between font-mono text-xs shadow-xl">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Trophy className="w-4 h-4 text-amber-400" />
                <span className="font-extrabold text-emerald-300">
                  Overall Winner: {summary.winner_provider.toUpperCase()}
                </span>
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed">{summary.winner_reason}</p>
            </div>
            <Badge variant="emerald" size="md">
              Score: 96/100
            </Badge>
          </div>
        )}

        {/* Dual Side-by-Side Streaming Columns */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Column A: OpenAI GPT-4o */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col space-y-3 font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-indigo-400" />
                <span className="font-bold text-white text-xs">OpenAI (GPT-4o)</span>
              </div>
              <Badge variant="indigo" size="sm">
                {streamA.split(' ').length} words
              </Badge>
            </div>

            <div ref={paneARef} onScroll={handleSyncScrollA} className="flex-1 min-h-[400px] max-h-[500px] overflow-y-auto">
              <CodeViewer content={streamA || 'Streaming tokens from OpenAI...'} language="markdown" />
            </div>

            <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-400 flex items-center justify-between">
              <span>Latency: 0.8s</span>
              <span>Cost: $0.0025 / 1k</span>
              <span>Quality: 94/100</span>
            </div>
          </div>

          {/* Column B: Anthropic Claude 3.5 Sonnet */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col space-y-3 font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <Brain className="w-4 h-4 text-emerald-400" />
                <span className="font-bold text-white text-xs">Anthropic (Claude 3.5 Sonnet)</span>
              </div>
              <Badge variant="emerald" size="sm">
                {streamB.split(' ').length} words
              </Badge>
            </div>

            <div ref={paneBRef} onScroll={handleSyncScrollB} className="flex-1 min-h-[400px] max-h-[500px] overflow-y-auto">
              <CodeViewer content={streamB || 'Streaming tokens from Anthropic...'} language="markdown" />
            </div>

            <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-400 flex items-center justify-between">
              <span>Latency: 1.1s</span>
              <span>Cost: $0.003 / 1k</span>
              <span>Quality: 96/100</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
