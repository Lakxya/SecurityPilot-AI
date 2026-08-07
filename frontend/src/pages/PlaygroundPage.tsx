import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FlaskConical, BookOpen, Zap, ArrowLeft } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/common/Badge';
import { RichMarkdownViewer } from '../components/common/RichMarkdownViewer';
import { PromptLibraryModal } from '../components/playground/PromptLibraryModal';
import { useSSEStream } from '../hooks/useSSEStream';
import { useToast } from '../hooks/useToast';

export function PlaygroundPage() {
  const navigate = useNavigate();
  const { showToast } = useToast();

  const [prompt, setPrompt] = useState('Analyze our microservices authentication architecture for potential JWT token replay and secret leakage vulnerabilities.');
  const [selectedProvider, setSelectedProvider] = useState('OPENAI');
  const [modelName, setModelName] = useState('gpt-4o');
  const [temperature, setTemperature] = useState(0.7);
  const [isPromptLibraryOpen, setIsPromptLibraryOpen] = useState(false);
  const [savedPrompts, setSavedPrompts] = useState<string[]>([]);

  const { isStreaming, streamContent, startStream, resetStream } = useSSEStream();
  const [output, setOutput] = useState('');

  useEffect(() => {
    if (isStreaming) {
      setOutput(streamContent);
    }
  }, [isStreaming, streamContent]);

  const handleRunPrompt = () => {
    setOutput('');
    startStream('playground', {
      doc_type: 'README',
      custom_instructions: prompt,
      provider: selectedProvider.toLowerCase(),
    });
    showToast('info', 'Generation Started', `Streaming live tokens from ${selectedProvider}...`);
  };

  const handleSavePrompt = () => {
    if (!prompt.trim()) return;
    setSavedPrompts((prev) => [prompt, ...prev]);
    showToast('success', 'Prompt Saved', 'Added prompt to your custom workspace library.');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans flex flex-col selection:bg-indigo-500/30 animate-page-entry">
      {/* Top Header Navigation */}
      <header className="h-16 border-b border-slate-800/80 px-6 flex items-center justify-between shrink-0 bg-slate-900/60 backdrop-blur-md">
        <div className="flex items-center gap-3 font-mono">
          <button
            onClick={() => navigate('/dashboard')}
            className="text-xs text-slate-400 hover:text-white flex items-center gap-1.5 font-medium transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Dashboard</span>
          </button>
          <span className="text-slate-600">/</span>
          <span className="text-sm font-bold text-white flex items-center gap-2">
            <FlaskConical className="w-4 h-4 text-indigo-400" />
            <span>AI Playground Sandbox</span>
          </span>
          <Badge variant="emerald" size="sm">
            Live Stream Engine
          </Badge>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsPromptLibraryOpen(true)}
            icon={<BookOpen className="w-3.5 h-3.5" />}
          >
            Prompt Library
          </Button>

          <Button variant="ghost" size="sm" onClick={() => navigate('/dashboard')}>
            Exit Playground
          </Button>
        </div>
      </header>

      {/* Playground Main Layout */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-0 overflow-hidden">
        {/* Left Config Controls Column */}
        <aside className="lg:col-span-4 border-r border-slate-800/80 p-6 space-y-6 bg-slate-950 font-mono text-xs overflow-y-auto">
          <div className="space-y-2">
            <label className="block text-[11px] uppercase tracking-wider text-slate-400 font-bold">
              Select Connected Provider
            </label>
            <select
              value={selectedProvider}
              onChange={(e) => {
                setSelectedProvider(e.target.value);
                if (e.target.value === 'OPENAI') setModelName('gpt-4o');
                else if (e.target.value === 'ANTHROPIC') setModelName('claude-3-5-sonnet');
                else if (e.target.value === 'OPENROUTER') setModelName('meta-llama/llama-3.1-70b');
                else if (e.target.value === 'OLLAMA') setModelName('llama3:8b');
              }}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
            >
              <option value="OPENAI">OpenAI (GPT-4o)</option>
              <option value="ANTHROPIC">Anthropic (Claude 3.5 Sonnet)</option>
              <option value="OPENROUTER">OpenRouter Unified</option>
              <option value="OLLAMA">Ollama (Local Model)</option>
            </select>
          </div>

          <div className="space-y-2">
            <label className="block text-[11px] uppercase tracking-wider text-slate-400 font-bold">
              Target Model Name
            </label>
            <input
              type="text"
              value={modelName}
              onChange={(e) => setModelName(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] text-slate-400 font-bold">
              <span>Temperature</span>
              <span>{temperature}</span>
            </div>
            <input
              type="range"
              min="0.0"
              max="1.0"
              step="0.05"
              value={temperature}
              onChange={(e) => setTemperature(parseFloat(e.target.value))}
              className="w-full accent-indigo-500"
            />
          </div>

          <div className="space-y-2">
            <label className="block text-[11px] uppercase tracking-wider text-slate-400 font-bold">
              Prompt Instructions
            </label>
            <textarea
              rows={8}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Type your security prompt instructions here..."
              className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono text-xs leading-relaxed"
            />
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="emerald"
              size="sm"
              onClick={handleRunPrompt}
              disabled={isStreaming}
              icon={<Zap className="w-3.5 h-3.5" />}
            >
              {isStreaming ? 'Streaming...' : 'Run Prompt'}
            </Button>

            {isStreaming ? (
              <Button variant="danger" size="sm" onClick={resetStream}>
                Stop
              </Button>
            ) : (
              <Button variant="ghost" size="sm" onClick={handleSavePrompt}>
                Save Prompt
              </Button>
            )}
          </div>

          {/* Saved Prompts Drawer */}
          {savedPrompts.length > 0 && (
            <div className="space-y-2 pt-4 border-t border-slate-800">
              <span className="text-[10px] uppercase font-bold text-slate-400">Saved Workspace Prompts ({savedPrompts.length})</span>
              <div className="space-y-1">
                {savedPrompts.map((p, i) => (
                  <button
                    key={i}
                    onClick={() => setPrompt(p)}
                    className="w-full p-2 bg-slate-900 hover:bg-slate-850 rounded text-left truncate text-slate-300 transition-colors"
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          )}
        </aside>

        {/* Right Output Stream View */}
        <main className="lg:col-span-8 p-6 bg-slate-950 flex flex-col overflow-y-auto">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4 font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="font-bold text-white">Streaming Output Canvas</span>
              {isStreaming && (
                <Badge variant="emerald" size="sm" pulse>
                  Generating Tokens...
                </Badge>
              )}
            </div>

            <div className="text-slate-400 text-[11px]">
              Words: {output.split(' ').length} | Model: {modelName}
            </div>
          </div>

          <div className="flex-1">
            <RichMarkdownViewer content={output || 'Click "Run Prompt" to stream AI response tokens live.'} />
          </div>
        </main>
      </div>

      {/* Prompt Library Modal */}
      <PromptLibraryModal
        isOpen={isPromptLibraryOpen}
        onClose={() => setIsPromptLibraryOpen(false)}
        onSelectPrompt={(p) => setPrompt(p)}
      />
    </div>
  );
}
