import { useState, useEffect } from 'react';
import { KeyRound, Zap, Brain, Box } from 'lucide-react';
import { Dialog } from '../ui/Dialog';
import { Button } from '../ui/Button';
import { Badge } from '../common/Badge';
import { vaultService, AIProviderSpec } from '../../services/vaultService';
import { useToast } from '../../hooks/useToast';

export interface VaultModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function VaultModal({ isOpen, onClose }: VaultModalProps) {
  const { showToast } = useToast();
  const [providers, setProviders] = useState<AIProviderSpec[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState('OPENAI');
  const [apiKey, setApiKey] = useState('');
  const [modelName, setModelName] = useState('gpt-4o');
  const [baseUrl, setBaseUrl] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const loadVaultProviders = async () => {
    setIsLoading(true);
    try {
      const data = await vaultService.listProviders();
      setProviders(data);
    } catch {
      // Ignore initial empty vault
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadVaultProviders();
    }
  }, [isOpen]);

  const handleAddProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await vaultService.createProvider({
        provider_name: selectedProvider,
        api_key: apiKey,
        model_name: modelName,
        base_url: baseUrl || undefined,
        is_default: providers.length === 0,
      });
      showToast('success', 'Provider Key Added', `${selectedProvider} API key saved in vault.`);
      setApiKey('');
      setBaseUrl('');
      loadVaultProviders();
    } catch {
      showToast('error', 'Vault Error', 'Could not store provider key.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRemoveProvider = async (providerId: string) => {
    try {
      await vaultService.deleteProvider(providerId);
      showToast('info', 'Key Removed', 'Provider credential removed from vault.');
      loadVaultProviders();
    } catch {
      showToast('error', 'Delete Failed', 'Could not remove vault credential.');
    }
  };

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Enterprise AI Vault (BYOK Key Storage)"
      description="Secure Fernet AES-256 encrypted API key store. Credentials never leave server memory unencrypted."
      maxWidth="md"
    >
      <div className="space-y-6">
        {/* Add Provider Key Form */}
        <form onSubmit={handleAddProvider} className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="font-bold text-white text-xs flex items-center gap-2">
              <KeyRound className="w-3.5 h-3.5 text-indigo-400" />
              <span>Connect AI Provider Key</span>
            </span>
            <Badge variant="indigo" size="sm">
              AES-256 Encrypted
            </Badge>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-[10px] text-slate-400 mb-1">Provider Engine</label>
              <select
                value={selectedProvider}
                onChange={(e) => {
                  setSelectedProvider(e.target.value);
                  if (e.target.value === 'OPENAI') setModelName('gpt-4o');
                  else if (e.target.value === 'ANTHROPIC') setModelName('claude-3-5-sonnet');
                  else if (e.target.value === 'OPENROUTER') setModelName('meta-llama/llama-3.1-70b');
                  else if (e.target.value === 'OLLAMA') setModelName('llama3:8b');
                }}
                className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none"
              >
                <option value="OPENAI">OpenAI</option>
                <option value="ANTHROPIC">Anthropic</option>
                <option value="OPENROUTER">OpenRouter</option>
                <option value="OLLAMA">Ollama (Local)</option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] text-slate-400 mb-1">Model Name</label>
              <input
                type="text"
                value={modelName}
                onChange={(e) => setModelName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[10px] text-slate-400 mb-1">API Key / Token</label>
              <input
                type="password"
                placeholder={selectedProvider === 'OLLAMA' ? 'Optional for Local' : 'sk-proj-••••'}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none"
              />
            </div>
          </div>

          {selectedProvider === 'OLLAMA' && (
            <div>
              <label className="block text-[10px] text-slate-400 mb-1">Ollama Base URL</label>
              <input
                type="text"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="http://localhost:11434"
                className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none"
              />
            </div>
          )}

          <div className="flex justify-end pt-1">
            <Button variant="emerald" size="sm" type="submit" disabled={isSubmitting} icon={<KeyRound className="w-3.5 h-3.5" />}>
              {isSubmitting ? 'Encrypting & Saving...' : 'Store in Vault'}
            </Button>
          </div>
        </form>

        {/* Existing Vault Credentials List */}
        <div className="space-y-3">
          <h4 className="font-bold text-white text-xs font-mono">Configured Vault Credentials ({providers.length})</h4>

          {isLoading ? (
            <div className="py-6 text-center text-xs text-slate-500 font-mono">Loading Vault...</div>
          ) : providers.length === 0 ? (
            <div className="p-4 bg-slate-950 border border-slate-800/60 rounded-xl text-center text-xs text-slate-400 font-mono">
              No custom API keys stored yet.
            </div>
          ) : (
            <div className="space-y-2">
              {providers.map((p) => (
                <div
                  key={p.id}
                  className="p-3 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between font-mono text-xs"
                >
                  <div className="flex items-center gap-3">
                    {p.provider_name === 'OPENAI' ? (
                      <Zap className="w-4 h-4 text-indigo-400" />
                    ) : p.provider_name === 'ANTHROPIC' ? (
                      <Brain className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Box className="w-4 h-4 text-cyan-400" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white">{p.provider_name}</span>
                        <span className="text-slate-400">({p.model_name})</span>
                        {p.is_default && <Badge variant="emerald" size="sm">Default</Badge>}
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono">{p.masked_api_key}</span>
                    </div>
                  </div>

                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleRemoveProvider(p.id)}
                    className="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10"
                  >
                    Remove
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Dialog>
  );
}
