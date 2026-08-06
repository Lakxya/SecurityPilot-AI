import { useState, useEffect } from 'react';
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

  const handleDelete = async (id: string) => {
    try {
      await vaultService.deleteProvider(id);
      showToast('info', 'Credential Revoked', 'Provider removed from vault.');
      loadVaultProviders();
    } catch {
      showToast('error', 'Revoke Failed', 'Could not delete credential.');
    }
  };

  const handleTest = async (id: string) => {
    try {
      const res = await vaultService.testProvider(id);
      showToast('success', 'Connection Validated', `Handshake successful. Latency: ${res.latency_ms}ms`);
    } catch {
      showToast('error', 'Test Failed', 'Provider unreachable.');
    }
  };

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Enterprise AI Provider Vault"
      description="Store, encrypt, and manage Bring Your Own Key (BYOK) credentials for Multi-LLM generation"
      maxWidth="lg"
    >
      <div className="space-y-6">
        {/* Form to Add New Key */}
        <form onSubmit={handleAddProvider} className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-4 font-mono text-xs">
          <h4 className="font-bold text-white tracking-tight text-xs">Add New AI Model Credential</h4>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-[10px] text-slate-400 mb-1">Provider Type</label>
              <select
                value={selectedProvider}
                onChange={(e) => {
                  setSelectedProvider(e.target.value);
                  if (e.target.value === 'OPENAI') setModelName('gpt-4o');
                  else if (e.target.value === 'ANTHROPIC') setModelName('claude-3-5-sonnet');
                  else if (e.target.value === 'OPENROUTER') setModelName('meta-llama/llama-3.1-70b');
                  else if (e.target.value === 'OLLAMA') {
                    setModelName('llama3:8b');
                    setBaseUrl('http://localhost:11434');
                  }
                }}
                className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none"
              >
                <option value="OPENAI">OpenAI (BYOK)</option>
                <option value="ANTHROPIC">Anthropic (Claude)</option>
                <option value="OPENROUTER">OpenRouter Unified</option>
                <option value="OLLAMA">Ollama (Local Model)</option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] text-slate-400 mb-1">Target Model Name</label>
              <input
                type="text"
                required
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
            <Button variant="emerald" size="sm" type="submit" disabled={isSubmitting}>
              {isSubmitting ? 'Encrypting & Saving...' : '🔑 Store in Vault'}
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
              No custom API keys stored yet. Mock provider active by default.
            </div>
          ) : (
            <div className="space-y-2">
              {providers.map((p) => (
                <div
                  key={p.id}
                  className="p-3 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between font-mono text-xs"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-base">{p.provider_name === 'OPENAI' ? '⚡' : p.provider_name === 'ANTHROPIC' ? '🧠' : '🦙'}</span>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white">{p.provider_name}</span>
                        <span className="text-[10px] text-slate-400">({p.model_name})</span>
                        {p.is_default && <Badge variant="emerald" size="sm">Default</Badge>}
                      </div>
                      <span className="text-[10px] text-slate-500">{p.masked_api_key}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button variant="ghost" size="sm" onClick={() => handleTest(p.id)}>
                      Ping Test
                    </Button>
                    <Button variant="danger" size="sm" onClick={() => handleDelete(p.id)}>
                      Revoke
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Dialog>
  );
}
