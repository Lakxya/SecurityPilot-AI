import { useState, useEffect, useCallback } from 'react';
import { KeyRound, ShieldCheck, Package, FileText } from 'lucide-react';
import { Dialog } from '../ui/Dialog';
import { Button } from '../ui/Button';
import { Badge } from '../common/Badge';
import { vaultService, AIProviderSpec } from '../../services/vaultService';
import { providerAssignmentService, ProviderAssignmentSpec } from '../../services/providerAssignmentService';
import { useToast } from '../../hooks/useToast';

export interface ProviderAssignmentPanelProps {
  isOpen: boolean;
  onClose: () => void;
  projectId: string;
}

const ARTIFACT_LIST = [
  { id: 'README', label: 'README.md', category: 'General' },
  { id: 'SRS', label: 'SRS Architecture Spec', category: 'General' },
  { id: 'SDS', label: 'SDS Design Spec', category: 'General' },
  { id: 'THREAT_MODEL', label: 'STRIDE Threat Model', category: 'Security' },
  { id: 'OWASP_REVIEW', label: 'OWASP Top 10 Review', category: 'Security' },
  { id: 'DOCKERFILE', label: 'Dockerfile', category: 'DevOps' },
  { id: 'DOCKER_COMPOSE', label: 'docker-compose.yml', category: 'DevOps' },
  { id: 'TERRAFORM', label: 'main.tf (Terraform)', category: 'DevOps' },
  { id: 'KUBERNETES', label: 'deployment.yaml (K8s)', category: 'DevOps' },
  { id: 'GITHUB_ACTIONS', label: 'ci.yml (Actions)', category: 'DevOps' },
];

export function ProviderAssignmentPanel({ isOpen, onClose, projectId }: ProviderAssignmentPanelProps) {
  const { showToast } = useToast();
  const [assignments, setAssignments] = useState<Record<string, ProviderAssignmentSpec>>({});
  const [vaultProviders, setVaultProviders] = useState<AIProviderSpec[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [assignmentsMap, vaultList] = await Promise.all([
        providerAssignmentService.getAssignments(projectId),
        vaultService.listProviders(),
      ]);
      setAssignments(assignmentsMap);
      setVaultProviders(vaultList);
    } catch {
      showToast('error', 'Panel Error', 'Could not load provider assignment map.');
    } finally {
      setIsLoading(false);
    }
  }, [projectId, showToast]);

  useEffect(() => {
    if (isOpen) {
      loadData();
    }
  }, [isOpen, loadData]);

  const handleSelectProvider = async (artifact: string, vaultProviderId: string) => {
    const selected = vaultProviders.find((p) => p.id === vaultProviderId);
    if (!selected) return;

    try {
      const updated = await providerAssignmentService.updateAssignment(
        projectId,
        artifact,
        selected.provider_name,
        selected.model_name,
        selected.id
      );
      setAssignments((prev) => ({ ...prev, [artifact]: updated }));
      showToast('success', 'Provider Assigned', `Set ${artifact} engine to ${selected.model_name}`);
    } catch {
      showToast('error', 'Assignment Failed', `Could not update ${artifact} provider.`);
    }
  };

  const handleResetAssignment = async (artifact: string) => {
    try {
      await providerAssignmentService.removeAssignment(projectId, artifact);
      setAssignments((prev) => {
        const next = { ...prev };
        delete next[artifact];
        return next;
      });
      showToast('info', 'Assignment Cleared', `Reverted ${artifact} to Recommendation Engine.`);
    } catch {
      showToast('error', 'Reset Failed', 'Could not clear assignment.');
    }
  };

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Multi-Provider Workspace Matrix"
      description="Assign dedicated AI models per artifact across your connected AI Vault endpoints"
      maxWidth="lg"
    >
      <div className="space-y-4 font-mono text-xs">
        {isLoading ? (
          <div className="py-8 text-center text-slate-500">Loading Provider Matrix...</div>
        ) : vaultProviders.length === 0 ? (
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-6 text-center space-y-3">
            <KeyRound className="w-8 h-8 text-indigo-400 mx-auto" />
            <h4 className="font-bold text-white text-sm">No Connected AI Providers</h4>
            <p className="text-slate-400 text-xs max-w-md mx-auto">
              Add your Bring Your Own Key (BYOK) OpenAI, Anthropic, or Ollama credentials in the AI Vault to assign custom models per artifact.
            </p>
          </div>
        ) : (
          <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
            {ARTIFACT_LIST.map((item) => {
              const current = assignments[item.id];
              return (
                <div
                  key={item.id}
                  className="bg-slate-950 border border-slate-800 rounded-xl p-3 flex items-center justify-between gap-4 hover:border-slate-700 transition-all"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-indigo-600/10 border border-indigo-500/20 text-indigo-400 flex items-center justify-center font-bold text-sm">
                      {item.category === 'Security' ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      ) : item.category === 'DevOps' ? (
                        <Package className="w-4 h-4 text-indigo-400" />
                      ) : (
                        <FileText className="w-4 h-4 text-cyan-400" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white">{item.label}</span>
                        {current ? (
                          <Badge variant="emerald" size="sm">
                            {current.provider} ({current.model})
                          </Badge>
                        ) : (
                          <Badge variant="indigo" size="sm">
                            Recommendation Auto-Assign
                          </Badge>
                        )}
                      </div>
                      <span className="text-[10px] text-slate-500">
                        {current ? `Last updated: ${new Date(current.last_updated).toLocaleTimeString()}` : 'Uses intelligent recommendation engine'}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <select
                      value={current?.provider_id || ''}
                      onChange={(e) => handleSelectProvider(item.id, e.target.value)}
                      className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 focus:outline-none max-w-[160px] truncate"
                    >
                      <option value="">-- Recommendation Engine --</option>
                      {vaultProviders.map((vp) => (
                        <option key={vp.id} value={vp.id}>
                          {vp.provider_name} ({vp.model_name})
                        </option>
                      ))}
                    </select>

                    {current && (
                      <Button variant="ghost" size="sm" onClick={() => handleResetAssignment(item.id)}>
                        Reset
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Dialog>
  );
}
