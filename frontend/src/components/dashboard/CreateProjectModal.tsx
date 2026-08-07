import React, { useState } from 'react';
import { Rocket } from 'lucide-react';
import { Dialog } from '../ui/Dialog';
import { Button } from '../ui/Button';
import { projectService } from '../../services/projectService';
import { Project } from '../../types/project';

export interface CreateProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: (newProject?: Project) => void;
}

export function CreateProjectModal({ isOpen, onClose, onSuccess }: CreateProjectModalProps) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Form State
  const [projectName, setProjectName] = useState('');
  const [description, setDescription] = useState('');

  const [selectedFrontend, setSelectedFrontend] = useState('React 18');
  const [selectedBackend, setSelectedBackend] = useState('FastAPI');
  const [selectedDatabase, setSelectedDatabase] = useState('PostgreSQL 16');
  const [selectedCloud, setSelectedCloud] = useState('AWS Cloud');
  const [selectedContainer, setSelectedContainer] = useState('Docker + K8s');

  const [selectedCompliance, setSelectedCompliance] = useState<string[]>([
    'OWASP Top 10',
    'SOC 2 Type II',
  ]);

  const toggleCompliance = (framework: string) => {
    if (selectedCompliance.includes(framework)) {
      setSelectedCompliance(selectedCompliance.filter((f) => f !== framework));
    } else {
      setSelectedCompliance([...selectedCompliance, framework]);
    }
  };

  const handleComplete = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const newProj = await projectService.createProject({
        name: projectName || 'Untitled Security Project',
        description: description || 'Secure software architecture specification',
        tech_stack: {
          frontend: selectedFrontend,
          backend: selectedBackend,
          database: selectedDatabase,
          cloud: selectedCloud,
          container: selectedContainer,
        },
        compliance_frameworks: selectedCompliance,
      });

      if (onSuccess) onSuccess(newProj);
      onClose();
      // Reset state
      setStep(1);
      setProjectName('');
      setDescription('');
    } catch (err) {
      console.error('Failed to create project:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Create New Security Architecture Project"
      description={`Step ${step} of 3 — Configure project metadata, stack specifications, and compliance targets`}
      maxWidth="lg"
    >
      <div className="space-y-6">
        {/* Step Indicator Bar */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 text-xs font-mono">
          <span className={step === 1 ? 'text-indigo-400 font-bold' : 'text-slate-500'}>
            1. Metadata
          </span>
          <span className="text-slate-700">──►</span>
          <span className={step === 2 ? 'text-indigo-400 font-bold' : 'text-slate-500'}>
            2. Tech Stack
          </span>
          <span className="text-slate-700">──►</span>
          <span className={step === 3 ? 'text-indigo-400 font-bold' : 'text-slate-500'}>
            3. Compliance
          </span>
        </div>

        {/* Step 1: Project Metadata */}
        {step === 1 && (
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Project Name *
              </label>
              <input
                type="text"
                required
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="e.g. Banking Security Core API"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-all"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Description / Architectural Purpose
              </label>
              <textarea
                rows={3}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief summary of microservice goals, security requirements, and data classification..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-all"
              />
            </div>
          </div>
        )}

        {/* Step 2: Tech Stack Selection */}
        {step === 2 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Frontend Framework</label>
              <select
                value={selectedFrontend}
                onChange={(e) => setSelectedFrontend(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500"
              >
                <option value="React 18">React 18 (Vite + TypeScript)</option>
                <option value="Vue 3">Vue 3 (Vite)</option>
                <option value="Next.js">Next.js 14</option>
                <option value="None">API Only (No Frontend)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Backend Core Engine</label>
              <select
                value={selectedBackend}
                onChange={(e) => setSelectedBackend(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500"
              >
                <option value="FastAPI">Python FastAPI (Async Core)</option>
                <option value="Go Gin">Go (Gin / Fiber Framework)</option>
                <option value="Node Express">Node.js (Express / NestJS)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Database Layer</label>
              <select
                value={selectedDatabase}
                onChange={(e) => setSelectedDatabase(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500"
              >
                <option value="PostgreSQL 16">PostgreSQL 16 + Redis 7</option>
                <option value="MongoDB">MongoDB Enterprise</option>
                <option value="MySQL">MySQL 8.0</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Cloud Infrastructure</label>
              <select
                value={selectedCloud}
                onChange={(e) => setSelectedCloud(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500"
              >
                <option value="AWS Cloud">AWS (EKS, RDS, S3, KMS)</option>
                <option value="Google Cloud">Google Cloud (GKE, Cloud SQL)</option>
                <option value="Microsoft Azure">Azure (AKS, Azure SQL)</option>
              </select>
            </div>

            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-300 mb-1">Container Runtime</label>
              <select
                value={selectedContainer}
                onChange={(e) => setSelectedContainer(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500"
              >
                <option value="Docker + K8s">Multi-Stage Distroless Docker + Kubernetes Helm</option>
                <option value="Docker Compose">Standalone Docker Compose</option>
              </select>
            </div>
          </div>
        )}

        {/* Step 3: Compliance Frameworks */}
        {step === 3 && (
          <div className="space-y-3">
            <label className="block text-xs font-medium text-slate-300">
              Select Security & Compliance Targets
            </label>
            <div className="grid grid-cols-2 gap-3">
              {[
                { name: 'OWASP Top 10', desc: 'Web & API vulnerability mitigation matrix' },
                { name: 'SOC 2 Type II', desc: 'Trust Services Criteria security controls' },
                { name: 'HIPAA', desc: 'Healthcare Data Protection & ePHI encryption' },
                { name: 'PCI-DSS', desc: 'Payment Card Industry Data Security Standard' },
                { name: 'ISO 27001', desc: 'Information Security Management System' },
                { name: 'GDPR', desc: 'EU Data Privacy & User Encryption Mandate' },
              ].map((item) => {
                const isSelected = selectedCompliance.includes(item.name);
                return (
                  <button
                    key={item.name}
                    type="button"
                    onClick={() => toggleCompliance(item.name)}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      isSelected
                        ? 'bg-indigo-600/20 border-indigo-500/50 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <p className="text-xs font-semibold">{item.name}</p>
                    <p className="text-[10px] text-slate-500 mt-1 line-clamp-1">{item.desc}</p>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Action Controls Footer */}
        <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
          {step > 1 ? (
            <Button variant="ghost" size="sm" onClick={() => setStep((step - 1) as 1 | 2)}>
              ← Back
            </Button>
          ) : (
            <div />
          )}

          {step < 3 ? (
            <Button
              variant="emerald"
              size="sm"
              disabled={!projectName.trim()}
              onClick={() => setStep((step + 1) as 2 | 3)}
            >
              Next: Tech Stack →
            </Button>
          ) : (
            <Button variant="emerald" size="sm" onClick={handleComplete} disabled={isSubmitting} icon={<Rocket className="w-3.5 h-3.5" />}>
              {isSubmitting ? 'Creating Project...' : 'Create Project Workspace'}
            </Button>

          )}
        </div>
      </div>
    </Dialog>
  );
}
