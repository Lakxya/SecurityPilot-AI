import { useState } from 'react';
import { Dialog } from '../ui/Dialog';
import { Button } from '../ui/Button';
import { Badge } from '../common/Badge';

export interface PromptTemplate {
  id: string;
  title: string;
  category: string;
  description: string;
  prompt: string;
  icon: string;
}

const ENTERPRISE_PROMPTS: PromptTemplate[] = [
  {
    id: 'stride-1',
    title: 'STRIDE Threat Model & Vector Breakdown',
    category: 'Threat Modeling',
    description: 'Generates a full STRIDE threat vector matrix with mitigation strategies and CVSS scores.',
    prompt: 'Perform a comprehensive STRIDE threat modeling review of the provided microservices architecture. Group threats by Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. Assign CVSS v3.1 impact scores and concrete remediation steps.',
    icon: '🛡️',
  },
  {
    id: 'owasp-1',
    title: 'OWASP Top 10 API Security Assessment',
    category: 'OWASP Review',
    description: 'Audits API routes against BOLA, Broken Authentication, Mass Assignment, and SSRF.',
    prompt: 'Evaluate our OpenAPI specification and API backend against the OWASP Top 10 (2025). Focus on Broken Object Level Authorization (BOLA), Broken Function Level Authorization (BFLA), SSRF risks, and Unrestricted Resource Consumption. Provide recommended security headers and rate-limiting limits.',
    icon: '⚖️',
  },
  {
    id: 'docker-1',
    title: 'Production Dockerfile Hardening & Multi-Stage Audit',
    category: 'Docker Security',
    description: 'Refactors Dockerfiles to distroless non-root images with SHA-256 digest pinning.',
    prompt: 'Audit and harden the provided Dockerfile. Convert to a multi-stage build using Google Distroless or Alpine non-root execution (UID 10001). Enforce read-only root filesystems, drop Linux capabilities (ALL), and pin base image layers with explicit SHA-256 digest hashes.',
    icon: '🐳',
  },
  {
    id: 'terraform-1',
    title: 'Terraform IaC CIS Benchmark Hardening',
    category: 'Terraform Review',
    description: 'Enforces CIS AWS Foundations Benchmark standards across Terraform HCL manifests.',
    prompt: 'Audit our Terraform HCL infrastructure scripts against the CIS AWS Foundations Benchmark v3.0. Verify KMS customer-managed keys for EBS/S3, enable AWS CloudTrail multi-region logging, enforce S3 Block Public Access, and remove 0.0.0.0/0 ingress rules from Security Groups.',
    icon: '🏛️',
  },
  {
    id: 'k8s-1',
    title: 'Kubernetes Pod Security Standards & RBAC Audit',
    category: 'Kubernetes Audit',
    description: 'Generates Restricted Pod Security Admission policies and zero-trust NetworkPolicies.',
    prompt: 'Review our Kubernetes Deployment manifests. Apply Kubernetes Restricted Pod Security Standards (PSS). Enforce seccomp RuntimeDefault profiles, allowPrivilegeEscalation=false, readOnlyRootFilesystem=true, and generate zero-trust default-deny NetworkPolicies.',
    icon: '☸️',
  },
  {
    id: 'cloud-1',
    title: 'Cloud Security Posture Assessment (CSPM)',
    category: 'Cloud Security',
    description: 'Evaluates AWS/Azure multi-cloud security architecture and IAM role least-privilege boundaries.',
    prompt: 'Conduct a Cloud Security Posture Assessment (CSPM) for our multi-cloud microservices architecture. Evaluate IAM role trust policies, Service Control Policies (SCPs), VPC peering boundaries, and GuardDuty / AWS Security Hub alert routing.',
    icon: '☁️',
  },
  {
    id: 'ir-1',
    title: 'Incident Response Playbook & Forensic Timeline',
    category: 'Incident Response',
    description: 'Generates a 6-phase NIST SP 800-61 Rev 2 incident response protocol for compromised credentials.',
    prompt: 'Generate an enterprise Incident Response (IR) playbook for a suspected OAuth2 / JWT credential compromise. Structure steps into Preparation, Identification, Containment, Eradication, Recovery, and Lessons Learned in compliance with NIST SP 800-61 Rev 2.',
    icon: '🚨',
  },
  {
    id: 'soc-1',
    title: 'SIEM Detection Rules (Sigma & YARA)',
    category: 'SOC Analysis',
    description: 'Creates Sigma and YARA rules for detecting unauthorized privilege escalation and lateral movement.',
    prompt: 'Synthesize SIEM detection rules in Sigma YAML format for detecting MITRE ATT&CK technique T1078 (Valid Accounts) and T1059 (Command and Scripting Interpreter). Include syslog, auditd, and AWS CloudTrail query patterns.',
    icon: '🔍',
  },
];

export interface PromptLibraryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectPrompt: (promptText: string) => void;
}

export function PromptLibraryModal({ isOpen, onClose, onSelectPrompt }: PromptLibraryModalProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  const categories = ['ALL', 'Threat Modeling', 'OWASP Review', 'Docker Security', 'Terraform Review', 'Kubernetes Audit', 'Cloud Security', 'Incident Response', 'SOC Analysis'];

  const filtered = ENTERPRISE_PROMPTS.filter((p) => {
    const matchesCategory = selectedCategory === 'ALL' || p.category === selectedCategory;
    const matchesSearch = p.title.toLowerCase().includes(searchQuery.toLowerCase()) || p.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Enterprise Security Prompt Library"
      description="Select from curated NIST, CIS, and OWASP cybersecurity engineering prompt blueprints"
      maxWidth="lg"
    >
      <div className="space-y-4 font-mono text-xs">
        {/* Search & Category Header */}
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="Search prompt catalog..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />

          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-300 focus:outline-none"
          >
            {categories.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>

        {/* Prompt Templates Grid */}
        <div className="max-h-[380px] overflow-y-auto space-y-2.5 pr-1">
          {filtered.map((item) => (
            <div
              key={item.id}
              className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 hover:border-indigo-500/40 transition-all flex flex-col justify-between gap-3 group"
            >
              <div>
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-base">{item.icon}</span>
                    <span className="font-bold text-white group-hover:text-indigo-300 transition-colors">
                      {item.title}
                    </span>
                  </div>
                  <Badge variant="indigo" size="sm">
                    {item.category}
                  </Badge>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
                  {item.description}
                </p>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-slate-900">
                <span className="text-[10px] text-slate-500 truncate max-w-[320px]">
                  {item.prompt}
                </span>
                <Button
                  variant="emerald"
                  size="sm"
                  onClick={() => {
                    onSelectPrompt(item.prompt);
                    onClose();
                  }}
                  icon={<span>⚡</span>}
                >
                  Insert Prompt
                </Button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Dialog>
  );
}
