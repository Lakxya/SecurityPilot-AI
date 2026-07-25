import { useState } from 'react';
import { Navbar } from '../components/layout/Navbar';
import { Footer } from '../components/layout/Footer';
import { Button } from '../components/ui/Button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/Card';
import { Badge } from '../components/common/Badge';

export function LandingPage() {
  const [activeTab, setActiveTab] = useState<'threat' | 'srs' | 'terraform'>('threat');
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  const trustedTech = [
    { name: 'React 18', tag: 'Frontend UI' },
    { name: 'FastAPI', tag: 'Async Backend' },
    { name: 'PostgreSQL 16', tag: 'Relational DB' },
    { name: 'Docker', tag: 'Distroless Containers' },
    { name: 'Kubernetes', tag: 'Orchestration' },
    { name: 'Terraform', tag: 'IaC Infrastructure' },
    { name: 'AWS Cloud', tag: 'VPC & EKS' },
  ];

  const features = [
    {
      icon: '🛡️',
      badge: 'Security First',
      title: 'Automated Security Architecture',
      description: 'Instantly generate complete, secure-by-default software design documents (SRS, SDS, API Specs) tailored to your exact tech stack.',
    },
    {
      icon: '🔍',
      badge: 'STRIDE Framework',
      title: 'Automated Threat Modeling',
      description: 'Identify architectural attack vectors, spoofing risks, and elevation-of-privilege threats with automated CVSS vulnerability scoring.',
    },
    {
      icon: '🔐',
      badge: 'OWASP Top 10',
      title: 'Vulnerability Review & Remediation',
      description: 'Audit your architecture against Injection, Broken Auth, SSRF, and Cryptographic Failures with copy-paste remediation patterns.',
    },
    {
      icon: '🏗️',
      badge: 'Infrastructure as Code',
      title: 'Hardened Terraform & K8s Manifests',
      description: 'Generate production-ready HCL scripts, Helm charts, and Distroless Dockerfiles configured with non-root security profiles.',
    },
    {
      icon: '🤖',
      badge: 'Context Aware',
      title: 'Interactive Security Copilot',
      description: 'Ask real-time security architectural questions, refine database encryption schemes, and validate compliance rules inline.',
    },
    {
      icon: '⚡',
      badge: '1-Click Export',
      title: 'Multi-Format Archiving & Sync',
      description: 'Export your complete security architecture as a structured ZIP archive, consolidated Markdown bundle, or push directly to GitHub.',
    },
  ];

  const workflowSteps = [
    {
      step: '01',
      title: 'Define Tech Stack & Compliance',
      description: 'Select your frontend, backend, database, cloud provider, and compliance targets (OWASP, SOC 2, HIPAA).',
    },
    {
      step: '02',
      title: 'AI Threat & Architecture Analysis',
      description: 'Our AI security engine analyzes component boundaries, data flow paths, and threat vectors in seconds.',
    },
    {
      step: '03',
      title: 'Auto-Generate 13 Core Artifacts',
      description: 'Receive full SRS, SDS, API Specs, STRIDE Threat Models, Dockerfiles, K8s manifests, and Terraform scripts.',
    },
    {
      step: '04',
      title: 'Inspect, Edit & Export',
      description: 'Refine documents in our dual-pane Monaco editor, preview Mermaid.js diagrams, and export as a production-ready repository.',
    },
  ];

  const comparisonData = [
    { feature: 'Architecture Spec Generation', manual: '3 - 4 Weeks of Manual Writing', securityPilot: '30 Seconds Automated AI Generation' },
    { feature: 'Threat Modeling (STRIDE)', manual: 'Infrequent, Manual Whiteboard Sessions', securityPilot: 'Automated Real-Time CVSS Analysis' },
    { feature: 'Infrastructure Hardening', manual: 'Error-Prone Boilerplate Copying', securityPilot: 'Secure-by-Default Terraform & K8s Helm' },
    { feature: 'OWASP Top 10 Compliance', manual: 'Reactive Security Audits', securityPilot: 'Proactive Automated Mitigation Matrix' },
    { feature: 'Documentation Maintenance', manual: 'Stale, Outdated Wiki Pages', securityPilot: 'Version-Controlled Sync & Regeneration' },
  ];

  const faqs = [
    {
      q: 'What is SecurityPilotAI?',
      a: 'SecurityPilotAI is an AI-powered security architecture and infrastructure orchestration platform designed to generate secure software design documents, threat models, and IaC scaffolding automatically.',
    },
    {
      q: 'Does SecurityPilotAI store or train on my proprietary code?',
      a: 'No. SecurityPilotAI adheres to zero code retention policies. All document generations execute in isolated ephemeral sandboxes, and user prompt data is never used to train foundational AI models.',
    },
    {
      q: 'Which security compliance frameworks are supported?',
      a: 'SecurityPilotAI generates artifacts tailored to OWASP Top 10, SOC 2 Type II, HIPAA, PCI-DSS, GDPR, and ISO 27001 compliance standards.',
    },
    {
      q: 'Can I edit the generated Terraform and Kubernetes code?',
      a: 'Yes! The workspace features a full dual-pane Monaco editor with syntax highlighting. You can modify code directly or prompt the AI Copilot to refine specific modules.',
    },
    {
      q: 'What LLM models power SecurityPilotAI?',
      a: 'SecurityPilotAI supports multi-provider integration including Anthropic Claude 3.5 Sonnet, OpenAI GPT-4o, and self-hosted local Ollama models for air-gapped security environments.',
    },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-indigo-500/30 selection:text-indigo-200">
      {/* Top Navbar */}
      <Navbar />

      {/* Hero Section */}
      <section className="relative pt-20 pb-24 overflow-hidden border-b border-slate-800/60">
        {/* Background Ambient Glows */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-indigo-600/15 blur-[120px] rounded-full pointer-events-none" />
        <div className="absolute top-1/3 left-1/3 w-[400px] h-[250px] bg-cyan-600/10 blur-[100px] rounded-full pointer-events-none" />

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-900/90 border border-slate-800 shadow-inner mb-8">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-medium text-slate-300">Sprint 1 Foundation Active</span>
            <span className="text-slate-600">|</span>
            <span className="text-xs font-medium text-emerald-400">Autonomous Security Engineering</span>
          </div>

          {/* Main Headline */}
          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-[1.15]">
            Autonomous Security Architecture & <span className="bg-gradient-to-r from-indigo-400 via-cyan-400 to-emerald-400 bg-clip-text text-transparent">Infrastructure Copilot</span>
          </h1>

          {/* Description */}
          <p className="mt-6 text-base sm:text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Automatically design, analyze, generate, and document production-grade secure software architectures, STRIDE threat models, and hardened Terraform infrastructure in seconds.
          </p>

          {/* CTAs */}
          <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
            <Button variant="emerald" size="lg" icon={<span>🚀</span>}>
              Get Started Free
            </Button>
            <Button variant="outline" size="lg" icon={<span>📖</span>}>
              View Architecture Specs
            </Button>
          </div>

          {/* Interactive Preview Canvas Placeholder */}
          <div className="mt-16 max-w-5xl mx-auto rounded-xl border border-slate-800 bg-slate-900/90 shadow-2xl overflow-hidden backdrop-blur-md">
            {/* Window Header */}
            <div className="flex items-center justify-between px-4 py-3 bg-slate-950 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-rose-500/80" />
                <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                <span className="ml-2 text-xs font-mono text-slate-400">securitypilot-workspace / e-commerce-api</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveTab('threat')}
                  className={`text-xs px-2.5 py-1 rounded transition-colors ${
                    activeTab === 'threat' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  🛡️ Threat Model
                </button>
                <button
                  onClick={() => setActiveTab('srs')}
                  className={`text-xs px-2.5 py-1 rounded transition-colors ${
                    activeTab === 'srs' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  📄 SRS Spec
                </button>
                <button
                  onClick={() => setActiveTab('terraform')}
                  className={`text-xs px-2.5 py-1 rounded transition-colors ${
                    activeTab === 'terraform' ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  🏗️ Terraform IaC
                </button>
              </div>
            </div>

            {/* Code / Markdown Content Stream Simulation */}
            <div className="p-6 text-left font-mono text-xs text-slate-300 bg-slate-950/60 overflow-x-auto min-h-[280px]">
              {activeTab === 'threat' && (
                <div className="space-y-2">
                  <span className="text-slate-400"># STRIDE Threat Model Analysis — E-Commerce API</span>
                  <p className="text-emerald-400">✔ Threat Vector Identified: Unencrypted Transit Vector in Payment Gateway</p>
                  <p className="text-amber-400">⚠ Mitigation Control Required: Enforce TLS 1.3 with AES-256-GCM cipher suite</p>
                  <div className="pt-2 text-slate-400">
                    <table className="w-full text-left border-collapse border border-slate-800">
                      <thead>
                        <tr className="bg-slate-900 text-slate-200 border-b border-slate-800">
                          <th className="p-2">Threat ID</th>
                          <th className="p-2">STRIDE Category</th>
                          <th className="p-2">Impact</th>
                          <th className="p-2">Remediation Control</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr className="border-b border-slate-900">
                          <td className="p-2 text-rose-400">THREAT-01</td>
                          <td className="p-2">Spoofing</td>
                          <td className="p-2 text-rose-400">HIGH (7.5)</td>
                          <td className="p-2 text-emerald-400">Enforce RS256 JWT Signature Verification</td>
                        </tr>
                        <tr>
                          <td className="p-2 text-amber-400">THREAT-02</td>
                          <td className="p-2">Tampering</td>
                          <td className="p-2 text-amber-400">MEDIUM (5.4)</td>
                          <td className="p-2 text-emerald-400">Database Column Encryption via AWS KMS</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeTab === 'srs' && (
                <div className="space-y-2 text-slate-300">
                  <span className="text-indigo-400"># Software Requirements Specification (SRS)</span>
                  <p className="text-slate-400">## 1. Non-Functional Security Requirements</p>
                  <p>- <span className="text-emerald-400">REQ-SEC-01:</span> All authentication tokens MUST expire in 15 minutes.</p>
                  <p>- <span className="text-emerald-400">REQ-SEC-02:</span> Database passwords MUST be hashed using bcrypt (cost factor &gt;= 12).</p>
                  <p>- <span className="text-emerald-400">REQ-SEC-03:</span> Rate limiting MUST enforce max 100 requests/minute per IP.</p>
                </div>
              )}

              {activeTab === 'terraform' && (
                <div className="space-y-1 text-slate-300">
                  <span className="text-cyan-400"># Terraform Production VPC & Security Group</span>
                  <p className="text-slate-400"><span className="text-indigo-400">resource</span> &quot;aws_security_group&quot; &quot;app_sg&quot; &#123;</p>
                  <p className="pl-4">name        = &quot;sec-pilot-backend-sg&quot;</p>
                  <p className="pl-4">description = &quot;Hardened ingress rules for SecurityPilot API&quot;</p>
                  <p className="pl-4 text-emerald-400">ingress &#123;</p>
                  <p className="pl-8 text-emerald-300">from_port   = 443</p>
                  <p className="pl-8 text-emerald-300">to_port     = 443</p>
                  <p className="pl-8 text-emerald-300">protocol    = &quot;tcp&quot;</p>
                  <p className="pl-8 text-emerald-300">cidr_blocks = [&quot;10.0.0.0/16&quot;]</p>
                  <p className="pl-4 text-emerald-400">&#125;</p>
                  <p>&#125;</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Trusted Tech Stack Section */}
      <section className="py-12 bg-slate-950/80 border-b border-slate-800/60">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-6">
            Supported Enterprise Tech Stack & Cloud Infrastructure
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3 sm:gap-6">
            {trustedTech.map((tech) => (
              <div
                key={tech.name}
                className="px-4 py-2 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center gap-2 hover:border-slate-700 transition-colors"
              >
                <span className="text-sm font-semibold text-white">{tech.name}</span>
                <span className="text-[10px] text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">{tech.tag}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Grid Section */}
      <section id="features" className="py-24 border-b border-slate-800/60 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <Badge variant="indigo" size="md">
              Enterprise Features
            </Badge>
            <h2 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
              Designed for Secure Software Engineering
            </h2>
            <p className="text-slate-400 text-sm sm:text-base">
              Everything you need to automate security architecture, pass compliance audits, and deploy hardened infrastructure.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feat) => (
              <Card key={feat.title} className="flex flex-col justify-between">
                <CardHeader>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-2xl">{feat.icon}</span>
                    <Badge variant="slate" size="sm">
                      {feat.badge}
                    </Badge>
                  </div>
                  <CardTitle>{feat.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-sm text-slate-400 leading-relaxed">
                    {feat.description}
                  </CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-24 bg-slate-900/40 border-b border-slate-800/60">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <Badge variant="cyan" size="md">
              Workflow Pipeline
            </Badge>
            <h2 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
              Four Steps to Secure Architecture
            </h2>
            <p className="text-slate-400 text-sm sm:text-base">
              From zero documentation to production-ready secure scaffolding in under a minute.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {workflowSteps.map((ws) => (
              <div key={ws.step} className="p-6 rounded-xl bg-slate-900 border border-slate-800 relative space-y-3">
                <span className="text-xs font-mono font-bold text-indigo-400 bg-indigo-500/10 border border-indigo-500/20 px-2.5 py-1 rounded">
                  STEP {ws.step}
                </span>
                <h3 className="text-base font-semibold text-white pt-1">{ws.title}</h3>
                <p className="text-xs text-slate-400 leading-relaxed">{ws.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Why SecurityPilotAI Section */}
      <section id="why-us" className="py-24 border-b border-slate-800/60">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <Badge variant="emerald" size="md">
              Comparison
            </Badge>
            <h2 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
              Why Engineers Choose SecurityPilotAI
            </h2>
            <p className="text-slate-400 text-sm sm:text-base">
              Replace weeks of manual documentation and error-prone IaC boilerplate with automated, secure-by-default blueprints.
            </p>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/60">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900 border-b border-slate-800 text-xs font-semibold text-slate-300 uppercase tracking-wider">
                <tr>
                  <th className="p-4 sm:p-5">Capability / Requirement</th>
                  <th className="p-4 sm:p-5 text-slate-400">Traditional Manual SecOps</th>
                  <th className="p-4 sm:p-5 text-emerald-400">SecurityPilotAI Platform</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs sm:text-sm">
                {comparisonData.map((row) => (
                  <tr key={row.feature} className="hover:bg-slate-900/40 transition-colors">
                    <td className="p-4 sm:p-5 font-medium text-white">{row.feature}</td>
                    <td className="p-4 sm:p-5 text-slate-400">{row.manual}</td>
                    <td className="p-4 sm:p-5 text-emerald-400 font-semibold flex items-center gap-2">
                      <span>✔</span> {row.securityPilot}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section id="faq" className="py-24 bg-slate-900/30 border-b border-slate-800/60">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16 space-y-4">
            <Badge variant="amber" size="md">
              Got Questions?
            </Badge>
            <h2 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
              Frequently Asked Questions
            </h2>
          </div>

          <div className="space-y-4">
            {faqs.map((faq, index) => (
              <div
                key={faq.q}
                className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden transition-colors"
              >
                <button
                  onClick={() => setOpenFaq(openFaq === index ? null : index)}
                  className="w-full px-6 py-4 text-left font-medium text-white flex items-center justify-between gap-4 focus:outline-none"
                >
                  <span className="text-sm sm:text-base">{faq.q}</span>
                  <span className="text-slate-400 shrink-0 text-lg">
                    {openFaq === index ? '−' : '+'}
                  </span>
                </button>
                {openFaq === index && (
                  <div className="px-6 pb-5 text-xs sm:text-sm text-slate-400 border-t border-slate-800/60 pt-3 leading-relaxed">
                    {faq.a}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Bottom CTA Section */}
      <section className="py-20 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-indigo-950/20 to-slate-950 pointer-events-none" />
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 text-center space-y-6">
          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            Ready to Build Secure Architectures?
          </h2>
          <p className="text-slate-400 text-sm sm:text-base max-w-xl mx-auto">
            Join developers, SecOps engineers, and founders streamlining secure software delivery with SecurityPilotAI.
          </p>
          <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-4">
            <Button variant="emerald" size="lg" icon={<span>🚀</span>}>
              Get Started Free
            </Button>
            <Button variant="secondary" size="lg" icon={<span>⭐</span>}>
              Star on GitHub
            </Button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <Footer />
    </div>
  );
}
