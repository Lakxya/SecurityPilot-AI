import { Badge } from '../common/Badge';

export function Footer() {
  return (
    <footer className="bg-slate-950 border-t border-slate-800/80 pt-12 pb-8 text-slate-400 text-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-8 mb-12">
          {/* Brand Col */}
          <div className="md:col-span-2 space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 flex items-center justify-center font-bold text-base">
                🛡️
              </div>
              <span className="font-bold text-lg text-white tracking-tight">
                SecurityPilot<span className="text-indigo-400">AI</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
              Autonomous Security & Infrastructure Orchestration Platform. Automatically design, analyze, generate, document, and remediate secure architectures in seconds.
            </p>
            <div className="flex items-center gap-2 pt-1">
              <Badge variant="emerald" size="sm">
                System Normal
              </Badge>
              <Badge variant="indigo" size="sm">
                Sprint 2 Active
              </Badge>
            </div>
          </div>

          {/* Col 1: Product */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-white uppercase tracking-wider">Product</h4>
            <ul className="space-y-2 text-xs">
              <li>
                <a href="#features" className="hover:text-white transition-colors">
                  Security Engine
                </a>
              </li>
              <li>
                <a href="#how-it-works" className="hover:text-white transition-colors">
                  STRIDE Threat Model
                </a>
              </li>
              <li>
                <a href="#features" className="hover:text-white transition-colors">
                  Terraform & K8s
                </a>
              </li>
              <li>
                <a href="#features" className="hover:text-white transition-colors">
                  OWASP Top 10 Audit
                </a>
              </li>
            </ul>
          </div>

          {/* Col 2: Documentation */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-white uppercase tracking-wider">Resources</h4>
            <ul className="space-y-2 text-xs">
              <li>
                <a href="#faq" className="hover:text-white transition-colors">
                  Documentation
                </a>
              </li>
              <li>
                <a href="#faq" className="hover:text-white transition-colors">
                  API Reference
                </a>
              </li>
              <li>
                <a href="https://github.com/Lakxya/SecurityPilot-AI" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">
                  GitHub Specs
                </a>
              </li>
              <li>
                <a href="#faq" className="hover:text-white transition-colors">
                  Compliance Guides
                </a>
              </li>
            </ul>
          </div>

          {/* Col 3: Legal & Security */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-white uppercase tracking-wider">Security</h4>
            <ul className="space-y-2 text-xs">
              <li>
                <a href="#" className="hover:text-white transition-colors">
                  Privacy Policy
                </a>
              </li>
              <li>
                <a href="#" className="hover:text-white transition-colors">
                  Terms of Service
                </a>
              </li>
              <li>
                <a href="#" className="hover:text-white transition-colors">
                  SOC 2 Compliance
                </a>
              </li>
              <li>
                <a href="#" className="hover:text-white transition-colors">
                  Security Responsible Disclosure
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-slate-900 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-400">
          <p>© 2026 SecurityPilotAI. All rights reserved. Designed for secure software engineering.</p>
          <div className="flex items-center gap-6">
            <a href="https://github.com/Lakxya/SecurityPilot-AI" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">
              GitHub
            </a>
            <a href="#" className="hover:text-white transition-colors">
              Twitter / X
            </a>
            <a href="#" className="hover:text-white transition-colors">
              Discord
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
