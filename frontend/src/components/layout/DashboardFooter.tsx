export function DashboardFooter() {
  return (
    <footer className="h-8 bg-slate-950 border-t border-slate-800/80 px-6 flex items-center justify-between text-[11px] font-mono text-slate-400 shrink-0">
      <div className="flex items-center gap-4">
        <span className="flex items-center gap-1.5 text-emerald-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>System Operational</span>
        </span>
        <span className="text-slate-700">|</span>
        <span>Latency: 24ms</span>
        <span className="text-slate-700">|</span>
        <span>Security Scope: OWASP Top 10 + STRIDE</span>
      </div>

      <div className="flex items-center gap-4">
        <span>Model: SecurityPilot-V1</span>
        <span className="text-slate-700">|</span>
        <span className="text-indigo-400">Sprint 4 Dashboard Ready</span>
      </div>
    </footer>
  );
}
