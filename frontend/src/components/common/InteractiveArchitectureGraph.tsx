import { useState, useRef } from 'react';
import { ShieldCheck, Lock, Database, KeyRound, ShieldAlert, Boxes } from 'lucide-react';
import { Badge } from './Badge';

export interface ArchNode {
  id: string;
  label: string;
  sublabel: string;
  icon: React.ReactNode;
  x: number;
  y: number;
  protocol: string;
  status: string;
  connections: string[];
}

export function InteractiveArchitectureGraph() {
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);
  const [tilt, setTilt] = useState({ rx: 0, ry: 0 });
  const containerRef = useRef<HTMLDivElement | null>(null);

  const nodes: ArchNode[] = [
    {
      id: 'gateway',
      label: 'Edge API Gateway',
      sublabel: 'WAF & Rate Limiter',
      icon: <ShieldCheck className="w-5 h-5 text-indigo-400" />,
      x: 15,
      y: 30,
      protocol: 'HTTPS / TLS 1.3',
      status: 'SECURE',
      connections: ['auth', 'threat'],
    },
    {
      id: 'auth',
      label: 'Auth Microservice',
      sublabel: 'OAuth 2.0 / RS256 JWT',
      icon: <Lock className="w-5 h-5 text-cyan-400" />,
      x: 45,
      y: 20,
      protocol: 'gRPC / Mutual TLS',
      status: 'VERIFIED',
      connections: ['db', 'vault'],
    },
    {
      id: 'db',
      label: 'PostgreSQL DB Cluster',
      sublabel: 'AES-256-GCM Encrypted',
      icon: <Database className="w-5 h-5 text-emerald-400" />,
      x: 80,
      y: 35,
      protocol: 'TLS Encrypted Transit',
      status: 'ENCRYPTED',
      connections: [],
    },
    {
      id: 'vault',
      label: 'Enterprise AI Vault',
      sublabel: 'Encrypted BYOK Storage',
      icon: <KeyRound className="w-5 h-5 text-amber-400" />,
      x: 40,
      y: 75,
      protocol: 'In-Memory Decryption',
      status: 'HARDENED',
      connections: ['iac'],
    },
    {
      id: 'threat',
      label: 'STRIDE Threat Engine',
      sublabel: 'Automated CVSS Auditor',
      icon: <ShieldAlert className="w-5 h-5 text-rose-400" />,
      x: 15,
      y: 70,
      protocol: 'Real-Time SSE Stream',
      status: 'ACTIVE',
      connections: ['vault'],
    },
    {
      id: 'iac',
      label: 'Terraform IaC Module',
      sublabel: 'AWS EKS & VPC Blueprints',
      icon: <Boxes className="w-5 h-5 text-purple-400" />,
      x: 75,
      y: 75,
      protocol: 'HCL 1.5 Spec',
      status: 'COMPILED',
      connections: ['db'],
    },
  ];

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    const dx = (e.clientX - cx) / (rect.width / 2);
    const dy = (e.clientY - cy) / (rect.height / 2);
    setTilt({ rx: -dy * 4, ry: dx * 4 });
  };

  const handleMouseLeave = () => {
    setTilt({ rx: 0, ry: 0 });
  };

  const isConnected = (sourceId: string, targetId: string) => {
    if (!activeNodeId) return false;
    if (activeNodeId === sourceId || activeNodeId === targetId) {
      const sourceNode = nodes.find((n) => n.id === sourceId);
      const targetNode = nodes.find((n) => n.id === targetId);
      return (
        sourceNode?.connections.includes(targetId) ||
        targetNode?.connections.includes(sourceId)
      );
    }
    return false;
  };

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className="relative w-full h-[420px] rounded-2xl border border-slate-800/80 bg-slate-950/80 backdrop-blur-xl overflow-hidden p-6 shadow-2xl transition-transform duration-300 ease-out select-none"
      style={{
        transform: `perspective(1000px) rotateX(${tilt.rx}deg) rotateY(${tilt.ry}deg)`,
      }}
    >
      {/* Background Radial Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[450px] h-[250px] bg-indigo-600/10 blur-[100px] pointer-events-none rounded-full" />

      {/* SVG Connecting Lines with Pulsing Data Streams */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none z-10">
        <defs>
          <linearGradient id="lineGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#6366f1" stopOpacity="0.6" />
            <stop offset="50%" stopColor="#06b6d4" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#10b981" stopOpacity="0.6" />
          </linearGradient>
          <linearGradient id="activeLineGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#818cf8" stopOpacity="1" />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="1" />
          </linearGradient>
        </defs>

        {nodes.map((node) =>
          node.connections.map((targetId) => {
            const target = nodes.find((n) => n.id === targetId);
            if (!target) return null;

            const active = isConnected(node.id, target.id);

            return (
              <g key={`${node.id}-${target.id}`}>
                <line
                  x1={`${node.x}%`}
                  y1={`${node.y}%`}
                  x2={`${target.x}%`}
                  y2={`${target.y}%`}
                  stroke={active ? 'url(#activeLineGrad)' : 'url(#lineGrad)'}
                  strokeWidth={active ? 2.5 : 1.2}
                  strokeDasharray={active ? 'none' : '4 4'}
                  className="transition-all duration-300"
                />
                {/* Traveling Energy Pulse */}
                <circle r={active ? 3.5 : 2} fill="#22d3ee">
                  <animateMotion
                    path={`M ${node.x * 4.5} ${node.y * 2.8} L ${target.x * 4.5} ${target.y * 2.8}`}
                    dur={active ? '1.5s' : '3.5s'}
                    repeatCount="indefinite"
                  />
                </circle>
              </g>
            );
          })
        )}
      </svg>

      {/* Floating Cloud Architecture Nodes */}
      {nodes.map((node) => {
        const isHovered = activeNodeId === node.id;
        return (
          <div
            key={node.id}
            onMouseEnter={() => setActiveNodeId(node.id)}
            onMouseLeave={() => setActiveNodeId(null)}
            style={{
              left: `${node.x}%`,
              top: `${node.y}%`,
              transform: 'translate(-50%, -50%)',
            }}
            className={`absolute z-20 transition-all duration-250 cursor-pointer ${
              isHovered ? 'scale-110 z-30' : 'hover:scale-105'
            }`}
          >
            <div
              className={`p-3.5 rounded-xl border backdrop-blur-md transition-all duration-250 shadow-xl flex items-center gap-3 ${
                isHovered
                  ? 'bg-slate-900 border-indigo-500/80 shadow-indigo-500/25 ring-2 ring-indigo-500/30'
                  : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 shrink-0">
                {node.icon}
              </div>

              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-white font-sans tracking-tight">
                    {node.label}
                  </span>
                  <Badge variant="emerald" size="sm">
                    {node.status}
                  </Badge>
                </div>
                <p className="text-[10px] font-mono text-slate-400">{node.sublabel}</p>
                {isHovered && (
                  <p className="text-[9px] font-mono text-cyan-400 font-bold animate-in fade-in duration-150">
                    Protocol: {node.protocol}
                  </p>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
