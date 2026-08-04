import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../ui/Card';
import { Badge } from '../common/Badge';
import { Button } from '../ui/Button';

export interface ProjectItem {
  id: string;
  name: string;
  description: string;
  techStack: string[];
  compliance: string[];
  updatedAt: string;
  status: 'ACTIVE' | 'ARCHIVED';
}

export interface RecentProjectsGridProps {
  onNewProjectClick: () => void;
}

export function RecentProjectsGrid({ onNewProjectClick }: RecentProjectsGridProps) {
  const [searchTerm, setSearchTerm] = useState('');

  const sampleProjects: ProjectItem[] = [
    {
      id: 'proj-1',
      name: 'E-Commerce Cloud Microservices',
      description: 'Distributed payment gateway and inventory API built with FastAPI, PostgreSQL, and AWS EKS.',
      techStack: ['React', 'FastAPI', 'PostgreSQL', 'Docker', 'AWS'],
      compliance: ['OWASP Top 10', 'PCI-DSS', 'SOC 2'],
      updatedAt: '12 mins ago',
      status: 'ACTIVE',
    },
    {
      id: 'proj-2',
      name: 'Healthcare Patient Portal Spec',
      description: 'HIPAA-compliant medical records API with end-to-end encryption and audit logging.',
      techStack: ['TypeScript', 'Node.js', 'PostgreSQL', 'Kubernetes'],
      compliance: ['HIPAA', 'OWASP Top 10'],
      updatedAt: '2 hours ago',
      status: 'ACTIVE',
    },
    {
      id: 'proj-3',
      name: 'FinTech Banking Auth Engine',
      description: 'OAuth 2.0 + RS256 JWT security core with STRIDE threat modeling and Terraform IaC.',
      techStack: ['Go', 'Redis', 'Terraform', 'Docker'],
      compliance: ['SOC 2', 'ISO 27001'],
      updatedAt: '1 day ago',
      status: 'ACTIVE',
    },
  ];

  const filteredProjects = sampleProjects.filter(
    (p) =>
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-4">
      {/* Search Bar & Action Controls Header */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight">Security Projects</h2>
          <p className="text-xs text-slate-400">Manage and inspect your active architecture workspaces</p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative flex-1 sm:w-64">
            <input
              type="text"
              placeholder="Search projects..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-all"
            />
          </div>
          <Button variant="emerald" size="sm" onClick={onNewProjectClick} icon={<span>+</span>}>
            New Project
          </Button>
        </div>
      </div>

      {/* Projects Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredProjects.map((project) => (
          <Card key={project.id} className="flex flex-col justify-between p-6">
            <CardHeader>
              <div className="flex items-start justify-between gap-2 mb-2">
                <CardTitle className="text-base font-bold text-white hover:text-indigo-400 transition-colors cursor-pointer">
                  {project.name}
                </CardTitle>
                <Badge variant="emerald" size="sm">
                  {project.status}
                </Badge>
              </div>
              <CardDescription className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                {project.description}
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-4 py-2">
              {/* Tech Stack Tags */}
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Tech Stack</span>
                <div className="flex flex-wrap gap-1">
                  {project.techStack.map((tech) => (
                    <span
                      key={tech}
                      className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-950 text-slate-300 border border-slate-800"
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              </div>

              {/* Compliance Frameworks */}
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Compliance</span>
                <div className="flex flex-wrap gap-1">
                  {project.compliance.map((c) => (
                    <Badge key={c} variant="indigo" size="sm">
                      {c}
                    </Badge>
                  ))}
                </div>
              </div>
            </CardContent>

            <CardFooter className="mt-4 pt-4 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-[10px] text-slate-400 font-mono">Updated {project.updatedAt}</span>
              <Button variant="outline" size="sm">
                Open Workspace →
              </Button>
            </CardFooter>
          </Card>
        ))}
      </div>
    </div>
  );
}
