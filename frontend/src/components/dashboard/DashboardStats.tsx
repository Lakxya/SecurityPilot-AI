import { Card, CardHeader, CardTitle, CardContent } from '../ui/Card';
import { Badge } from '../common/Badge';

export function DashboardStats() {
  const stats = [
    {
      title: 'Active Security Projects',
      value: '3',
      change: '+2 this week',
      badge: 'emerald',
      icon: '📁',
    },
    {
      title: 'Generated Security Specs',
      value: '39',
      change: '13 docs / project',
      badge: 'indigo',
      icon: '📄',
    },
    {
      title: 'STRIDE Threats Mitigated',
      value: '142',
      change: 'Zero Critical Flaws',
      badge: 'cyan',
      icon: '🛡️',
    },
    {
      title: 'Hardened IaC Manifests',
      value: '12',
      change: 'K8s + Terraform HCL',
      badge: 'amber',
      icon: '☸️',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {stats.map((st) => (
        <Card key={st.title} className="p-5">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 mb-0">
            <CardTitle className="text-xs font-medium text-slate-400">{st.title}</CardTitle>
            <span className="text-lg">{st.icon}</span>
          </CardHeader>
          <CardContent className="pt-2">
            <div className="text-2xl font-bold text-white tracking-tight">{st.value}</div>
            <div className="mt-2 flex items-center justify-between">
              <Badge variant={st.badge as 'emerald' | 'indigo' | 'cyan' | 'amber'} size="sm">
                {st.change}
              </Badge>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
