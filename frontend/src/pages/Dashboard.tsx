import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Server, Shield } from "lucide-react";
import { alertsApi } from "@/api/alerts";
import { hostsApi } from "@/api/hosts";
import { rulesApi } from "@/api/rules";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";

export function Dashboard() {
  const hosts = useQuery({
    queryKey: ["hosts", "count"],
    queryFn: () => hostsApi.list({ limit: 1 }),
  });
  const rules = useQuery({
    queryKey: ["rules", "count"],
    queryFn: () => rulesApi.list({ limit: 1 }),
  });
  const newAlerts = useQuery({
    queryKey: ["alerts", "new"],
    queryFn: () => alertsApi.list({ state: "new", limit: 1 }),
  });

  return (
    <>
      <PageHeader title="Dashboard" description="High-level overview of your fleet." />
      <div className="grid gap-4 p-8 sm:grid-cols-2 lg:grid-cols-3">
        <StatCard
          title="Hosts"
          value={hosts.data?.total ?? "..."}
          icon={Server}
          hint="enrolled endpoints"
        />
        <StatCard
          title="Rules"
          value={rules.data?.total ?? "..."}
          icon={Shield}
          hint="YARA + Sigma + IOC"
        />
        <StatCard
          title="New alerts"
          value={newAlerts.data?.total ?? "..."}
          icon={AlertTriangle}
          hint="awaiting triage"
        />
      </div>
    </>
  );
}

function StatCard({
  title,
  value,
  icon: Icon,
  hint,
}: {
  title: string;
  value: string | number;
  icon: typeof Server;
  hint?: string;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </CardContent>
    </Card>
  );
}
