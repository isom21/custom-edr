import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { alertsApi } from "@/api/alerts";
import { Badge } from "@/components/ui/badge";
import { Select } from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/PageHeader";
import type { AlertState, Severity } from "@/types/api";

const SEVERITY_VARIANT: Record<
  Severity,
  "default" | "secondary" | "destructive" | "outline" | "success" | "warning"
> = {
  info: "outline",
  low: "secondary",
  medium: "default",
  high: "warning",
  critical: "destructive",
};

const STATE_VARIANT: Record<
  AlertState,
  "default" | "secondary" | "destructive" | "outline" | "success" | "warning"
> = {
  new: "warning",
  investigating: "default",
  false_positive: "secondary",
  true_positive: "destructive",
};

export function Alerts() {
  const [state, setState] = useState<AlertState | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");

  const { data, isLoading } = useQuery({
    queryKey: ["alerts", { state, severity }],
    queryFn: () =>
      alertsApi.list({
        state: state || undefined,
        severity: severity || undefined,
        limit: 200,
      }),
  });

  return (
    <>
      <PageHeader title="Alerts" description={`${data?.total ?? 0} total`} />
      <div className="flex flex-wrap gap-3 px-8 pt-6">
        <Select value={state} onChange={(e) => setState(e.target.value as AlertState | "")}>
          <option value="">all states</option>
          <option value="new">new</option>
          <option value="investigating">investigating</option>
          <option value="false_positive">false positive</option>
          <option value="true_positive">true positive</option>
        </Select>
        <Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
          <option value="">all severities</option>
          <option value="info">info</option>
          <option value="low">low</option>
          <option value="medium">medium</option>
          <option value="high">high</option>
          <option value="critical">critical</option>
        </Select>
      </div>
      <div className="px-8 py-6">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Summary</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Opened</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground">
                    loading...
                  </TableCell>
                </TableRow>
              )}
              {data?.items.length === 0 && !isLoading && (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground">
                    No alerts yet.
                  </TableCell>
                </TableRow>
              )}
              {data?.items.map((a) => (
                <TableRow key={a.id}>
                  <TableCell>
                    <Link to={`/alerts/${a.id}`} className="font-medium hover:underline">
                      {a.summary}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <Badge variant={SEVERITY_VARIANT[a.severity]}>{a.severity}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{a.action_taken}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={STATE_VARIANT[a.state]}>{a.state}</Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(a.opened_at).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </>
  );
}
