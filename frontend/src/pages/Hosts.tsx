import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { hostsApi } from "@/api/hosts";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
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
import type { HostStatus, OsFamily } from "@/types/api";

const STATUS_VARIANT: Record<HostStatus, "default" | "secondary" | "destructive" | "outline" | "success" | "warning"> =
  {
    pending: "warning",
    online: "success",
    offline: "secondary",
    isolated: "destructive",
    decommissioned: "outline",
  };

export function Hosts() {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<HostStatus | "">("");
  const [osFamily, setOsFamily] = useState<OsFamily | "">("");

  const { data, isLoading } = useQuery({
    queryKey: ["hosts", { q, status, osFamily }],
    queryFn: () =>
      hostsApi.list({
        q: q || undefined,
        status_: status || undefined,
        os_family: osFamily || undefined,
        limit: 100,
      }),
  });

  return (
    <>
      <PageHeader title="Hosts" description={`${data?.total ?? 0} enrolled hosts`} />
      <div className="flex flex-wrap gap-3 px-8 pt-6">
        <Input
          placeholder="Search hostname..."
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="max-w-xs"
        />
        <Select value={status} onChange={(e) => setStatus(e.target.value as HostStatus | "")}>
          <option value="">all statuses</option>
          <option value="pending">pending</option>
          <option value="online">online</option>
          <option value="offline">offline</option>
          <option value="isolated">isolated</option>
          <option value="decommissioned">decommissioned</option>
        </Select>
        <Select
          value={osFamily}
          onChange={(e) => setOsFamily(e.target.value as OsFamily | "")}
        >
          <option value="">all OS</option>
          <option value="windows">windows</option>
          <option value="linux">linux</option>
          <option value="macos">macos</option>
        </Select>
      </div>
      <div className="px-8 py-6">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hostname</TableHead>
                <TableHead>OS</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last seen</TableHead>
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
                    No hosts yet — issue an enrollment token to add one.
                  </TableCell>
                </TableRow>
              )}
              {data?.items.map((h) => (
                <TableRow key={h.id}>
                  <TableCell>
                    <Link to={`/hosts/${h.id}`} className="font-medium hover:underline">
                      {h.hostname}
                    </Link>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {h.os_platform ?? h.os_family} {h.os_arch ? `(${h.os_arch})` : ""}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {h.agent_version ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={STATUS_VARIANT[h.status]}>{h.status}</Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {h.last_seen_at ? new Date(h.last_seen_at).toLocaleString() : "never"}
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
