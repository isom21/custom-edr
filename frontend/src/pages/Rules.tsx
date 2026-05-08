import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { rulesApi } from "@/api/rules";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/PageHeader";
import type { RuleKind } from "@/types/api";

const KIND_LABEL: Record<RuleKind, string> = { yara: "YARA", sigma: "Sigma", ioc: "IOC" };

export function Rules() {
  const [kind, setKind] = useState<RuleKind>("yara");
  const [q, setQ] = useState("");

  return (
    <>
      <PageHeader
        title="Rules"
        description="Detection content evaluated by agents and the streaming pipeline."
        actions={
          <Button asChild>
            <Link to={`/rules/new?kind=${kind}`}>
              <Plus className="h-4 w-4" /> New rule
            </Link>
          </Button>
        }
      />
      <div className="px-8 pt-6">
        <Tabs value={kind} onValueChange={(v) => setKind(v as RuleKind)}>
          <TabsList>
            <TabsTrigger value="yara">YARA</TabsTrigger>
            <TabsTrigger value="sigma">Sigma</TabsTrigger>
            <TabsTrigger value="ioc">IOC</TabsTrigger>
          </TabsList>
          {(["yara", "sigma", "ioc"] as const).map((k) => (
            <TabsContent key={k} value={k}>
              <div className="mt-2 flex items-center gap-3">
                <Input
                  placeholder={`Search ${KIND_LABEL[k]} rules...`}
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  className="max-w-xs"
                />
              </div>
              <RuleTable kind={k} q={q} />
            </TabsContent>
          ))}
        </Tabs>
      </div>
    </>
  );
}

function RuleTable({ kind, q }: { kind: RuleKind; q: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["rules", { kind, q }],
    queryFn: () => rulesApi.list({ kind, q: q || undefined, limit: 200 }),
  });
  return (
    <div className="mt-4 rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Action</TableHead>
            <TableHead>Enabled</TableHead>
            <TableHead>Updated</TableHead>
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
                No {KIND_LABEL[kind]} rules yet.
              </TableCell>
            </TableRow>
          )}
          {data?.items.map((r) => (
            <TableRow key={r.id}>
              <TableCell>
                <Link to={`/rules/${r.id}`} className="font-medium hover:underline">
                  {r.name}
                </Link>
                {r.description && (
                  <div className="text-xs text-muted-foreground">{r.description}</div>
                )}
              </TableCell>
              <TableCell>
                <Badge variant="outline">{r.severity}</Badge>
              </TableCell>
              <TableCell>
                <Badge>{r.action}</Badge>
              </TableCell>
              <TableCell>
                <Badge variant={r.enabled ? "success" : "secondary"}>
                  {r.enabled ? "enabled" : "disabled"}
                </Badge>
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">
                {new Date(r.updated_at).toLocaleString()}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
