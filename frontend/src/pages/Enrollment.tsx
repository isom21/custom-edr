import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Plus } from "lucide-react";
import { enrollmentApi } from "@/api/enrollment";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ConfirmDestructive } from "@/components/ConfirmDestructive";
import { PageHeader } from "@/components/PageHeader";

export function Enrollment() {
  const qc = useQueryClient();
  const tokens = useQuery({
    queryKey: ["enrollment-tokens"],
    queryFn: () => enrollmentApi.listTokens(),
  });

  const [label, setLabel] = useState("");
  const [ttl, setTtl] = useState(24);
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => enrollmentApi.createToken({ label: label || undefined, ttl_hours: ttl }),
    onSuccess: (data) => {
      setCreated(data.token);
      setLabel("");
      qc.invalidateQueries({ queryKey: ["enrollment-tokens"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => enrollmentApi.revokeToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["enrollment-tokens"] }),
  });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setCreated(null);
    create.mutate();
  };

  return (
    <>
      <PageHeader
        title="Enrollment"
        description="One-time tokens used by agents during their first connection. Each is single-use."
      />
      <div className="grid gap-4 p-8 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Issue token</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={onSubmit} className="space-y-3">
              <div className="space-y-2">
                <Label>Label (optional)</Label>
                <Input
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="e.g. lab-win11-vm"
                />
              </div>
              <div className="space-y-2">
                <Label>TTL (hours)</Label>
                <Input
                  type="number"
                  min={1}
                  max={720}
                  value={ttl}
                  onChange={(e) => setTtl(Number(e.target.value))}
                />
              </div>
              <Button type="submit" disabled={create.isPending}>
                <Plus className="h-4 w-4" /> Generate
              </Button>
              {error && (
                <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {error}
                </div>
              )}
              {created && (
                <div className="space-y-2 rounded-md bg-secondary p-3">
                  <div className="text-sm font-medium">Token (shown once)</div>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 break-all rounded bg-background p-2 text-xs">
                      {created}
                    </code>
                    <Button
                      type="button"
                      size="icon"
                      variant="outline"
                      onClick={() => navigator.clipboard.writeText(created)}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Active tokens</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Used</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tokens.data?.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} className="text-muted-foreground">
                      No tokens.
                    </TableCell>
                  </TableRow>
                )}
                {tokens.data?.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell>{t.label ?? "—"}</TableCell>
                    <TableCell className="text-sm">
                      {new Date(t.expires_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-sm">
                      {t.used_at ? new Date(t.used_at).toLocaleString() : "—"}
                    </TableCell>
                    <TableCell className="text-right">
                      <ConfirmDestructive
                        title="Revoke enrollment token?"
                        description={
                          <>
                            This invalidates{" "}
                            <span className="font-mono">{t.label ?? t.id.slice(0, 8)}</span> so the
                            agent it was minted for can no longer complete first connection.
                            Already-enrolled hosts are unaffected.
                          </>
                        }
                        confirmLabel="Yes, revoke"
                        onConfirm={() => revoke.mutate(t.id)}
                        pending={revoke.isPending}
                        trigger={
                          <Button size="sm" variant="ghost" disabled={!!t.used_at}>
                            Revoke
                          </Button>
                        }
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
