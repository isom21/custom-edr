/**
 * M22.d: audit log viewer (admin-only on the backend).
 *
 * Generic listing over /api/audit with the shared DataTable so column
 * filtering + saved sets work out of the box. Payload renders as a
 * truncated JSON snippet inline; future iteration could pop a detail
 * drawer for the full row.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { CheckCircle2, AlertOctagon, Loader2 } from "lucide-react";
import { auditApi } from "@/api/audit";
import { ApiError } from "@/api/client";
import { DataTable } from "@/components/data-table";
import type { ColumnDef } from "@/components/data-table";
import { PageHeader } from "@/components/PageHeader";
import { useTableQuery } from "@/hooks/useTableQuery";
import { useColumnFilters } from "@/lib/table-filters";
import { cn } from "@/lib/utils";
import type { AuditEntry } from "@/types/api";

// Resource-type → detail-page route prefix. The detail page resolves
// the uuid into a human-readable name, so a click here is enough.
const RESOURCE_ROUTE: Record<string, string> = {
  host: "/hosts",
  rule: "/rules",
  alert: "/alerts",
};

export function Audit() {
  const { state, setSort, setOffset, setLimit, setHiddenCols } = useTableQuery({ limit: 100 });
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();

  const list = useQuery({
    queryKey: ["audit", { offset: state.offset, limit: state.limit }],
    queryFn: () => auditApi.list({ limit: state.limit, offset: state.offset }),
    placeholderData: (prev) => prev,
  });

  // M22.d.b: render the HMAC chain status alongside the table so the
  // page actually shows what its subtitle promises. Refetch every 60s
  // so a chain break shows up within a minute without operator action.
  const verify = useQuery({
    queryKey: ["audit-verify"],
    queryFn: () => auditApi.verify(),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    retry: false,
  });

  const columns: ColumnDef<AuditEntry>[] = [
    {
      id: "seq",
      header: "Seq",
      filterValue: (e) => e.seq,
      cell: (e) => (
        <span className="font-mono text-xs tabular-nums text-muted-foreground">{e.seq}</span>
      ),
    },
    {
      id: "ts",
      header: "Timestamp",
      filterValue: (e) => e.ts,
      cell: (e) => (
        <time
          dateTime={e.ts}
          className="whitespace-nowrap text-xs tabular-nums text-muted-foreground"
          title={e.ts}
        >
          {new Date(e.ts).toLocaleString()}
        </time>
      ),
    },
    {
      id: "actor_kind",
      header: "Actor",
      filterValue: (e) => e.actor_kind,
      cell: (e) => (
        <span className="text-xs uppercase tracking-wider text-muted-foreground">
          {e.actor_kind}
        </span>
      ),
    },
    {
      id: "action",
      header: "Action",
      filterValue: (e) => e.action,
      cell: (e) => <span className="font-mono text-xs">{e.action}</span>,
    },
    {
      id: "resource_type",
      header: "Resource type",
      filterValue: (e) => e.resource_type ?? "",
      cell: (e) => <span className="text-xs text-muted-foreground">{e.resource_type ?? "—"}</span>,
    },
    {
      id: "resource_id",
      header: "Resource id",
      filterValue: (e) => e.resource_id ?? "",
      cell: (e) => {
        if (!e.resource_id) return <span className="text-xs text-muted-foreground">—</span>;
        const route = e.resource_type ? RESOURCE_ROUTE[e.resource_type] : undefined;
        const short = `${e.resource_id.slice(0, 8)}…`;
        if (!route) {
          return (
            <span className="font-mono text-xs text-muted-foreground" title={e.resource_id}>
              {short}
            </span>
          );
        }
        return (
          <Link
            to={`${route}/${e.resource_id}`}
            onClick={(ev) => ev.stopPropagation()}
            className="font-mono text-xs underline-offset-2 hover:underline"
            title={e.resource_id}
          >
            {short}
          </Link>
        );
      },
    },
    {
      id: "payload",
      header: "Payload",
      filterValue: (e) => JSON.stringify(e.payload ?? {}),
      cell: (e) => (
        <span className="block max-w-md truncate font-mono text-[11px] text-muted-foreground">
          {e.payload ? JSON.stringify(e.payload) : "—"}
        </span>
      ),
    },
    {
      id: "ip",
      header: "IP",
      hiddenByDefault: true,
      filterValue: (e) => e.ip ?? "",
      cell: (e) => <span className="font-mono text-xs text-muted-foreground">{e.ip ?? "—"}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every privileged action is recorded with a tamper-evident HMAC chain. Admins only."
      />
      <div className="space-y-4 px-8 py-6">
        <ChainStatusBadge query={verify} />
        <DataTable<AuditEntry>
          tableId="audit"
          columns={columns}
          rows={list.data?.items}
          total={list.data?.total ?? 0}
          isLoading={list.isLoading}
          isError={list.isError}
          errorMessage={list.error instanceof ApiError ? list.error.detail : undefined}
          emptyMessage="No audit entries yet."
          getRowId={(e) => e.id}
          sort={state.sort}
          onSortChange={setSort}
          offset={state.offset}
          limit={state.limit}
          onOffsetChange={setOffset}
          onLimitChange={setLimit}
          hiddenCols={state.hiddenCols}
          onHiddenColsChange={setHiddenCols}
          columnFilters={columnFilters}
          onColumnFiltersChange={setColumnFilters}
          savedFiltersTableId="audit"
        />
      </div>
    </>
  );
}

interface VerifyQuery {
  data?: { ok: boolean; rows_examined: number; chain_rows: number; breaks: unknown[] };
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  dataUpdatedAt: number;
}

function ChainStatusBadge({ query }: { query: VerifyQuery }) {
  // Three states. Loading + error render small + neutral; ok/broken
  // get the actual semantic colours.
  if (query.isLoading && !query.data) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="inline-flex items-center gap-2 rounded-md border bg-secondary/40 px-3 py-2 text-xs text-muted-foreground"
      >
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        Verifying HMAC chain…
      </div>
    );
  }
  if (query.isError || !query.data) {
    const msg =
      query.error instanceof ApiError ? query.error.detail : "chain verify request failed";
    return (
      <div
        role="status"
        className="inline-flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-500"
      >
        <AlertOctagon className="h-3.5 w-3.5" />
        HMAC chain status unavailable: {msg}
      </div>
    );
  }
  const v = query.data;
  const updated = new Date(query.dataUpdatedAt);
  const time = updated.toLocaleTimeString();
  if (v.ok) {
    // Empty log is also "ok" from the verifier's perspective (no rows
    // to walk). Phrase the badge so it isn't actively misleading.
    const tail =
      v.chain_rows > 0
        ? `through seq ${v.chain_rows}`
        : v.rows_examined > 0
          ? `(${v.rows_examined} pre-HMAC rows)`
          : "(no rows yet)";
    return (
      <div
        role="status"
        aria-live="polite"
        className={cn(
          "inline-flex items-center gap-2 rounded-md border px-3 py-2 text-xs",
          "border-emerald-500/30 bg-emerald-500/10 text-emerald-500",
        )}
      >
        <CheckCircle2 className="h-3.5 w-3.5" />
        <span className="font-medium">Chain verified</span>
        <span className="text-emerald-500/80">
          {tail} · checked at {time}
        </span>
      </div>
    );
  }
  // Chain broken — render in destructive colour and name the first
  // break's sequence number so the operator can jump to it.
  const firstBreak = v.breaks[0] as { seq?: number } | undefined;
  return (
    <div
      role="alert"
      aria-live="assertive"
      className="inline-flex items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive"
    >
      <AlertOctagon className="h-3.5 w-3.5" />
      <span className="font-medium">
        Chain broken{typeof firstBreak?.seq === "number" ? ` at seq ${firstBreak.seq}` : ""}
      </span>
      <span className="text-destructive/80">— investigate · checked at {time}</span>
    </div>
  );
}
