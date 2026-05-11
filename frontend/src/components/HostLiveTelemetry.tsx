/**
 * Per-host live telemetry feed.
 *
 * Polls `GET /api/hosts/:id/telemetry?since=<iso>` every 2s and appends
 * new events to a rolling client-side buffer (cap 2000) so the table
 * tails without unbounded memory growth.
 *
 * The feed is sliced into category tabs — Processes / Files / Network /
 * Auth / Modules / Other — each rendering its own columns so analysts
 * see the right fields per-event-type (parent pid + working dir for
 * processes, signed/signer for modules, source/destination tuple for
 * network, etc.) without packing every column into one wide table.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Pause, Play, Trash } from "lucide-react";
import { hostsApi } from "@/api/hosts";
import { ColumnHeaderFilter } from "@/components/data-table/ColumnHeaderFilter";
import { FilterChipBar } from "@/components/data-table/FilterChipBar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { applyFilters, useColumnFilters } from "@/lib/table-filters";
import { cn } from "@/lib/utils";
import type { LiveTelemetryEvent } from "@/types/api";

const POLL_MS = 2000;
const BUFFER_CAP = 2000;

interface Column {
  id: string;
  label: string;
  accessor: (e: LiveTelemetryEvent) => string | number | null | undefined;
  render: (e: LiveTelemetryEvent) => React.ReactNode;
  className?: string;
}

const TIME_COL: Column = {
  id: "time",
  label: "time",
  accessor: (e) => e.timestamp,
  render: (e) => (
    <time
      dateTime={e.timestamp}
      className="whitespace-nowrap font-mono tabular-nums text-muted-foreground"
      title={e.timestamp}
    >
      {new Date(e.timestamp).toLocaleTimeString()}
    </time>
  ),
};

const PID_COL: Column = {
  id: "pid",
  label: "pid",
  accessor: (e) => e.pid ?? "",
  render: (e) => (
    <span className="font-mono tabular-nums text-muted-foreground">{e.pid ?? "—"}</span>
  ),
};

const ACTION_COL: Column = {
  id: "action",
  label: "action",
  accessor: (e) => e.action ?? "",
  render: (e) => (
    <span className="font-mono">
      {e.action ?? "—"}
      {e.outcome === "failure" && <span className="ml-1 text-sev-critical">✕</span>}
    </span>
  ),
};

const RULE_COL: Column = {
  id: "rule",
  label: "rule",
  accessor: (e) => e.rule_name ?? "",
  render: (e) => <span className="text-muted-foreground">{e.rule_name ?? "—"}</span>,
};

const PROCESS_COLUMNS: Column[] = [
  TIME_COL,
  PID_COL,
  {
    id: "parent_pid",
    label: "parent",
    accessor: (e) => e.parent_pid ?? "",
    render: (e) => (
      <span className="font-mono tabular-nums text-muted-foreground">{e.parent_pid ?? "—"}</span>
    ),
  },
  ACTION_COL,
  {
    id: "user",
    label: "user",
    accessor: (e) => e.user_name ?? "",
    render: (e) => (
      <span className="truncate font-mono text-muted-foreground">{e.user_name ?? "—"}</span>
    ),
  },
  {
    id: "executable",
    label: "executable",
    accessor: (e) => e.executable ?? "",
    render: (e) => (
      <span className="block max-w-md truncate font-mono" title={e.executable ?? undefined}>
        {e.executable ?? "—"}
      </span>
    ),
  },
  {
    id: "command_line",
    label: "command line",
    accessor: (e) => e.command_line ?? "",
    render: (e) => (
      <span
        className="block max-w-xl truncate font-mono text-muted-foreground"
        title={e.command_line ?? undefined}
      >
        {e.command_line ?? "—"}
      </span>
    ),
  },
  {
    id: "sha256",
    label: "sha256",
    accessor: (e) => e.sha256 ?? "",
    render: (e) => (
      <span className="font-mono text-muted-foreground" title={e.sha256 ?? undefined}>
        {e.sha256 ? `${e.sha256.slice(0, 12)}…` : "—"}
      </span>
    ),
  },
];

const FILE_COLUMNS: Column[] = [
  TIME_COL,
  PID_COL,
  {
    id: "file_action",
    label: "action",
    accessor: (e) => e.file_action ?? e.action ?? "",
    render: (e) => <span className="font-mono">{e.file_action ?? e.action ?? "—"}</span>,
  },
  {
    id: "file_path",
    label: "path",
    accessor: (e) => e.file_path ?? "",
    render: (e) => (
      <span className="block max-w-xl truncate font-mono" title={e.file_path ?? undefined}>
        {e.file_path ?? "—"}
      </span>
    ),
  },
  {
    id: "file_size",
    label: "size",
    accessor: (e) => e.file_size ?? "",
    render: (e) => (
      <span className="font-mono tabular-nums text-muted-foreground">
        {e.file_size != null ? e.file_size.toLocaleString() : "—"}
      </span>
    ),
  },
  {
    id: "sha256",
    label: "sha256",
    accessor: (e) => e.sha256 ?? "",
    render: (e) => (
      <span className="font-mono text-muted-foreground" title={e.sha256 ?? undefined}>
        {e.sha256 ? `${e.sha256.slice(0, 12)}…` : "—"}
      </span>
    ),
  },
];

const NETWORK_COLUMNS: Column[] = [
  TIME_COL,
  PID_COL,
  {
    id: "direction",
    label: "direction",
    accessor: (e) => e.direction ?? "",
    render: (e) => (
      <span className="font-mono uppercase tracking-wider text-muted-foreground">
        {e.direction ?? "—"}
      </span>
    ),
  },
  {
    id: "transport",
    label: "transport",
    accessor: (e) => e.transport ?? "",
    render: (e) => (
      <span className="font-mono uppercase text-muted-foreground">{e.transport ?? "—"}</span>
    ),
  },
  {
    id: "source",
    label: "source",
    accessor: (e) => e.source_ip ?? "",
    render: (e) => (
      <span className="font-mono tabular-nums text-muted-foreground">
        {e.source_ip ? `${e.source_ip}${e.source_port ? `:${e.source_port}` : ""}` : "—"}
      </span>
    ),
  },
  {
    id: "destination",
    label: "destination",
    accessor: (e) => e.destination_domain ?? e.destination_ip ?? "",
    render: (e) => {
      if (!e.destination_ip && !e.destination_domain) return <span>—</span>;
      const port = e.destination_port ? `:${e.destination_port}` : "";
      return (
        <span className="font-mono tabular-nums">
          {e.destination_domain ? (
            <>
              {e.destination_domain}
              {e.destination_ip && (
                <span className="ml-1 text-muted-foreground">
                  ({e.destination_ip}
                  {port})
                </span>
              )}
            </>
          ) : (
            <>
              {e.destination_ip}
              {port}
            </>
          )}
        </span>
      );
    },
  },
  {
    id: "dns",
    label: "dns",
    accessor: (e) => e.dns_question_name ?? "",
    render: (e) => (
      <span className="font-mono text-muted-foreground">{e.dns_question_name ?? "—"}</span>
    ),
  },
];

const AUTH_COLUMNS: Column[] = [
  TIME_COL,
  ACTION_COL,
  {
    id: "outcome",
    label: "outcome",
    accessor: (e) => e.outcome ?? "",
    render: (e) => (
      <span
        className={cn(
          "font-mono uppercase",
          e.outcome === "failure" ? "text-sev-critical" : "text-muted-foreground",
        )}
      >
        {e.outcome ?? "—"}
      </span>
    ),
  },
  {
    id: "user",
    label: "user",
    accessor: (e) => e.user_name ?? "",
    render: (e) => <span className="font-mono">{e.user_name ?? "—"}</span>,
  },
  {
    id: "source_ip",
    label: "source",
    accessor: (e) => e.source_ip ?? "",
    render: (e) => (
      <span className="font-mono tabular-nums text-muted-foreground">{e.source_ip ?? "—"}</span>
    ),
  },
  {
    id: "provider",
    label: "provider",
    accessor: (e) => e.event_provider ?? "",
    render: (e) => (
      <span className="font-mono text-muted-foreground">{e.event_provider ?? "—"}</span>
    ),
  },
];

const MODULE_COLUMNS: Column[] = [
  TIME_COL,
  PID_COL,
  {
    id: "module_path",
    label: "module",
    accessor: (e) => e.module_path ?? e.file_path ?? "",
    render: (e) => (
      <span
        className="block max-w-xl truncate font-mono"
        title={e.module_path ?? e.file_path ?? undefined}
      >
        {e.module_path ?? e.file_path ?? "—"}
      </span>
    ),
  },
  {
    id: "signed",
    label: "signed",
    accessor: (e) => (e.module_signed == null ? "" : e.module_signed ? "yes" : "no"),
    render: (e) =>
      e.module_signed == null ? (
        <span className="text-muted-foreground">—</span>
      ) : e.module_signed ? (
        <span className="font-mono text-emerald-500">signed</span>
      ) : (
        <span className="font-mono text-sev-critical">unsigned</span>
      ),
  },
  {
    id: "signer",
    label: "signer",
    accessor: (e) => e.module_signer ?? "",
    render: (e) => (
      <span
        className="block max-w-xs truncate font-mono text-muted-foreground"
        title={e.module_signer ?? undefined}
      >
        {e.module_signer ?? "—"}
      </span>
    ),
  },
];

const OTHER_COLUMNS: Column[] = [
  TIME_COL,
  {
    id: "category",
    label: "category",
    accessor: (e) => e.category.join(","),
    render: (e) => (
      <span className="font-mono text-muted-foreground">{e.category.join(",") || "—"}</span>
    ),
  },
  ACTION_COL,
  PID_COL,
  {
    id: "target",
    label: "target",
    accessor: (e) => e.file_path ?? e.destination_ip ?? e.executable ?? e.command_line ?? "",
    render: (e) => (
      <span className="block max-w-xl truncate font-mono text-muted-foreground">
        {describeTarget(e)}
      </span>
    ),
  },
  RULE_COL,
];

const ALL_COLUMNS: Column[] = [
  TIME_COL,
  {
    id: "category",
    label: "category",
    accessor: (e) => e.category.join(","),
    render: (e) => (
      <span className="font-mono text-muted-foreground">{e.category.join(",") || "—"}</span>
    ),
  },
  ACTION_COL,
  PID_COL,
  {
    id: "target",
    label: "target",
    accessor: (e) => e.file_path ?? e.destination_ip ?? e.executable ?? e.command_line ?? "",
    render: (e) => (
      <span className="block max-w-xl truncate font-mono text-muted-foreground">
        {describeTarget(e)}
      </span>
    ),
  },
  RULE_COL,
];

// Which events land in which tab. Order matters: "library" must win
// over plain "file" because library loads ship under the file category
// too on some platforms.
type TabKey = "all" | "processes" | "files" | "network" | "auth" | "modules" | "other";

const TABS: { key: TabKey; label: string; columns: Column[] }[] = [
  { key: "all", label: "All", columns: ALL_COLUMNS },
  { key: "processes", label: "Processes", columns: PROCESS_COLUMNS },
  { key: "files", label: "Files", columns: FILE_COLUMNS },
  { key: "network", label: "Network", columns: NETWORK_COLUMNS },
  { key: "auth", label: "Auth", columns: AUTH_COLUMNS },
  { key: "modules", label: "Modules", columns: MODULE_COLUMNS },
  { key: "other", label: "Other", columns: OTHER_COLUMNS },
];

function tabFor(e: LiveTelemetryEvent): TabKey {
  const cats = e.category;
  if (cats.includes("library")) return "modules";
  if (cats.includes("process")) return "processes";
  if (cats.includes("network") || cats.includes("dns")) return "network";
  if (cats.includes("authentication")) return "auth";
  if (cats.includes("file")) return "files";
  return "other";
}

function bucketize(events: LiveTelemetryEvent[]): Record<TabKey, LiveTelemetryEvent[]> {
  const out: Record<TabKey, LiveTelemetryEvent[]> = {
    all: events,
    processes: [],
    files: [],
    network: [],
    auth: [],
    modules: [],
    other: [],
  };
  for (const e of events) out[tabFor(e)].push(e);
  return out;
}

interface Props {
  hostId: string;
}

export function HostLiveTelemetry({ hostId }: Props) {
  const [paused, setPaused] = useState(false);
  const [since, setSince] = useState<string | null>(null);
  const [tab, setTab] = useState<TabKey>("all");
  const [buffer, setBuffer] = useState<LiveTelemetryEvent[]>([]);
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();

  const { data, isError, error } = useQuery({
    queryKey: ["host-live-telemetry", hostId, since],
    queryFn: () => hostsApi.telemetry(hostId, since ? { since, limit: 200 } : { limit: 200 }),
    refetchInterval: paused ? false : POLL_MS,
    refetchIntervalInBackground: false,
  });

  // Merge new events into the rolling buffer + advance `since`.
  useEffect(() => {
    if (!data || !data.events.length) return;
    setBuffer((prev) => {
      const merged = [...prev, ...data.events];
      if (merged.length <= BUFFER_CAP) return merged;
      return merged.slice(merged.length - BUFFER_CAP);
    });
    if (data.latest_timestamp) setSince(data.latest_timestamp);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.latest_timestamp]);

  const buckets = useMemo(() => bucketize(buffer), [buffer]);
  const activeTab = TABS.find((t) => t.key === tab) ?? TABS[0];
  const columnLabels = useMemo(
    () => Object.fromEntries(activeTab.columns.map((c) => [c.id, c.label])),
    [activeTab],
  );
  const accessorMap = useMemo(
    () => new Map(activeTab.columns.map((c) => [c.id, c.accessor])),
    [activeTab],
  );

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">
            Live telemetry
            <span className="ml-2 text-xs font-normal tabular-nums text-muted-foreground">
              {buffer.length} buffered
              {paused ? " · paused" : ` · polling every ${POLL_MS / 1000}s`}
            </span>
          </CardTitle>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => setPaused((v) => !v)}>
              {paused ? (
                <>
                  <Play className="h-3.5 w-3.5" aria-hidden="true" /> Resume
                </>
              ) : (
                <>
                  <Pause className="h-3.5 w-3.5" aria-hidden="true" /> Pause
                </>
              )}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setBuffer([]);
                setSince(null);
              }}
              title="Clear buffer + reseed from the recent backlog on next poll"
            >
              <Trash className="h-3.5 w-3.5" aria-hidden="true" /> Clear
            </Button>
          </div>
        </div>
        {isError && (
          <p className="mt-1 text-xs text-destructive" role="alert">
            {error instanceof Error ? error.message : "telemetry feed error"}
          </p>
        )}
      </CardHeader>
      <CardContent className="p-0">
        <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
          <TabsList className="mx-3 mt-1">
            {TABS.map((t) => (
              <TabsTrigger key={t.key} value={t.key}>
                <span>{t.label}</span>
                <span className="ml-1.5 rounded-sm bg-muted px-1 font-mono text-[10px] tabular-nums text-muted-foreground">
                  {buckets[t.key].length}
                </span>
              </TabsTrigger>
            ))}
          </TabsList>
          {TABS.map((t) => (
            <TabsContent key={t.key} value={t.key} className="mt-0">
              <div className="px-3 py-2">
                <FilterChipBar
                  tableId={`host-live-${hostId}-${t.key}`}
                  filters={columnFilters}
                  columnLabels={columnLabels}
                  onRemove={(i) => setColumnFilters(columnFilters.filter((_, j) => j !== i))}
                  onClear={() => setColumnFilters([])}
                  onApply={setColumnFilters}
                />
              </div>
              <TelemetryTable
                events={buckets[t.key]}
                columns={t.columns}
                accessorMap={accessorMap}
                columnFilters={columnFilters}
                onAddFilter={(f) => setColumnFilters([...columnFilters, f])}
              />
            </TabsContent>
          ))}
        </Tabs>
      </CardContent>
    </Card>
  );
}

interface TableProps {
  events: LiveTelemetryEvent[];
  columns: Column[];
  accessorMap: Map<string, Column["accessor"]>;
  columnFilters: ReturnType<typeof useColumnFilters>["filters"];
  onAddFilter: (f: ReturnType<typeof useColumnFilters>["filters"][number]) => void;
}

function TelemetryTable({ events, columns, accessorMap, columnFilters, onAddFilter }: TableProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    if (columnFilters.length === 0) return events;
    return applyFilters(events, columnFilters, (row, col) => accessorMap.get(col)?.(row));
  }, [events, columnFilters, accessorMap]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    if (nearBottom) el.scrollTop = el.scrollHeight;
  }, [filtered.length]);

  return (
    <div ref={scrollRef} className="max-h-[640px] overflow-auto" aria-live="polite">
      <table className="w-full text-xs">
        <thead className="sticky top-0 z-10 bg-card">
          <tr className="border-b text-left text-muted-foreground">
            {columns.map((c) => (
              <th key={c.id} className={cn("px-3 py-2 font-medium", c.className)}>
                <ColumnHeaderFilter colId={c.id} label={c.label} onAdd={onAddFilter} />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-3 py-6 text-center text-muted-foreground">
                {events.length === 0 ? "Waiting for telemetry…" : "No events match the filters."}
              </td>
            </tr>
          )}
          {filtered.map((e) => {
            const isFailure = e.outcome === "failure";
            const isAlert = e.category.includes("intrusion_detection");
            return (
              <tr
                key={e.event_id}
                className={cn(
                  "border-b border-border/40 align-top",
                  isAlert && "bg-sev-critical/5",
                  isFailure && !isAlert && "bg-sev-medium/5",
                )}
              >
                {columns.map((c) => (
                  <td key={c.id} className="px-3 py-1.5">
                    {c.render(e)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function describeTarget(e: LiveTelemetryEvent): string {
  if (e.file_path) return e.file_path;
  if (e.destination_domain) return e.destination_domain;
  if (e.destination_ip) {
    const port = e.destination_port ? `:${e.destination_port}` : "";
    const proto = e.transport ? `${e.transport} ` : "";
    return `${proto}${e.destination_ip}${port}`;
  }
  if (e.executable) return e.executable;
  if (e.command_line) return e.command_line;
  return "—";
}
