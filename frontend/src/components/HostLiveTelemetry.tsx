/**
 * M20.j: per-host live telemetry feed.
 *
 * Polls `GET /api/hosts/:id/telemetry?since=<iso>` every 2s and
 * appends new events to a rolling client-side buffer (cap 2000) so
 * the table behaves like a tail without unbounded memory growth.
 * Pause toggle stops polling without dropping the buffer.
 *
 * Each row is a flattened ECS doc — pid, action, target — same shape
 * the investigation timeline uses, plus rule attribution and SHA-256
 * when the event was hashed. A category filter narrows the view.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Pause, Play, Trash } from "lucide-react";
import { hostsApi } from "@/api/hosts";
import { ColumnHeaderFilter } from "@/components/data-table/ColumnHeaderFilter";
import { FilterChipBar } from "@/components/data-table/FilterChipBar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/select";
import { applyFilters, useColumnFilters } from "@/lib/table-filters";
import { cn } from "@/lib/utils";
import type { LiveTelemetryEvent } from "@/types/api";

// Column-id -> filterable value extractor + display label.
// Mirrors the ColumnDef accessor pattern from the DataTable, but inline
// because this table doesn't use DataTable.
const LIVE_COLUMNS: { id: string; label: string; accessor: (e: LiveTelemetryEvent) => unknown }[] =
  [
    { id: "time", label: "time", accessor: (e) => e.timestamp },
    { id: "category", label: "category", accessor: (e) => e.category.join(",") },
    { id: "action", label: "action", accessor: (e) => e.action ?? "" },
    { id: "pid", label: "pid", accessor: (e) => e.pid ?? "" },
    {
      id: "target",
      label: "target",
      accessor: (e) => e.file_path ?? e.destination_ip ?? e.executable ?? e.command_line ?? "",
    },
    { id: "rule", label: "rule", accessor: (e) => e.rule_name ?? "" },
  ];
const LIVE_LABELS = Object.fromEntries(LIVE_COLUMNS.map((c) => [c.id, c.label]));

const POLL_MS = 2000;
const BUFFER_CAP = 2000;
const CATEGORIES = [
  "all",
  "process",
  "file",
  "network",
  "registry",
  "authentication",
  "intrusion_detection",
] as const;

type Category = (typeof CATEGORIES)[number];

interface Props {
  hostId: string;
}

export function HostLiveTelemetry({ hostId }: Props) {
  const [paused, setPaused] = useState(false);
  const [since, setSince] = useState<string | null>(null);
  const [category, setCategory] = useState<Category>("all");
  const [buffer, setBuffer] = useState<LiveTelemetryEvent[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);
  // Column filters share the same URL param + saved-set storage as the
  // server-side tables. Live telemetry filters always run client-side.
  const { filters: columnFilters, setFilters: setColumnFilters } = useColumnFilters();
  const accessorMap = useMemo(() => new Map(LIVE_COLUMNS.map((c) => [c.id, c.accessor])), []);

  const { data, isError, error } = useQuery({
    queryKey: ["host-live-telemetry", hostId, since],
    queryFn: () => hostsApi.telemetry(hostId, since ? { since, limit: 200 } : { limit: 200 }),
    refetchInterval: paused ? false : POLL_MS,
    refetchIntervalInBackground: false,
  });

  // Merge new events into the rolling buffer + advance `since`.
  // Keying on data.latest_timestamp prevents re-applying the same
  // batch when react-query returns the cached result on a stale tick.
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

  // Auto-scroll to bottom when new events arrive — but only if the
  // user is already near the bottom, so they can scroll up to inspect
  // without being yanked back every tick.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    if (nearBottom) el.scrollTop = el.scrollHeight;
  }, [buffer]);

  const filtered = useMemo(() => {
    const byCategory =
      category === "all" ? buffer : buffer.filter((e) => e.category.includes(category));
    if (columnFilters.length === 0) return byCategory;
    return applyFilters(byCategory, columnFilters, (row, col) => accessorMap.get(col)?.(row));
  }, [buffer, category, columnFilters, accessorMap]);

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">
            Live telemetry
            <span className="ml-2 text-xs font-normal text-muted-foreground">
              {filtered.length} of {buffer.length} buffered
              {paused ? " · paused" : ` · polling every ${POLL_MS / 1000}s`}
            </span>
          </CardTitle>
          <div className="flex items-center gap-2">
            <Select
              value={category}
              onChange={(e) => setCategory(e.target.value as Category)}
              className="h-8 w-44"
            >
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
            <Button size="sm" variant="outline" onClick={() => setPaused((v) => !v)}>
              {paused ? (
                <>
                  <Play className="h-3.5 w-3.5" /> Resume
                </>
              ) : (
                <>
                  <Pause className="h-3.5 w-3.5" /> Pause
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
              <Trash className="h-3.5 w-3.5" /> Clear
            </Button>
          </div>
        </div>
        {isError && (
          <p className="mt-1 text-xs text-destructive">
            {error instanceof Error ? error.message : "telemetry feed error"}
          </p>
        )}
        <div className="mt-2">
          <FilterChipBar
            tableId={`host-live-${hostId}`}
            filters={columnFilters}
            columnLabels={LIVE_LABELS}
            onRemove={(i) => setColumnFilters(columnFilters.filter((_, j) => j !== i))}
            onClear={() => setColumnFilters([])}
            onApply={setColumnFilters}
          />
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div ref={scrollRef} className="max-h-[640px] overflow-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card">
              <tr className="border-b text-left text-muted-foreground">
                {LIVE_COLUMNS.map((c) => (
                  <th key={c.id} className="px-3 py-2 font-medium">
                    <ColumnHeaderFilter
                      colId={c.id}
                      label={c.label}
                      onAdd={(f) => setColumnFilters([...columnFilters, f])}
                    />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-6 text-center text-muted-foreground">
                    {buffer.length === 0
                      ? "waiting for telemetry…"
                      : `no events match the "${category}" filter`}
                  </td>
                </tr>
              )}
              {filtered.map((e) => (
                <TelemetryRow key={e.event_id} event={e} />
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

function TelemetryRow({ event }: { event: LiveTelemetryEvent }) {
  const isFailure = event.outcome === "failure";
  const isAlert = event.category.includes("intrusion_detection");
  return (
    <tr
      className={cn(
        "border-b border-border/40 align-top",
        isAlert && "bg-sev-critical/5",
        isFailure && !isAlert && "bg-sev-medium/5",
      )}
    >
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-muted-foreground">
        {new Date(event.timestamp).toLocaleTimeString()}
      </td>
      <td className="px-3 py-1.5 font-mono text-muted-foreground">
        {event.category.join(",") || "—"}
      </td>
      <td className="px-3 py-1.5 font-mono">
        {event.action ?? "—"}
        {isFailure && <span className="ml-1 text-sev-critical">✕</span>}
      </td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-muted-foreground">
        {event.pid ?? "—"}
      </td>
      <td className="px-3 py-1.5 font-mono break-all text-muted-foreground">
        {describeTarget(event)}
      </td>
      <td className="px-3 py-1.5 text-muted-foreground">{event.rule_name ?? "—"}</td>
    </tr>
  );
}

function describeTarget(e: LiveTelemetryEvent): string {
  if (e.file_path) return e.file_path;
  if (e.destination_ip) {
    const port = e.destination_port ? `:${e.destination_port}` : "";
    const proto = e.transport ? `${e.transport} ` : "";
    return `${proto}${e.destination_ip}${port}`;
  }
  if (e.executable) return e.executable;
  if (e.command_line) return e.command_line;
  return "—";
}
