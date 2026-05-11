/**
 * Above-table strip that shows the active column filters as chips +
 * star-saved filter sets the operator can re-apply with one click.
 *
 * Empty state hides the whole strip so unfiltered tables aren't noisy.
 */
import { useEffect, useRef, useState } from "react";
import { Star, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import {
  FILTER_OPS,
  POSITIVE_OPS,
  type Filter,
  type SavedFilterSet,
  useSavedFilterSets,
} from "@/lib/table-filters";

interface Props {
  /** Stable id used to scope saved sets in localStorage. */
  tableId: string;
  filters: Filter[];
  /** Column id -> display label, so chips show "Host = lab-linux" not "host_id = …". */
  columnLabels: Record<string, string>;
  onRemove: (index: number) => void;
  onClear: () => void;
  onApply: (filters: Filter[]) => void;
}

function opLabel(op: Filter["op"]): string {
  return FILTER_OPS.find((o) => o.value === op)?.short ?? op;
}

function colorFor(op: Filter["op"]): string {
  return POSITIVE_OPS.has(op)
    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
    : "border-rose-500/30 bg-rose-500/10 text-rose-200";
}

export function FilterChipBar({
  tableId,
  filters,
  columnLabels,
  onRemove,
  onClear,
  onApply,
}: Props) {
  const { sets, save, remove } = useSavedFilterSets(tableId);
  const [showSave, setShowSave] = useState(false);
  const [name, setName] = useState("");
  const [savedOpen, setSavedOpen] = useState(false);
  const savedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!savedOpen) return;
    const onDown = (e: globalThis.MouseEvent) => {
      if (!savedRef.current?.contains(e.target as globalThis.Node)) setSavedOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [savedOpen]);

  const hasFilters = filters.length > 0;
  const hasSets = sets.length > 0;
  if (!hasFilters && !hasSets) return null;

  const doSave = () => {
    if (!name.trim() || !hasFilters) return;
    save(name.trim(), filters);
    setName("");
    setShowSave(false);
  };

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border bg-secondary/30 px-3 py-2 text-xs">
      {hasFilters && (
        <>
          {filters.map((f, i) => (
            <span
              key={`${f.col}-${f.op}-${f.value}-${i}`}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono",
                colorFor(f.op),
              )}
            >
              <span className="font-medium">{columnLabels[f.col] ?? f.col}</span>
              <span>{opLabel(f.op)}</span>
              <span className="max-w-[14rem] truncate">{f.value}</span>
              <button
                type="button"
                onClick={() => onRemove(i)}
                className="ml-0.5 rounded-full p-0.5 hover:bg-background/40"
                aria-label="Remove filter"
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
          <Button size="sm" variant="ghost" onClick={onClear}>
            Clear all
          </Button>
          <div className="relative">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowSave((v) => !v)}
              title="Save the current filter set"
            >
              <Star className="h-3.5 w-3.5" /> Save set
            </Button>
            {showSave && (
              <div className="absolute right-0 top-full z-50 mt-1 w-64 rounded-md border bg-card p-3 shadow-lg">
                <p className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">
                  Name this set
                </p>
                <Input
                  autoFocus
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") doSave();
                  }}
                  placeholder="e.g. high-sev open alerts"
                  className="h-8 text-xs"
                />
                <div className="mt-2 flex justify-end gap-2">
                  <Button size="sm" variant="ghost" onClick={() => setShowSave(false)}>
                    Cancel
                  </Button>
                  <Button size="sm" onClick={doSave} disabled={!name.trim()}>
                    Save
                  </Button>
                </div>
              </div>
            )}
          </div>
        </>
      )}
      {hasSets && (
        <div className="relative ml-auto" ref={savedRef}>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setSavedOpen((v) => !v)}
            title="Apply a saved filter set"
          >
            <Star className="h-3.5 w-3.5 fill-amber-400 text-amber-400" />
            Saved ({sets.length})
          </Button>
          {savedOpen && (
            <div className="absolute right-0 top-full z-50 mt-1 w-72 rounded-md border bg-card shadow-lg">
              <ul className="max-h-80 overflow-auto">
                {sets.map((s: SavedFilterSet) => (
                  <li
                    key={s.id}
                    className="flex items-center justify-between border-b border-border/40 px-3 py-2 last:border-0 hover:bg-secondary/40"
                  >
                    <button
                      type="button"
                      onClick={() => {
                        onApply(s.filters);
                        setSavedOpen(false);
                      }}
                      className="min-w-0 flex-1 text-left"
                    >
                      <div className="truncate text-sm font-medium">{s.name}</div>
                      <div className="text-[10px] text-muted-foreground">
                        {s.filters.length} filter{s.filters.length === 1 ? "" : "s"} ·{" "}
                        {new Date(s.created_at).toLocaleDateString()}
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => remove(s.id)}
                      className="ml-2 rounded-full p-1 text-muted-foreground hover:bg-background/40 hover:text-destructive"
                      aria-label="Delete saved set"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
