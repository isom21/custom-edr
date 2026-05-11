/**
 * Generic column-filter engine shared by every Vigil table.
 *
 * Each filter is `{col, op, value}`. The engine groups filters by column
 * and combines them like this:
 *
 *   - Between columns: AND.
 *   - Same column, positive operators (eq, contains):    OR.
 *   - Same column, negative operators (ne, not_contains): AND.
 *
 * Rationale: "host = lab-windows OR host = lab-linux" is the natural
 * intent when stacking positive filters on one column. "host != foo AND
 * host != bar" is the natural intent for negatives — you're excluding
 * two specific things, not "either".
 *
 * Filter state lives in the URL (`?cf=<json>`) so views are shareable.
 * Saved filter sets live in localStorage so a user can name a combo and
 * re-apply it later.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

export type FilterOp = "eq" | "ne" | "contains" | "not_contains";

export const FILTER_OPS: { value: FilterOp; label: string; short: string }[] = [
  { value: "eq", label: "equals", short: "=" },
  { value: "ne", label: "not equals", short: "≠" },
  { value: "contains", label: "contains", short: "⊃" },
  { value: "not_contains", label: "not contains", short: "⊅" },
];

export const POSITIVE_OPS: ReadonlySet<FilterOp> = new Set(["eq", "contains"]);

export interface Filter {
  col: string;
  op: FilterOp;
  value: string;
}

export interface SavedFilterSet {
  id: string;
  name: string;
  filters: Filter[];
  created_at: string;
}

/** Normalize anything cell-like to a comparable lowercase string. */
function toCmp(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (v instanceof Date) return v.toISOString();
  if (typeof v === "object") {
    try {
      return JSON.stringify(v).toLowerCase();
    } catch {
      return String(v).toLowerCase();
    }
  }
  return String(v).toLowerCase();
}

function matchOne(rowVal: unknown, f: Filter): boolean {
  const v = toCmp(rowVal);
  const needle = f.value.toLowerCase();
  switch (f.op) {
    case "eq":
      return v === needle;
    case "ne":
      return v !== needle;
    case "contains":
      return v.includes(needle);
    case "not_contains":
      return !v.includes(needle);
  }
}

/**
 * Apply the column-filter logic to `rows`.
 *
 * `rowValue(row, col)` extracts the filterable value for a given column id;
 * callers wire this from `ColumnDef.filterValue`.
 */
export function applyFilters<T>(
  rows: T[],
  filters: Filter[],
  rowValue: (row: T, col: string) => unknown,
): T[] {
  if (filters.length === 0) return rows;
  // Group filters by column once.
  const byCol = new Map<string, Filter[]>();
  for (const f of filters) {
    if (!f.value) continue; // empty value = no-op
    const arr = byCol.get(f.col);
    if (arr) arr.push(f);
    else byCol.set(f.col, [f]);
  }
  if (byCol.size === 0) return rows;
  return rows.filter((row) => {
    for (const [col, fs] of byCol.entries()) {
      const val = rowValue(row, col);
      // Positives OR-combine, negatives AND-combine, within the column.
      const positives = fs.filter((f) => POSITIVE_OPS.has(f.op));
      const negatives = fs.filter((f) => !POSITIVE_OPS.has(f.op));
      const posOk = positives.length === 0 || positives.some((f) => matchOne(val, f));
      const negOk = negatives.every((f) => matchOne(val, f));
      if (!(posOk && negOk)) return false;
    }
    return true;
  });
}

/** URL-encode a filter list compactly. Empty list -> param omitted. */
function encodeFilters(filters: Filter[]): string | null {
  const trimmed = filters.filter((f) => f.value !== "");
  if (trimmed.length === 0) return null;
  // Short keys keep URLs tolerable for ~6+ filters.
  const compact = trimmed.map((f) => ({ c: f.col, o: f.op, v: f.value }));
  return JSON.stringify(compact);
}

function decodeFilters(raw: string | null): Filter[] {
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((x) => x && typeof x === "object" && typeof x.c === "string")
      .map((x) => ({ col: x.c, op: x.o ?? "contains", value: String(x.v ?? "") }));
  } catch {
    return [];
  }
}

/**
 * URL-backed column-filter state. Mirrors useTableQuery's pattern but
 * lives under `?cf=` so it doesn't collide with the existing key-based
 * filter params (state, severity, host_hostname, …).
 */
export function useColumnFilters() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("cf");
  const filters = useMemo(() => decodeFilters(raw), [raw]);

  const setFilters = useCallback(
    (next: Filter[]) => {
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          const enc = encodeFilters(next);
          if (enc) p.set("cf", enc);
          else p.delete("cf");
          p.delete("offset");
          return p;
        },
        { replace: false },
      );
    },
    [setParams],
  );

  const addFilter = useCallback((f: Filter) => setFilters([...filters, f]), [filters, setFilters]);
  const removeFilter = useCallback(
    (idx: number) => setFilters(filters.filter((_, i) => i !== idx)),
    [filters, setFilters],
  );
  const clearFilters = useCallback(() => setFilters([]), [setFilters]);

  return { filters, setFilters, addFilter, removeFilter, clearFilters };
}

/**
 * Persisted saved-filter sets, keyed by table id. Each entry stores its
 * own filter array so applying a saved set is a single setFilters call.
 */
export function useSavedFilterSets(tableId: string) {
  const storageKey = `vigil:saved-filters:${tableId}`;
  const [sets, setSets] = useState<SavedFilterSet[]>(() => {
    try {
      const raw = localStorage.getItem(storageKey);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(sets));
    } catch {
      // localStorage full / disabled — degrade silently.
    }
  }, [sets, storageKey]);

  const save = useCallback((name: string, filters: Filter[]): SavedFilterSet => {
    const set: SavedFilterSet = {
      id: globalThis.crypto.randomUUID(),
      name,
      filters,
      created_at: new Date().toISOString(),
    };
    setSets((prev) => [...prev, set]);
    return set;
  }, []);

  const remove = useCallback((id: string) => {
    setSets((prev) => prev.filter((s) => s.id !== id));
  }, []);

  const rename = useCallback((id: string, name: string) => {
    setSets((prev) => prev.map((s) => (s.id === id ? { ...s, name } : s)));
  }, []);

  return { sets, save, remove, rename };
}
