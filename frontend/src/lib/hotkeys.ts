/**
 * Minimal keyboard-shortcut hook.
 *
 * Matches against `key` only (no chords); the caller passes a map
 * like `{ "g h": () => navigate("/hosts") }` for two-keystroke
 * sequences — the hook holds an in-memory buffer that decays after
 * 1s. Single keys fire immediately.
 *
 * Always skips when focus is in an input / textarea / contenteditable
 * so typing into the search box doesn't trip global shortcuts.
 */
/* global EventTarget, KeyboardEvent */
import { useEffect } from "react";

export type HotkeyHandler = (e: KeyboardEvent) => void;

const SEQUENCE_RESET_MS = 800;

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return true;
  if (target.isContentEditable) return true;
  return false;
}

export function useHotkeys(map: Record<string, HotkeyHandler>): void {
  useEffect(() => {
    let buffer = "";
    let bufferAt = 0;

    const onKeyDown = (e: KeyboardEvent) => {
      if (isTypingTarget(e.target)) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;

      // Build the chord key. For single-letter keys we also try the
      // raw character so handlers like "?" or "/" work without needing
      // to spell out "Shift+/".
      const k = e.key;
      const now = Date.now();
      if (now - bufferAt > SEQUENCE_RESET_MS) buffer = "";
      bufferAt = now;
      const candidate = buffer ? `${buffer} ${k}` : k;
      if (candidate in map) {
        map[candidate](e);
        e.preventDefault();
        buffer = "";
        return;
      }
      // No direct match — if any registered key starts with this k,
      // open a one-letter buffer; otherwise reset.
      const startsWith = Object.keys(map).some((key) => key.startsWith(`${k} `));
      buffer = startsWith ? k : "";
    };

    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [map]);
}
