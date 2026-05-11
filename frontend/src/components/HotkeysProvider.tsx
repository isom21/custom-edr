/**
 * M22.e: global keyboard shortcuts + cheat-sheet modal.
 *
 * Sits at layout level. Owns the hotkey map and the cheat-sheet open
 * state. The `?` key opens the modal; navigation shortcuts (g + letter)
 * jump between top-level pages. `/` focuses the first search-style
 * input on the page so the operator can start typing immediately.
 */
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useHotkeys } from "@/lib/hotkeys";

const SHORTCUTS: { keys: string; what: string }[] = [
  { keys: "?", what: "Open this cheat sheet" },
  { keys: "/", what: "Focus the search input on the current page" },
  { keys: "g a", what: "Go to Alerts" },
  { keys: "g h", what: "Go to Hosts" },
  { keys: "g r", what: "Go to Rules" },
  { keys: "g c", what: "Go to Commands" },
  { keys: "g q", what: "Go to Quarantine" },
  { keys: "g d", what: "Go to Dashboard" },
  { keys: "g u", what: "Go to Users (admin)" },
  { keys: "g l", what: "Go to Audit log (admin)" },
];

export function HotkeysProvider() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  const map = useMemo(
    () => ({
      "?": () => setOpen((v) => !v),
      "/": () => {
        // Focus the first search-ish input on the current page.
        const candidates = Array.from(document.querySelectorAll<HTMLInputElement>("input")).filter(
          (el) => {
            const ph = (el.placeholder || "").toLowerCase();
            return el.type === "search" || ph.includes("search");
          },
        );
        candidates[0]?.focus();
      },
      "g a": () => navigate("/alerts"),
      "g h": () => navigate("/hosts"),
      "g r": () => navigate("/rules"),
      "g c": () => navigate("/commands"),
      "g q": () => navigate("/quarantine"),
      "g d": () => navigate("/dashboard"),
      "g u": () => navigate("/users"),
      "g l": () => navigate("/audit"),
    }),
    [navigate],
  );
  useHotkeys(map);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            Single-letter keys fire immediately. Two-key sequences (e.g. <kbd>g</kbd> <kbd>a</kbd>)
            reset after a short pause. Shortcuts are ignored while typing in any input or textarea.
          </DialogDescription>
        </DialogHeader>
        <ul className="space-y-2 text-sm">
          {SHORTCUTS.map((s) => (
            <li key={s.keys} className="flex items-center justify-between">
              <span className="text-muted-foreground">{s.what}</span>
              <span className="font-mono text-xs">
                {s.keys.split(" ").map((k, i) => (
                  <span key={`${k}-${i}`}>
                    {i > 0 && <span className="mx-1 text-muted-foreground">then</span>}
                    <kbd className="rounded border bg-muted/50 px-1.5 py-0.5">{k}</kbd>
                  </span>
                ))}
              </span>
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  );
}
