/**
 * Confirmation dialog for irreversible / destructive actions.
 *
 * Single-click destructive surfaces (revoke, disable a self-protection
 * rule, delete) live behind this so a misplaced trackpad tap can't
 * tear something down. Layered on the existing shadcn Dialog primitive
 * (no extra Radix dep) and re-exports the same focus-trap / escape-
 * to-close behaviour.
 *
 * Usage:
 *   <ConfirmDestructive
 *     title="Revoke enrollment token?"
 *     description={<>This invalidates <code>{label}</code>…</>}
 *     confirmLabel="Yes, revoke"
 *     onConfirm={() => revoke.mutate(id)}
 *     pending={revoke.isPending}
 *     trigger={<Button variant="ghost" size="sm">revoke</Button>}
 *   />
 */
import { type ReactElement, type ReactNode, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

interface Props {
  /** The element that opens the dialog when clicked (e.g. the existing destructive Button). */
  trigger: ReactElement;
  /** Question phrasing (ends with "?"). Should clearly name the resource. */
  title: string;
  /** Optional context — what does confirming actually do? */
  description?: ReactNode;
  /** Confirm-button label, in active voice ("Yes, revoke" / "Yes, delete"). */
  confirmLabel: string;
  /** Called when the operator clicks the confirm button. Errors are caller-handled. */
  onConfirm: () => void | Promise<void>;
  /** Disables the confirm button while the underlying mutation is in flight. */
  pending?: boolean;
}

export function ConfirmDestructive({
  trigger,
  title,
  description,
  confirmLabel,
  onConfirm,
  pending,
}: Props) {
  const [open, setOpen] = useState(false);

  const handleConfirm = async () => {
    await Promise.resolve(onConfirm());
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={pending}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleConfirm} disabled={pending}>
            {pending ? "Working…" : confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
