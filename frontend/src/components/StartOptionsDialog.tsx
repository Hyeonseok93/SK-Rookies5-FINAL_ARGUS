import { useEffect, useState, type ReactNode } from "react";
import { ShieldCheck } from "lucide-react";
import { Modal, ModalFooter, ModalHeader } from "./ui/Modal";

export function StartOptionsDialog<T>({
  open,
  titleId,
  title,
  description,
  summary,
  initialOptions,
  defaultOptions,
  onClose,
  onStart,
  startLabel = "Start",
  isStartDisabled,
  children,
}: {
  open: boolean;
  titleId: string;
  title: string;
  description?: string;
  summary?: string;
  initialOptions: T;
  defaultOptions: T;
  onClose: () => void;
  onStart: (options: T) => void;
  startLabel?: string;
  isStartDisabled?: (options: T) => boolean;
  children: (options: T, setOptions: (next: T) => void) => ReactNode;
}) {
  const [options, setOptions] = useState<T>(defaultOptions);

  useEffect(() => {
    if (open) setOptions(initialOptions);
  }, [open, initialOptions]);

  return (
    <Modal open={open} titleId={titleId} onClose={onClose}>
      <ModalHeader
        titleId={titleId}
        title={title}
        description={description}
        summary={summary}
        onClose={onClose}
      />
      {children(options, setOptions)}
      <ModalFooter>
        <button
          type="button"
          disabled={isStartDisabled?.(options) ?? false}
          onClick={() => onStart(options)}
          className="flex items-center gap-1.5 rounded-lg border border-violet-400/50 bg-violet-500/15 px-4 py-2 text-xs font-semibold text-violet-300 transition hover:bg-violet-500/25 disabled:opacity-40"
        >
          <ShieldCheck className="h-3.5 w-3.5" />
          {startLabel}
        </button>
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg border border-cyber-border px-4 py-2 text-xs font-medium text-cyber-muted transition hover:border-cyber-border/80 hover:text-white"
        >
          Cancel
        </button>
      </ModalFooter>
    </Modal>
  );
}
