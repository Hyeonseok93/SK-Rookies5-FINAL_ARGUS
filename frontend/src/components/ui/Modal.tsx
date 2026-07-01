import { useEffect, type ReactNode } from "react";
import { X } from "lucide-react";

export function Modal({
  open,
  titleId,
  onClose,
  children,
  className = "relative z-10 w-full max-w-lg rounded-xl border border-cyber-border bg-cyber-panel p-5 shadow-2xl",
}: {
  open: boolean;
  titleId: string;
  onClose: () => void;
  children: ReactNode;
  className?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" aria-hidden />
      <div role="dialog" aria-modal="true" aria-labelledby={titleId} className={className}>
        {children}
      </div>
    </div>
  );
}

export function ModalHeader({
  titleId,
  title,
  description,
  summary,
  onClose,
}: {
  titleId: string;
  title: string;
  description?: string;
  summary?: string;
  onClose: () => void;
}) {
  return (
    <div className="mb-4 flex items-start justify-between gap-3">
      <div>
        <h2 id={titleId} className="font-display text-base font-semibold text-white">
          {title}
        </h2>
        {description ? <p className="mt-1 text-xs text-cyber-muted">{description}</p> : null}
        {summary ? (
          <p className="mt-1 font-mono text-[10px] text-cyan-300/80">{summary}</p>
        ) : null}
      </div>
      <button
        type="button"
        onClick={onClose}
        className="rounded p-1 text-cyber-muted transition hover:bg-cyber-border/30 hover:text-white"
        aria-label="Close"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

export function ModalFooter({
  children,
  className = "mt-4 flex justify-end gap-2",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={className}>{children}</div>;
}
