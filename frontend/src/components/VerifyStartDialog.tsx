import { useEffect, useState } from "react";
import { ShieldCheck, X } from "lucide-react";
import { VerifyOptionsPanel } from "./VerifyOptionsPanel";
import { DEFAULT_VERIFY_OPTIONS, type VerifyOptions } from "../lib/verifyOptions";

export function VerifyStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: VerifyOptions;
  onClose: () => void;
  onStart: (options: VerifyOptions) => void;
}) {
  const [options, setOptions] = useState<VerifyOptions>(DEFAULT_VERIFY_OPTIONS);

  useEffect(() => {
    if (open) {
      setOptions(initialOptions);
    }
  }, [open, initialOptions]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const noneSelected = !options.useHttpx && !options.useSpider && !options.useAjaxSpider;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" aria-hidden />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="verify-start-title"
        className="relative z-10 w-full max-w-lg rounded-xl border border-cyber-border bg-cyber-panel p-5 shadow-2xl"
      >
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 id="verify-start-title" className="font-display text-base font-semibold text-white">
              Verify options
            </h2>
            <p className="mt-1 text-xs text-cyber-muted">
              Ready {">"} Verified — 실행 전에 방법을 선택하세요.
            </p>
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

        <VerifyOptionsPanel options={options} onChange={setOptions} />

        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            disabled={noneSelected}
            onClick={() => onStart(options)}
            className="flex items-center gap-1.5 rounded-lg border border-violet-400/50 bg-violet-500/15 px-4 py-2 text-xs font-semibold text-violet-300 transition hover:bg-violet-500/25 disabled:opacity-40"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            Start Verify
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-cyber-border px-4 py-2 text-xs font-medium text-cyber-muted transition hover:border-cyber-border/80 hover:text-white"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
