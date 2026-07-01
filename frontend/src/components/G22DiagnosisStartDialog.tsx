import { useEffect, useState } from "react";
import { Stethoscope, X } from "lucide-react";
import { G22DiagnosisOptionsPanel } from "./G22DiagnosisOptionsPanel";
import {
  DEFAULT_G22_OPTIONS,
  g22OptionsSummary,
  type G22DiagnosisOptions,
} from "../lib/g22DiagnosisOptions";

export function G22DiagnosisStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: G22DiagnosisOptions;
  onClose: () => void;
  onStart: (options: G22DiagnosisOptions) => void;
}) {
  const [options, setOptions] = useState<G22DiagnosisOptions>(DEFAULT_G22_OPTIONS);

  useEffect(() => {
    if (open) setOptions(initialOptions);
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
        aria-labelledby="g22-start-title"
        className="relative z-10 max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-xl border border-cyber-border bg-cyber-panel p-5 shadow-2xl"
      >
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 id="g22-start-title" className="font-display text-base font-semibold text-white">
              2-2 Diagnosis options
            </h2>
            <p className="mt-1 text-xs text-cyber-muted">
              중요 정보 파일 다운로드 — 실행 전 방법과 한도를 선택하세요.
            </p>
            <p className="mt-1 font-mono text-[10px] text-cyan-300/80">
              {g22OptionsSummary(options)}
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

        <G22DiagnosisOptionsPanel options={options} onChange={setOptions} />

        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => onStart(options)}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-500/25"
          >
            <Stethoscope className="h-3.5 w-3.5" />
            Start 2-2
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
