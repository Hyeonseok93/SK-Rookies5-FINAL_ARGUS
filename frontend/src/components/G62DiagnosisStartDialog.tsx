import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { G62DiagnosisOptionsPanel } from "./G62DiagnosisOptionsPanel";
import {
  DEFAULT_G62_OPTIONS,
  g62OptionsSummary,
  type G62DiagnosisOptions,
} from "../lib/g62DiagnosisOptions";

export function G62DiagnosisStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: G62DiagnosisOptions;
  onClose: () => void;
  onStart: (options: G62DiagnosisOptions) => void;
}) {
  const [options, setOptions] = useState<G62DiagnosisOptions>(DEFAULT_G62_OPTIONS);

  useEffect(() => {
    if (open) setOptions(initialOptions);
  }, [open, initialOptions]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="g62-start-title"
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-xl border border-cyber-border/60 bg-cyber-panel shadow-xl"
      >
        <div className="sticky top-0 z-10 flex items-start justify-between border-b border-cyber-border/40 bg-cyber-panel px-4 py-3">
          <div>
            <h2 id="g62-start-title" className="font-display text-base font-semibold text-white">
              6-2 Diagnosis options
            </h2>
            <p className="mt-1 text-[10px] text-cyber-muted">
              로그인 실패 메시지 일괄 처리 (A/B 비교)
            </p>
            <p className="mt-1 font-mono text-[10px] text-cyan-300/80">{g62OptionsSummary(options)}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-cyber-muted hover:bg-cyber-border/30 hover:text-white"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="px-4 py-3">
          <G62DiagnosisOptionsPanel options={options} onChange={setOptions} />
        </div>

        <div className="sticky bottom-0 flex justify-end gap-2 border-t border-cyber-border/40 bg-cyber-panel px-4 py-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded border border-cyber-border/60 px-3 py-1.5 text-xs text-cyber-muted hover:text-white"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onStart(options)}
            className="rounded bg-cyan-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-cyan-500"
          >
            Start 6-2
          </button>
        </div>
      </div>
    </div>
  );
}
