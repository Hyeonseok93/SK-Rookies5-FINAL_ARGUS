import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { G74DiagnosisOptionsPanel } from "./G74DiagnosisOptionsPanel";
import {
  DEFAULT_G74_OPTIONS,
  g74OptionsSummary,
  type G74DiagnosisOptions,
} from "../lib/g74DiagnosisOptions";

export function G74DiagnosisStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: G74DiagnosisOptions;
  onClose: () => void;
  onStart: (options: G74DiagnosisOptions) => void;
}) {
  const [options, setOptions] = useState<G74DiagnosisOptions>(DEFAULT_G74_OPTIONS);

  useEffect(() => {
    if (open) setOptions(initialOptions);
  }, [open, initialOptions]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="g74-start-title"
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-xl border border-cyber-border/60 bg-cyber-panel shadow-xl"
      >
        <div className="sticky top-0 z-10 flex items-start justify-between border-b border-cyber-border/40 bg-cyber-panel px-4 py-3">
          <div>
            <h2 id="g74-start-title" className="font-display text-base font-semibold text-white">
              7-4 Diagnosis options
            </h2>
            <p className="mt-1 text-[10px] text-cyber-muted">취약한 보안설정 · Web/API scope</p>
            <p className="mt-1 font-mono text-[10px] text-cyan-300/80">
              {g74OptionsSummary(options)}
            </p>
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
          <G74DiagnosisOptionsPanel options={options} onChange={setOptions} />
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
            Start 7-4
          </button>
        </div>
      </div>
    </div>
  );
}
