import { useEffect, useState } from "react";
import { Stethoscope, X } from "lucide-react";
import { G52DiagnosisOptionsPanel } from "./G52DiagnosisOptionsPanel";
import {
  G52_SMOKE_PRESET,
  g52DetectTab,
  g52OptionsSummary,
  type G52DiagnosisOptions,
  type G52OptionsTab,
} from "../lib/g52DiagnosisOptions";

export function G52DiagnosisStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: G52DiagnosisOptions;
  onClose: () => void;
  onStart: (options: G52DiagnosisOptions) => void;
}) {
  const [options, setOptions] = useState<G52DiagnosisOptions>(G52_SMOKE_PRESET);
  const [activeTab, setActiveTab] = useState<G52OptionsTab>("smoke");

  useEffect(() => {
    if (open) {
      setOptions(initialOptions);
      setActiveTab(g52DetectTab(initialOptions));
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
        aria-labelledby="g52-start-title"
        className="relative z-10 max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-xl border border-cyber-border bg-cyber-panel p-5 shadow-2xl"
      >
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 id="g52-start-title" className="font-display text-base font-semibold text-white">
              5-2 Diagnosis options
            </h2>
            <p className="mt-1 text-xs text-cyber-muted">
              요청·응답 값 내 주요정보(PII) 마스킹 여부 — api-tree API를 실제 호출해 검사합니다.
            </p>
            <p className="mt-1 font-mono text-[10px] text-cyan-300/80">{g52OptionsSummary(options)}</p>
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

        <G52DiagnosisOptionsPanel
          activeTab={activeTab}
          onTabChange={setActiveTab}
          options={options}
          onChange={setOptions}
        />

        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => onStart(options)}
            className={`flex items-center gap-1.5 rounded-lg border px-4 py-2 text-xs font-semibold transition ${
              activeTab === "exhaustive"
                ? "border-amber-400/50 bg-amber-500/15 text-amber-200 hover:bg-amber-500/25"
                : "border-cyan-400/50 bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25"
            }`}
          >
            <Stethoscope className="h-3.5 w-3.5" />
            {activeTab === "exhaustive" ? "전체 전수 스캔 시작" : "Start 5-2"}
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
