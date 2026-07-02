import { useEffect, useMemo, useState } from "react";
import { Gauge, Settings2, Stethoscope, X, Zap, ZapOff } from "lucide-react";
import { G12DiagnosisOptionsPanel } from "./G12DiagnosisOptionsPanel";
import {
  FULL_G12_OPTIONS,
  G12_PRESET_LABELS,
  MINIMAL_G12_OPTIONS,
  g12OptionsForPreset,
  g12OptionsSummary,
  type G12DiagnosisOptions,
  type G12DiagnosisPreset,
} from "../lib/g12DiagnosisOptions";

const TABS: { id: G12DiagnosisPreset; icon: typeof Gauge; desc: string }[] = [
  { id: "minimal", icon: ZapOff, desc: "api-tree 40 · requests · ZAP OFF" },
  { id: "full", icon: Zap, desc: "inventory 전체 · ZAP + SQL direct" },
  { id: "manual", icon: Settings2, desc: "옵션 직접 설정" },
];

function PresetOverview({ preset, options }: { preset: "minimal" | "full"; options: G12DiagnosisOptions }) {
  const isMinimal = preset === "minimal";
  const checks = isMinimal
    ? ["api-tree verified inventory 상위 40", "requests direct — SQL/NoSQL/SSTI/Command", "ZAP OFF · 테스트 계정 인증", "수 분~十数 분"]
    : ["api-tree inventory 전체", "ZAP Spider + Active Scan → requests 재검증", "direct SQL only · verification aggressive", "단독 CLI findings_full_injection과 동일 프로필"];
  return (
    <div className={`rounded-xl border p-4 ${isMinimal ? "border-cyan-400/30 bg-gradient-to-br from-cyan-500/10 to-transparent" : "border-amber-400/30 bg-gradient-to-br from-amber-500/10 to-transparent"}`}>
      <div className="mb-3 flex items-center gap-2">
        <span className={`flex h-8 w-8 items-center justify-center rounded-lg ${isMinimal ? "bg-cyan-500/20 text-cyan-300" : "bg-amber-500/20 text-amber-200"}`}>
          {isMinimal ? <Gauge className="h-4 w-4" /> : <Zap className="h-4 w-4" />}
        </span>
        <div>
          <p className="text-sm font-semibold text-white">{G12_PRESET_LABELS[preset]}</p>
          <p className="text-[10px] text-cyber-muted">api-tree (Verify)</p>
        </div>
      </div>
      <ul className="mb-3 space-y-1.5">
        {checks.map((line) => (
          <li key={line} className="flex items-start gap-2 text-[11px] text-cyber-muted">
            <span className={`mt-1.5 h-1 w-1 shrink-0 rounded-full ${isMinimal ? "bg-cyan-400" : "bg-amber-400"}`} />
            <span>{line}</span>
          </li>
        ))}
      </ul>
      <div className="rounded-lg border border-cyber-border/40 bg-cyber-bg/50 px-3 py-2">
        <p className="text-[10px] font-medium uppercase tracking-wider text-cyber-muted">실행 프로필</p>
        <p className="mt-1 font-mono text-[10px] leading-relaxed text-cyan-300/90">{g12OptionsSummary(options)}</p>
      </div>
    </div>
  );
}

export function G12DiagnosisStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: G12DiagnosisOptions;
  onClose: () => void;
  onStart: (options: G12DiagnosisOptions) => void;
}) {
  const [tab, setTab] = useState<G12DiagnosisPreset>("minimal");
  const [manualOptions, setManualOptions] = useState<G12DiagnosisOptions>(initialOptions);

  useEffect(() => {
    if (open) {
      setTab("minimal");
      setManualOptions(initialOptions);
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

  const activeOptions = useMemo(() => {
    if (tab === "manual") return manualOptions;
    return g12OptionsForPreset(tab);
  }, [tab, manualOptions]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" aria-hidden />
      <div role="dialog" aria-modal="true" aria-labelledby="g12-start-title" className="relative z-10 flex max-h-[90vh] w-full max-w-xl flex-col overflow-hidden rounded-xl border border-cyber-border bg-cyber-panel shadow-2xl">
        <div className="border-b border-cyber-border/40 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 id="g12-start-title" className="font-display text-base font-semibold text-white">1-2 삽입(Injection)</h2>
              <p className="mt-1 text-xs text-cyber-muted">api-tree · ZAP → requests 재검증 · direct</p>
            </div>
            <button type="button" onClick={onClose} className="rounded p-1 text-cyber-muted transition hover:bg-cyber-border/30 hover:text-white" aria-label="Close"><X className="h-4 w-4" /></button>
          </div>
          <div className="mt-4 grid grid-cols-3 gap-1 rounded-lg border border-cyber-border/50 bg-cyber-bg/40 p-1" role="tablist">
            {TABS.map(({ id, icon: Icon, desc }) => {
              const active = tab === id;
              return (
                <button key={id} type="button" role="tab" aria-selected={active} onClick={() => setTab(id)} className={`rounded-md px-2 py-2.5 text-center transition ${active ? "bg-cyber-panel shadow-sm ring-1 ring-cyan-400/40" : "text-cyber-muted hover:text-white"}`}>
                  <Icon className={`mx-auto mb-1 h-4 w-4 ${active ? "text-cyan-300" : "opacity-70"}`} />
                  <span className="block text-[11px] font-semibold text-white">{G12_PRESET_LABELS[id]}</span>
                  <span className="mt-0.5 block text-[9px] leading-tight text-cyber-muted">{desc}</span>
                </button>
              );
            })}
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {tab === "minimal" ? <PresetOverview preset="minimal" options={MINIMAL_G12_OPTIONS} /> : null}
          {tab === "full" ? <PresetOverview preset="full" options={FULL_G12_OPTIONS} /> : null}
          {tab === "manual" ? <G12DiagnosisOptionsPanel options={manualOptions} onChange={setManualOptions} /> : null}
        </div>
        <div className="flex items-center justify-between gap-3 border-t border-cyber-border/40 bg-cyber-panel/80 px-5 py-3">
          <p className="hidden min-w-0 truncate font-mono text-[10px] text-cyan-300/70 sm:block">{g12OptionsSummary(activeOptions)}</p>
          <div className="flex shrink-0 justify-end gap-2">
            <button type="button" onClick={onClose} className="rounded-lg border border-cyber-border px-3 py-2 text-xs font-medium text-cyber-muted transition hover:text-white">취소</button>
            <button type="button" onClick={() => onStart(activeOptions)} className="flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-500/25">
              <Stethoscope className="h-3.5 w-3.5" />
              {G12_PRESET_LABELS[tab]} 시작
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
