import { useEffect, useMemo, useState } from "react";
import { FolderOpen, Gauge, Settings2, Stethoscope, X, Zap, ZapOff } from "lucide-react";
import { G72DiagnosisOptionsPanel } from "./G72DiagnosisOptionsPanel";
import {
  FULL_G72_OPTIONS,
  G72_PRESET_LABELS,
  MINIMAL_G72_OPTIONS,
  g72OptionsForPreset,
  g72OptionsSummary,
  type G72DiagnosisOptions,
  type G72DiagnosisPreset,
} from "../lib/g72DiagnosisOptions";

const TABS: { id: G72DiagnosisPreset; icon: typeof Gauge; desc: string }[] = [
  { id: "minimal", icon: ZapOff, desc: "동작 확인 · httpx · wordlist" },
  { id: "full", icon: Zap, desc: "전수 · httpx + ZAP" },
  { id: "manual", icon: Settings2, desc: "옵션 직접 설정" },
];

function PresetOverview({ preset, options }: { preset: "minimal" | "full"; options: G72DiagnosisOptions }) {
  const isMinimal = preset === "minimal";
  const checks = isMinimal
    ? ["내장 wordlist × Base URL (~400+ dir path)", "httpx GET — Index of / · autoindex 시그니처", "ZAP OFF · 수 분 이내", "SPA 오탐 필터 적용"]
    : ["wordlist + api-tree inventory 전체", "디렉터리 listing HTML 탐지", "ZAP active Rule 0 + 10033", "동일 listing finding 1건 collapse"];
  return (
    <div className={`rounded-xl border p-4 ${isMinimal ? "border-cyan-400/30 bg-gradient-to-br from-cyan-500/10 to-transparent" : "border-amber-400/30 bg-gradient-to-br from-amber-500/10 to-transparent"}`}>
      <div className="mb-3 flex items-center gap-2">
        <span className={`flex h-8 w-8 items-center justify-center rounded-lg ${isMinimal ? "bg-cyan-500/20 text-cyan-300" : "bg-amber-500/20 text-amber-200"}`}>
          {isMinimal ? <Gauge className="h-4 w-4" /> : <FolderOpen className="h-4 w-4" />}
        </span>
        <div>
          <p className="text-sm font-semibold text-white">{G72_PRESET_LABELS[preset]}</p>
          <p className="text-[10px] text-cyber-muted">{isMinimal ? "파일 목록화 빠른 확인" : "wordlist + inventory + ZAP 전수"}</p>
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
        <p className="mt-1 font-mono text-[10px] leading-relaxed text-cyan-300/90">{g72OptionsSummary(options)}</p>
      </div>
    </div>
  );
}

export function G72DiagnosisStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: G72DiagnosisOptions;
  onClose: () => void;
  onStart: (options: G72DiagnosisOptions) => void;
}) {
  const [tab, setTab] = useState<G72DiagnosisPreset>("minimal");
  const [manualOptions, setManualOptions] = useState<G72DiagnosisOptions>(initialOptions);

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
    return g72OptionsForPreset(tab);
  }, [tab, manualOptions]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" aria-hidden />
      <div role="dialog" aria-modal="true" aria-labelledby="g72-start-title" className="relative z-10 flex max-h-[90vh] w-full max-w-xl flex-col overflow-hidden rounded-xl border border-cyber-border bg-cyber-panel shadow-2xl">
        <div className="border-b border-cyber-border/40 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 id="g72-start-title" className="font-display text-base font-semibold text-white">7-2 파일 목록화</h2>
              <p className="mt-1 text-xs text-cyber-muted">디렉터리 listing · Index of / · autoindex 탐지</p>
            </div>
            <button type="button" onClick={onClose} className="rounded p-1 text-cyber-muted transition hover:bg-cyber-border/30 hover:text-white" aria-label="Close"><X className="h-4 w-4" /></button>
          </div>
          <div className="mt-4 grid grid-cols-3 gap-1 rounded-lg border border-cyber-border/50 bg-cyber-bg/40 p-1" role="tablist">
            {TABS.map(({ id, icon: Icon, desc }) => {
              const active = tab === id;
              return (
                <button key={id} type="button" role="tab" aria-selected={active} onClick={() => setTab(id)} className={`rounded-md px-2 py-2.5 text-center transition ${active ? "bg-cyber-panel shadow-sm ring-1 ring-cyan-400/40" : "text-cyber-muted hover:text-white"}`}>
                  <Icon className={`mx-auto mb-1 h-4 w-4 ${active ? "text-cyan-300" : "opacity-70"}`} />
                  <span className="block text-[11px] font-semibold text-white">{G72_PRESET_LABELS[id]}</span>
                  <span className="mt-0.5 block text-[9px] leading-tight text-cyber-muted">{desc}</span>
                </button>
              );
            })}
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {tab === "minimal" ? <PresetOverview preset="minimal" options={MINIMAL_G72_OPTIONS} /> : null}
          {tab === "full" ? <PresetOverview preset="full" options={FULL_G72_OPTIONS} /> : null}
          {tab === "manual" ? <G72DiagnosisOptionsPanel options={manualOptions} onChange={setManualOptions} /> : null}
        </div>
        <div className="flex items-center justify-between gap-3 border-t border-cyber-border/40 bg-cyber-panel/80 px-5 py-3">
          <p className="hidden min-w-0 truncate font-mono text-[10px] text-cyan-300/70 sm:block">{g72OptionsSummary(activeOptions)}</p>
          <div className="flex shrink-0 justify-end gap-2">
            <button type="button" onClick={onClose} className="rounded-lg border border-cyber-border px-3 py-2 text-xs font-medium text-cyber-muted transition hover:text-white">취소</button>
            <button type="button" onClick={() => onStart(activeOptions)} className="flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-500/25">
              <Stethoscope className="h-3.5 w-3.5" />
              {G72_PRESET_LABELS[tab]} 시작
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
