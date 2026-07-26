import { useEffect, useMemo, useState } from "react";
import { Gauge, Settings2, ShieldCheck, Stethoscope, X, Zap, ZapOff } from "lucide-react";
import { G74DiagnosisOptionsPanel } from "./G74DiagnosisOptionsPanel";
import {
  FULL_G74_OPTIONS,
  G74_PRESET_LABELS,
  MINIMAL_G74_OPTIONS,
  g74OptionsForPreset,
  g74OptionsSummary,
  type G74DiagnosisOptions,
  type G74DiagnosisPreset,
} from "../lib/g74DiagnosisOptions";

const TABS: {
  id: G74DiagnosisPreset;
  icon: typeof Gauge;
  desc: string;
}[] = [
  {
    id: "minimal",
    icon: ZapOff,
    desc: "동작 확인 · httpx · Base URL",
  },
  {
    id: "full",
    icon: Zap,
    desc: "전수 점검 · httpx + ZAP",
  },
  {
    id: "manual",
    icon: Settings2,
    desc: "옵션 직접 설정",
  },
];

function PresetOverview({
  preset,
  options,
}: {
  preset: "minimal" | "full";
  options: G74DiagnosisOptions;
}) {
  const isMinimal = preset === "minimal";
  const checks = isMinimal
    ? [
        "등록된 Base URL × / 경로만 probe",
        "httpx GET — 보안 헤더·Set-Cookie 점검",
        "ZAP 미사용 (수 초~1분)",
        "Strict + Cookie 점검 ON",
      ]
    : [
        "api-tree inventory 전체 경로 probe",
        "httpx GET — HSTS, CSP, XFO, nosniff, Referrer-Policy 등",
        "ZAP passive — Rule 10035/10038/10020/10021/10054/10063",
        "동일 이슈 finding 1건으로 collapse",
      ];

  return (
    <div
      className={`rounded-xl border p-4 ${
        isMinimal
          ? "border-cyan-400/30 bg-gradient-to-br from-cyan-500/10 to-transparent"
          : "border-amber-400/30 bg-gradient-to-br from-amber-500/10 to-transparent"
      }`}
    >
      <div className="mb-3 flex items-center gap-2">
        <span
          className={`flex h-8 w-8 items-center justify-center rounded-lg ${
            isMinimal ? "bg-cyan-500/20 text-cyan-300" : "bg-amber-500/20 text-amber-200"
          }`}
        >
          {isMinimal ? <Gauge className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />}
        </span>
        <div>
          <p className="text-sm font-semibold text-white">{G74_PRESET_LABELS[preset]}</p>
          <p className="text-[10px] text-cyber-muted">
            {isMinimal ? "파이프라인·연결만 빠르게 확인" : "가능한 전 범위 자동 점검"}
          </p>
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
        <p className="mt-1 font-mono text-[10px] leading-relaxed text-cyan-300/90">
          {g74OptionsSummary(options)}
        </p>
      </div>
    </div>
  );
}

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
  const [tab, setTab] = useState<G74DiagnosisPreset>("minimal");
  const [manualOptions, setManualOptions] = useState<G74DiagnosisOptions>(initialOptions);

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
    return g74OptionsForPreset(tab);
  }, [tab, manualOptions]);

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
        aria-labelledby="g74-start-title"
        className="relative z-10 flex max-h-[90vh] w-full max-w-xl flex-col overflow-hidden rounded-xl border border-cyber-border bg-cyber-panel shadow-2xl"
      >
        <div className="border-b border-cyber-border/40 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 id="g74-start-title" className="font-display text-base font-semibold text-white">
                7-4 취약한 보안설정
              </h2>
              <p className="mt-1 text-xs text-cyber-muted">
                Web/API 관측 가능 범위 — 보안 헤더·쿠키 속성 점검
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

          <div
            className="mt-4 grid grid-cols-3 gap-1 rounded-lg border border-cyber-border/50 bg-cyber-bg/40 p-1"
            role="tablist"
            aria-label="7-4 diagnosis mode"
          >
            {TABS.map(({ id, icon: Icon, desc }) => {
              const active = tab === id;
              return (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setTab(id)}
                  className={`rounded-md px-2 py-2.5 text-center transition ${
                    active
                      ? "bg-cyber-panel shadow-sm ring-1 ring-cyan-400/40"
                      : "text-cyber-muted hover:text-white"
                  }`}
                >
                  <Icon
                    className={`mx-auto mb-1 h-4 w-4 ${active ? "text-cyan-300" : "opacity-70"}`}
                  />
                  <span className="block text-[11px] font-semibold text-white">
                    {G74_PRESET_LABELS[id]}
                  </span>
                  <span className="mt-0.5 block text-[9px] leading-tight text-cyber-muted">
                    {desc}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {tab === "minimal" ? (
            <PresetOverview preset="minimal" options={MINIMAL_G74_OPTIONS} />
          ) : null}
          {tab === "full" ? <PresetOverview preset="full" options={FULL_G74_OPTIONS} /> : null}
          {tab === "manual" ? (
            <G74DiagnosisOptionsPanel options={manualOptions} onChange={setManualOptions} />
          ) : null}
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-cyber-border/40 bg-cyber-panel/80 px-5 py-3">
          <p className="hidden min-w-0 truncate font-mono text-[10px] text-cyan-300/70 sm:block">
            {g74OptionsSummary(activeOptions)}
          </p>
          <div className="flex shrink-0 justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-cyber-border px-3 py-2 text-xs font-medium text-cyber-muted transition hover:text-white"
            >
              취소
            </button>
            <button
              type="button"
              onClick={() => onStart(activeOptions)}
              className="flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-500/25"
            >
              <Stethoscope className="h-3.5 w-3.5" />
              {G74_PRESET_LABELS[tab]} 시작
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
