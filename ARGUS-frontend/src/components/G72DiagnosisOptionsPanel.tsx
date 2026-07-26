import type { G72DiagnosisOptions, G72ProbeMode } from "../lib/g72DiagnosisOptions";

function ProbeModeOption({
  mode,
  title,
  hint,
  selected,
  onSelect,
}: {
  mode: G72ProbeMode;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (mode: G72ProbeMode) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        selected ? "border-cyan-400/40 bg-cyan-500/10" : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input type="radio" name="g72-probe-mode" checked={selected} onChange={() => onSelect(mode)} className="mt-0.5 accent-cyan-400" />
      <span>
        <span className="block text-xs font-medium text-white">{title}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

export function G72DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G72DiagnosisOptions;
  onChange: (next: G72DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-cyan-400/25 bg-cyan-500/5 px-3 py-2 text-[10px] leading-relaxed text-cyan-200/90">
        내장 wordlist: Apache · nginx · Tomcat · IIS · Jetty · PHP/CMS · Spring · 2-2 forced-browse — 수동 path 입력 없음
      </div>
      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Probe 범위</p>
        <ProbeModeOption mode="base_only" title="내장 wordlist 전체" hint="모든 Base × ~400+ dir path. Tomcat /examples/ …" selected={options.probeMode === "base_only"} onSelect={(probeMode) => onChange({ ...options, probeMode })} />
        <ProbeModeOption mode="sample" title="wordlist + api-tree 샘플" hint="inventory 디렉터리형 path base당 N개" selected={options.probeMode === "sample"} onSelect={(probeMode) => onChange({ ...options, probeMode })} />
        <ProbeModeOption mode="full" title="wordlist + api-tree 전체" hint="전수 probe · 동일 listing finding 1건" selected={options.probeMode === "full"} onSelect={(probeMode) => onChange({ ...options, probeMode })} />
      </div>
      {options.probeMode === "sample" ? (
        <label className="block">
          <span className="mb-1 block text-[10px] font-medium text-white">Base당 inventory 샘플</span>
          <input type="number" min={1} max={500} value={options.sampleSize} onChange={(e) => onChange({ ...options, sampleSize: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
        </label>
      ) : null}
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Timeout (초)</span>
        <input type="number" min={1} max={60} value={options.timeout} onChange={(e) => onChange({ ...options, timeout: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
      <div className="rounded-xl border border-violet-400/25 bg-violet-500/5 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-violet-200/80">ZAP active</p>
        <label className="flex cursor-pointer items-start gap-2">
          <input type="checkbox" checked={options.useZap} onChange={(e) => onChange({ ...options, useZap: e.target.checked })} className="mt-0.5 accent-cyan-400" />
          <span>
            <span className="block text-xs font-medium text-white">ZAP active scan</span>
            <span className="block text-[10px] text-cyber-muted">Rule 0 + 10033 — listing URL seed + Base recurse</span>
          </span>
        </label>
        {options.useZap ? (
          <label className="mt-3 block">
            <span className="mb-1 block text-[10px] font-medium text-white">ZAP max minutes</span>
            <input type="number" min={1} max={120} value={options.zapMaxMinutes} onChange={(e) => onChange({ ...options, zapMaxMinutes: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
          </label>
        ) : null}
      </div>
      <p className="text-[10px] text-cyber-muted">SPA 오탐 필터: Base `/` body와 동일하면 listing 아님.</p>
    </div>
  );
}
