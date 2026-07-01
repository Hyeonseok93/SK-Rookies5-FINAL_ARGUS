import type { G15DiagnosisOptions, G15ProbeMode } from "../lib/g15DiagnosisOptions";

function Check({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        checked
          ? "border-cyan-400/40 bg-cyan-500/10"
          : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="mt-0.5 accent-cyan-400" />
      <span>
        <span className="block text-xs font-medium text-white">{label}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

function ProbeModeOption({
  mode,
  title,
  hint,
  selected,
  onSelect,
}: {
  mode: G15ProbeMode;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (mode: G15ProbeMode) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        selected ? "border-cyan-400/40 bg-cyan-500/10" : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input type="radio" name="g15-probe-mode" checked={selected} onChange={() => onSelect(mode)} className="mt-0.5 accent-cyan-400" />
      <span>
        <span className="block text-xs font-medium text-white">{title}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

export function G15DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G15DiagnosisOptions;
  onChange: (next: G15DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Open redirect 범위</p>
        <ProbeModeOption mode="base_only" title="CORS / crossdomain만" hint="Phase A·B redirect sweep 스킵." selected={options.probeMode === "base_only"} onSelect={(probeMode) => onChange({ ...options, probeMode })} />
        <ProbeModeOption mode="sample" title="sample — Phase A + B" hint="api-tree 일부 + redirect param append." selected={options.probeMode === "sample"} onSelect={(probeMode) => onChange({ ...options, probeMode })} />
        <ProbeModeOption mode="full" title="full — inventory 넓게" hint="더 많은 endpoint/path." selected={options.probeMode === "full"} onSelect={(probeMode) => onChange({ ...options, probeMode })} />
      </div>
      {options.probeMode === "sample" ? (
        <label className="block">
          <span className="mb-1 block text-[10px] font-medium text-white">Endpoint 샘플 수</span>
          <input type="number" min={10} max={500} value={options.sampleSize} onChange={(e) => onChange({ ...options, sampleSize: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
        </label>
      ) : null}
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3 space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Phase C</p>
        <Check label="CORS probe" hint="Base URL Origin 프로브 — wildcard/reflect" checked={options.corsEnabled} onChange={(corsEnabled) => onChange({ ...options, corsEnabled })} />
        <Check label="crossdomain.xml" hint="GET /crossdomain.xml permissive 설정" checked={options.crossdomainEnabled} onChange={(crossdomainEnabled) => onChange({ ...options, crossdomainEnabled })} />
      </div>
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Redirect sink URL (선택)</span>
        <input type="text" value={options.redirectSinkBase} onChange={(e) => onChange({ ...options, redirectSinkBase: e.target.value })} placeholder="비우면 config 기본값 (ARGUS /argus-redirect-sink)" className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Probe timeout (초)</span>
        <input type="number" min={1} max={60} value={options.timeout} onChange={(e) => onChange({ ...options, timeout: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
      <div className="rounded-xl border border-violet-400/25 bg-violet-500/5 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-violet-200/80">ZAP active</p>
        <Check label="ZAP active scan" hint="Rule 40031 / 10028 — httpx seed URL 우선" checked={options.useZap} onChange={(useZap) => onChange({ ...options, useZap })} />
        {options.useZap ? (
          <label className="mt-3 block">
            <span className="mb-1 block text-[10px] font-medium text-white">ZAP max minutes</span>
            <input type="number" min={1} max={120} value={options.zapMaxMinutes} onChange={(e) => onChange({ ...options, zapMaxMinutes: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
          </label>
        ) : null}
      </div>
    </div>
  );
}
