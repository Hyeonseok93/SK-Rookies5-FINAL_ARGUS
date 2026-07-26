import type { G22DiagnosisOptions } from "../lib/g22DiagnosisOptions";

type G22TargetMode = "dashboard" | "scored" | "full";

function targetModeFromOptions(options: G22DiagnosisOptions): G22TargetMode {
  if (options.dashboardDownloadOnly) return "dashboard";
  if (options.scanAllInventory) return "full";
  return "scored";
}

function applyTargetMode(options: G22DiagnosisOptions, mode: G22TargetMode): G22DiagnosisOptions {
  return {
    ...options,
    dashboardDownloadOnly: mode === "dashboard",
    scanAllInventory: mode === "full",
  };
}

function TargetModeOption({
  name,
  value,
  current,
  label,
  hint,
  disabled,
  onSelect,
}: {
  name: string;
  value: G22TargetMode;
  current: G22TargetMode;
  label: string;
  hint: string;
  disabled?: boolean;
  onSelect: (mode: G22TargetMode) => void;
}) {
  const active = current === value;
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        disabled
          ? "cursor-not-allowed border-cyber-border/30 opacity-40"
          : active
            ? "border-cyan-400/40 bg-cyan-500/10"
            : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input
        type="radio"
        name={name}
        checked={active}
        disabled={disabled}
        onChange={() => onSelect(value)}
        className="mt-0.5 accent-cyan-400"
      />
      <span>
        <span className="block text-xs font-medium text-white">{label}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

function Check({
  label,
  hint,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        disabled
          ? "cursor-not-allowed border-cyber-border/30 opacity-40"
          : checked
            ? "border-cyan-400/40 bg-cyan-500/10"
            : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} className="mt-0.5 accent-cyan-400" />
      <span>
        <span className="block text-xs font-medium text-white">{label}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

function NumField({
  label,
  hint,
  value,
  min,
  max,
  disabled,
  onChange,
}: {
  label: string;
  hint: string;
  value: number;
  min: number;
  max: number;
  disabled?: boolean;
  onChange: (v: number) => void;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[10px] font-medium text-white">{label}</span>
      <span className="mb-1.5 block text-[10px] text-cyber-muted">{hint}</span>
      <input type="number" min={min} max={max} disabled={disabled} value={value} onChange={(e) => onChange(Number(e.target.value))} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white disabled:opacity-40" />
    </label>
  );
}

export function G22DiagnosisOptionsPanel({
  options,
  onChange,
  disabled,
}: {
  options: G22DiagnosisOptions;
  onChange: (next: G22DiagnosisOptions) => void;
  disabled?: boolean;
}) {
  const targetMode = targetModeFromOptions(options);

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
          Targets
        </p>
        <div className="space-y-2" role="radiogroup" aria-label="2-2 scan targets">
          <TargetModeOption
            name="g22-target-mode"
            value="dashboard"
            current={targetMode}
            label="Download Endpoints 등록분만"
            hint="Attack Surface에 저장한 다운로드 API만"
            disabled={disabled}
            onSelect={(mode) => onChange(applyTargetMode(options, mode))}
          />
          <TargetModeOption
            name="g22-target-mode"
            value="scored"
            current={targetMode}
            label="inventory 후보 상위 N개"
            hint="api-tree에서 2-2 점수 필터 · Max candidates 적용"
            disabled={disabled}
            onSelect={(mode) => onChange(applyTargetMode(options, mode))}
          />
          <TargetModeOption
            name="g22-target-mode"
            value="full"
            current={targetMode}
            label="api-tree 전체"
            hint="inventory 전 행 · 점수 필터·상한 없음"
            disabled={disabled}
            onSelect={(mode) => onChange(applyTargetMode(options, mode))}
          />
        </div>
      </div>
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Scan methods</p>
        <div className="grid gap-2 sm:grid-cols-2">
          <Check label="httpx probe" hint="traversal · forced browse wordlist" checked={options.useHttpx} disabled={disabled} onChange={(useHttpx) => onChange({ ...options, useHttpx, idorProbe: useHttpx || options.useZap ? options.idorProbe : false })} />
          <Check label="ZAP scan" hint="unified + native 0/40035 — Docker ZAP 필요" checked={options.useZap} disabled={disabled} onChange={(useZap) => onChange({ ...options, useZap, idorProbe: useZap || options.useHttpx ? options.idorProbe : false })} />
        </div>
        <div className="mt-2">
          <Check label="IDOR (cross-account)" hint="test-accounts 2개 이상" checked={options.idorProbe} disabled={disabled || (!options.useHttpx && !options.useZap)} onChange={(idorProbe) => onChange({ ...options, idorProbe })} />
        </div>
      </div>
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Limits</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <NumField
            label="Max candidates"
            hint="inventory 후보 상위 N개 모드에서만 적용"
            value={options.maxCandidates}
            min={1}
            max={500}
            disabled={disabled || targetMode !== "scored"}
            onChange={(maxCandidates) => onChange({ ...options, maxCandidates })}
          />
          <NumField label="ZAP max minutes" hint="Active scan 최대 대기" value={options.zapMaxMinutes} min={1} max={120} disabled={disabled || !options.useZap} onChange={(zapMaxMinutes) => onChange({ ...options, zapMaxMinutes })} />
        </div>
      </div>
    </div>
  );
}
