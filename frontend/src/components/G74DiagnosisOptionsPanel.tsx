import type { G74DiagnosisOptions, G74ProbeMode } from "../lib/g74DiagnosisOptions";
import { RELAXED_G74_OPTIONS } from "../lib/g74DiagnosisOptions";

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
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 accent-cyan-400"
      />
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
  mode: G74ProbeMode;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (mode: G74ProbeMode) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        selected
          ? "border-cyan-400/40 bg-cyan-500/10"
          : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input
        type="radio"
        name="g74-probe-mode"
        checked={selected}
        onChange={() => onSelect(mode)}
        className="mt-0.5 accent-cyan-400"
      />
      <span>
        <span className="block text-xs font-medium text-white">{title}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

export function G74DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G74DiagnosisOptions;
  onChange: (next: G74DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onChange({ ...options, strict: true })}
          className={`rounded-full border px-2.5 py-1 text-[10px] transition ${
            options.strict
              ? "border-cyan-400/50 bg-cyan-500/15 text-cyan-200"
              : "border-cyber-border/60 text-cyber-muted hover:text-white"
          }`}
        >
          Strict
        </button>
        <button
          type="button"
          onClick={() => onChange({ ...options, ...RELAXED_G74_OPTIONS, probeMode: options.probeMode, useZap: options.useZap, zapMaxMinutes: options.zapMaxMinutes, sampleSize: options.sampleSize, extraProbePaths: options.extraProbePaths, timeout: options.timeout })}
          className="rounded-full border border-cyber-border/60 px-2.5 py-1 text-[10px] text-cyber-muted transition hover:text-white"
        >
          KISA 완화
        </button>
      </div>

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
          Probe 범위
        </p>
        <ProbeModeOption
          mode="base_only"
          title="Base URL만"
          hint="등록된 Base URL × / (+ 추가 경로). 가장 빠름."
          selected={options.probeMode === "base_only"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="sample"
          title="api-tree 샘플"
          hint="Base + inventory에서 base당 N개 경로."
          selected={options.probeMode === "sample"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="full"
          title="api-tree 전체"
          hint="inventory 경로 전부 probe. 동일 이슈는 finding 1건으로 합침."
          selected={options.probeMode === "full"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
      </div>

      {options.probeMode === "sample" ? (
        <label className="block">
          <span className="mb-1 block text-[10px] font-medium text-white">Base URL당 샘플 수</span>
          <input
            type="number"
            min={1}
            max={500}
            value={options.sampleSize}
            onChange={(e) => onChange({ ...options, sampleSize: Number(e.target.value) })}
            className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white"
          />
        </label>
      ) : null}

      <div className="grid gap-2 sm:grid-cols-2">
        <Check
          label="Strict 모드"
          hint="Referrer-Policy·Permissions-Policy·SameSite·HttpOnly까지 보고"
          checked={options.strict}
          onChange={(strict) => onChange({ ...options, strict })}
        />
        <Check
          label="Set-Cookie 점검"
          hint="Secure / HttpOnly / SameSite (HTTPS)"
          checked={options.checkCookies}
          onChange={(checkCookies) => onChange({ ...options, checkCookies })}
        />
      </div>

      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Probe timeout (초)</span>
        <input
          type="number"
          min={1}
          max={60}
          value={options.timeout}
          onChange={(e) => onChange({ ...options, timeout: Number(e.target.value) })}
          className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white"
        />
      </label>

      <div className="rounded-xl border border-violet-400/25 bg-violet-500/5 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-violet-200/80">
          ZAP passive
        </p>
        <Check
          label="ZAP passive scan"
          hint="HSTS / CSP / XFO / nosniff / cookie rules — active scan 없음"
          checked={options.useZap}
          onChange={(useZap) => onChange({ ...options, useZap })}
        />
        {options.useZap ? (
          <label className="mt-3 block">
            <span className="mb-1 block text-[10px] font-medium text-white">ZAP max minutes</span>
            <input
              type="number"
              min={1}
              max={120}
              value={options.zapMaxMinutes}
              onChange={(e) => onChange({ ...options, zapMaxMinutes: Number(e.target.value) })}
              className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white"
            />
          </label>
        ) : null}
      </div>

      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">
          추가 probe 경로 (선택)
        </span>
        <textarea
          rows={2}
          value={options.extraProbePaths}
          onChange={(e) => onChange({ ...options, extraProbePaths: e.target.value })}
          placeholder="/health"
          className="w-full resize-y rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white"
        />
      </label>
    </div>
  );
}
