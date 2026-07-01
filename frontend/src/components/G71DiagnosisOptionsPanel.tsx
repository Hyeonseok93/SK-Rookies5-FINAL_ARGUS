import type { G71DiagnosisOptions, G71ProbeMode } from "../lib/g71DiagnosisOptions";
import {
  DEFAULT_G71_OPTIONS,
  FULL_G71_OPTIONS,
  RELAXED_G71_OPTIONS,
} from "../lib/g71DiagnosisOptions";

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
        <span className="block text-[10px] text-cyber-muted">{hint}</span>
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
  mode: G71ProbeMode;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (mode: G71ProbeMode) => void;
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
        name="g71-probe-mode"
        checked={selected}
        onChange={() => onSelect(mode)}
        className="mt-0.5 accent-cyan-400"
      />
      <span>
        <span className="block text-xs font-medium text-white">{title}</span>
        <span className="block text-[10px] text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

export function G71DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G71DiagnosisOptions;
  onChange: (next: G71DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onChange(DEFAULT_G71_OPTIONS)}
          className="rounded border border-cyan-400/40 px-2 py-1 text-[10px] text-cyan-300 hover:bg-cyan-500/10"
        >
          Strict (기본)
        </button>
        <button
          type="button"
          onClick={() => onChange(RELAXED_G71_OPTIONS)}
          className="rounded border border-cyber-border/60 px-2 py-1 text-[10px] text-cyber-muted hover:text-white"
        >
          TRACE/TRACK만
        </button>
        <button
          type="button"
          onClick={() => onChange(FULL_G71_OPTIONS)}
          className="rounded border border-amber-400/40 px-2 py-1 text-[10px] text-amber-200/90 hover:bg-amber-500/10"
        >
          api-tree 전체
        </button>
      </div>

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-muted">
          Probe 범위
        </p>
        <ProbeModeOption
          mode="base_only"
          title="1단계 — Base URL만 (빠름)"
          hint="등록된 Base URL × / (+ 추가 경로). TRACE + OPTIONS Allow."
          selected={options.probeMode === "base_only"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="sample"
          title="2단계 — api-tree 샘플"
          hint="Base + api-tree에서 base당 N개 경로."
          selected={options.probeMode === "sample"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="full"
          title="3단계 — api-tree 전체"
          hint="매칭되는 inventory 경로 전부 probe."
          selected={options.probeMode === "full"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
      </div>

      {options.probeMode === "sample" ? (
        <label className="block">
          <span className="mb-1 block text-[10px] font-medium text-white">
            Base URL당 샘플 수
          </span>
          <input
            type="number"
            min={1}
            max={500}
            value={options.sampleSize}
            onChange={(e) => onChange({ ...options, sampleSize: Number(e.target.value) })}
            className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white"
          />
        </label>
      ) : null}

      <Check
        label="Strict risky (PUT/DELETE)"
        hint="Allow 헤더에 PUT/DELETE 포함 시 low(warn). 끄면 TRACE/TRACK/CONNECT만 점검"
        checked={options.strictRisky}
        onChange={(strictRisky) => onChange({ ...options, strictRisky })}
      />

      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Probe timeout (초)</span>
        <input
          type="number"
          min={1}
          max={60}
          value={options.timeout}
          onChange={(e) => onChange({ ...options, timeout: Number(e.target.value) })}
          className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white"
        />
      </label>

      <div className="rounded-lg border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
          ZAP (선택)
        </p>
        <Check
          label="ZAP active scan"
          hint="Rule 90028 (Insecure HTTP Method) — httpx hit URL 우선 seed"
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
              className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white"
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
          placeholder={"/health"}
          className="w-full resize-y rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white"
        />
      </label>
    </div>
  );
}
