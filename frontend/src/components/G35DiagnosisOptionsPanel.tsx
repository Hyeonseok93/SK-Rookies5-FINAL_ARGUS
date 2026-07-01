import type { G35DiagnosisOptions, G35ProbeMode } from "../lib/g35DiagnosisOptions";
import { DEFAULT_G35_OPTIONS } from "../lib/g35DiagnosisOptions";

function ProbeModeOption({
  mode,
  title,
  hint,
  selected,
  onSelect,
}: {
  mode: G35ProbeMode;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (mode: G35ProbeMode) => void;
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
        name="g35-probe-mode"
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

export function G35DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G35DiagnosisOptions;
  onChange: (next: G35DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-amber-400/30 bg-amber-500/5 px-3 py-2 text-[10px] text-amber-200/90">
        fail/warn 없음 — robots.txt · noindex/nofollow 인벤토리. api-tree 페이지 probe (frontend base 우선). anonymous + test-account auth pass.
      </div>

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-muted">페이지 probe 범위</p>
        <ProbeModeOption
          mode="base_only"
          title="1단계 — Base `/`만"
          hint="robots.txt + 홈만"
          selected={options.probeMode === "base_only"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="sample"
          title="2단계 — api-tree 샘플 (권장)"
          hint="inventory GET path base당 N개 — SPA route 포함"
          selected={options.probeMode === "sample"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="full"
          title="3단계 — api-tree 전체"
          hint="GET path 전수 (정적 asset 제외)"
          selected={options.probeMode === "full"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
      </div>

      {options.probeMode === "sample" ? (
        <label className="block">
          <span className="mb-1 block text-[10px] font-medium text-white">Base당 inventory 샘플</span>
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

      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Timeout (초)</span>
        <input
          type="number"
          min={1}
          max={60}
          value={options.timeout}
          onChange={(e) => onChange({ ...options, timeout: Number(e.target.value) })}
          className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white"
        />
      </label>

      <button
        type="button"
        onClick={() => onChange(DEFAULT_G35_OPTIONS)}
        className="rounded border border-cyan-400/40 px-2 py-1 text-[10px] text-cyan-300 hover:bg-cyan-500/10"
      >
        기본값으로
      </button>
    </div>
  );
}

export { DEFAULT_G35_OPTIONS };
