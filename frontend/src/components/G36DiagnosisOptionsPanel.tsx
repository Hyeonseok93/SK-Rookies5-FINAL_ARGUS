import type { G36DiagnosisOptions, G36ProbeMode } from "../lib/g36DiagnosisOptions";
import { DEFAULT_G36_OPTIONS } from "../lib/g36DiagnosisOptions";

function ProbeModeOption({
  mode,
  title,
  hint,
  selected,
  onSelect,
}: {
  mode: G36ProbeMode;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (mode: G36ProbeMode) => void;
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
        name="g36-probe-mode"
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

export function G36DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G36DiagnosisOptions;
  onChange: (next: G36DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-amber-400/30 bg-amber-500/5 px-3 py-2 text-[10px] text-amber-200/90">
        backup.zip · .env · phpinfo.php 등 — Base(8080·5173) × wordlist GET. 1st anonymous · 2nd authenticated (test account).
      </div>

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-muted">Probe 범위</p>
        <ProbeModeOption
          mode="base_only"
          title="1단계 — wordlist만"
          hint="모든 Base × backup/test wordlist"
          selected={options.probeMode === "base_only"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="sample"
          title="2단계 — wordlist + api-tree 샘플"
          hint="inventory에서 .bak/.zip/test* path base당 N개 추가"
          selected={options.probeMode === "sample"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="full"
          title="3단계 — wordlist + api-tree 전체"
          hint="파일형 path 전수 probe"
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
        onClick={() => onChange(DEFAULT_G36_OPTIONS)}
        className="rounded border border-cyan-400/40 px-2 py-1 text-[10px] text-cyan-300 hover:bg-cyan-500/10"
      >
        기본값으로
      </button>
    </div>
  );
}

export { DEFAULT_G36_OPTIONS };
