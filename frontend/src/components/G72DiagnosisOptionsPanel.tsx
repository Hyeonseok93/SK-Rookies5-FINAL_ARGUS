import type { G72DiagnosisOptions, G72ProbeMode } from "../lib/g72DiagnosisOptions";
import { DEFAULT_G72_OPTIONS, FULL_G72_OPTIONS } from "../lib/g72DiagnosisOptions";

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
        selected
          ? "border-cyan-400/40 bg-cyan-500/10"
          : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input
        type="radio"
        name="g72-probe-mode"
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

export function G72DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G72DiagnosisOptions;
  onChange: (next: G72DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-cyan-400/30 bg-cyan-500/5 px-3 py-2 text-[10px] text-cyan-200/90">
        내장 wordlist: Apache · nginx · Tomcat · IIS · Jetty · PHP/CMS · Spring static ·
        2-2 forced-browse 디렉터리명 — <strong>수동 path 입력 없음</strong>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onChange(DEFAULT_G72_OPTIONS)}
          className="rounded border border-cyan-400/40 px-2 py-1 text-[10px] text-cyan-300 hover:bg-cyan-500/10"
        >
          Wordlist (기본)
        </button>
        <button
          type="button"
          onClick={() => onChange(FULL_G72_OPTIONS)}
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
          title="1단계 — 내장 wordlist 전체"
          hint="모든 Base × ~400+ dir path × (/path/ + /path). Tomcat /examples/, Apache /icons/ …"
          selected={options.probeMode === "base_only"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="sample"
          title="2단계 — wordlist + api-tree 샘플"
          hint="inventory 디렉터리형 path + 상위 폴더 segment base당 N개"
          selected={options.probeMode === "sample"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="full"
          title="3단계 — wordlist + api-tree 전체"
          hint="전수 probe. 동일 listing은 finding 1건 (수천 probe, 수 분 가능)"
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

      <div className="rounded-lg border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
          ZAP (선택)
        </p>
        <label className="flex cursor-pointer items-start gap-2">
          <input
            type="checkbox"
            checked={options.useZap}
            onChange={(e) => onChange({ ...options, useZap: e.target.checked })}
            className="mt-0.5 accent-cyan-400"
          />
          <span>
            <span className="block text-xs font-medium text-white">ZAP active scan</span>
            <span className="block text-[10px] text-cyber-muted">
              Rule 0 (active) + 10033 (passive) — httpx listing URL 우선 seed + Base recurse scan
            </span>
          </span>
        </label>
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

      <p className="text-[10px] text-cyber-muted">
        SPA 오탐 필터: Base `/` body와 동일하면 listing 아님. listing HTML 있으면 fail.
      </p>
    </div>
  );
}
