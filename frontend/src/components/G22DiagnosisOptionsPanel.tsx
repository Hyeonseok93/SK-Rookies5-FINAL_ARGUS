import type { G22DiagnosisOptions } from "../lib/g22DiagnosisOptions";
import {
  DEFAULT_G22_OPTIONS,
  QUICK_G22_OPTIONS,
  STANDARD_G22_OPTIONS,
} from "../lib/g22DiagnosisOptions";

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
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
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
      <input
        type="number"
        min={min}
        max={max}
        disabled={disabled}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white disabled:opacity-40"
      />
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
  const applyPreset = (preset: G22DiagnosisOptions) => {
    if (!disabled) onChange({ ...preset });
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {(
          [
            ["빠른 확인", QUICK_G22_OPTIONS],
            ["표준 (httpx)", STANDARD_G22_OPTIONS],
            ["전체 (ZAP)", DEFAULT_G22_OPTIONS],
          ] as const
        ).map(([label, preset]) => (
          <button
            key={label}
            type="button"
            disabled={disabled}
            onClick={() => applyPreset(preset)}
            className="rounded-full border border-cyber-border/60 px-3 py-1 text-[10px] font-semibold text-cyber-muted transition hover:border-cyan-400/40 hover:text-cyan-300 disabled:opacity-40"
          >
            {label}
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
          Targets (검사 대상)
        </p>
        <Check
          label="api-tree 전체 확인"
          hint="해제(기본): 2-2 점수 높은 API만 상위 N개. 체크: api-tree 전 행(API+frontend), 제한 없음"
          checked={options.scanAllInventory}
          disabled={disabled}
          onChange={(scanAllInventory) => onChange({ ...options, scanAllInventory })}
        />
        {!options.scanAllInventory ? (
          <p className="mt-2 text-[10px] leading-relaxed text-cyber-muted">
            <span className="text-cyan-300/90">80개 기준:</span> download/export/report 경로,
            file·template·path 파라미터, 2-2 태그 등으로 점수를 매긴 뒤 kind=api 중 2점 이상만
            모아 높은 순으로 Max candidates만 사용합니다.
          </p>
        ) : (
          <p className="mt-2 text-[10px] text-amber-300/90">
            전체 모드 — httpx/ZAP 켜면 시간이 크게 늘 수 있습니다.
          </p>
        )}
      </div>

      <div className="rounded-lg border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
          Scan methods
        </p>
        <p className="mb-2 text-[10px] text-cyber-muted">
          설계 리뷰(후보 API · path/filename 파라미터)는 항상 실행됩니다.
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          <Check
            label="httpx probe"
            hint="무인증 다운로드 · traversal · forced browse (ARGUS 통합 로직)"
            checked={options.useHttpx}
            disabled={disabled}
            onChange={(useHttpx) =>
              onChange({
                ...options,
                useHttpx,
                idorProbe: useHttpx || options.useZap ? options.idorProbe : false,
              })
            }
          />
          <Check
            label="ZAP scan"
            hint="httpx와 동일 ARGUS 로직(ZAP 경유) + native 0/40035 보조 — Docker ZAP 필요"
            checked={options.useZap}
            disabled={disabled}
            onChange={(useZap) =>
              onChange({
                ...options,
                useZap,
                idorProbe: useZap || options.useHttpx ? options.idorProbe : false,
              })
            }
          />
        </div>
        <div className="mt-2">
          <Check
            label="IDOR (cross-account)"
            hint="test-accounts 2개 이상 — A 소유 export/download ID를 B 토큰으로 재요청 (httpx·ZAP unified)"
            checked={options.idorProbe}
            disabled={disabled || (!options.useHttpx && !options.useZap)}
            onChange={(idorProbe) => onChange({ ...options, idorProbe })}
          />
        </div>
      </div>

      <div className="rounded-lg border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
          Limits
        </p>
        <p className="mb-2 text-[10px] text-cyber-muted">
          httpx는 traversal wordlist(파라미터 주입)와 forced browse wordlist를 항상 전부 실행합니다.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          <NumField
            label="Max candidates"
            hint="2-2 후보 API 상한 (점수 순)"
            value={options.maxCandidates}
            min={1}
            max={500}
            disabled={disabled || options.scanAllInventory}
            onChange={(maxCandidates) => onChange({ ...options, maxCandidates })}
          />
          <NumField
            label="ZAP max minutes"
            hint="Active scan 최대 대기(분)"
            value={options.zapMaxMinutes}
            min={1}
            max={120}
            disabled={disabled || !options.useZap}
            onChange={(zapMaxMinutes) => onChange({ ...options, zapMaxMinutes })}
          />
        </div>
      </div>
    </div>
  );
}
