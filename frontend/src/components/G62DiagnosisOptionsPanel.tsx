import type { G62DiagnosisOptions } from "../lib/g62DiagnosisOptions";
import { DEFAULT_G62_OPTIONS } from "../lib/g62DiagnosisOptions";

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

export function G62DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G62DiagnosisOptions;
  onChange: (next: G62DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-3">
      <p className="text-[10px] text-cyber-muted">
        각 로그인 API에 대해 실패 시나리오 <strong className="text-white/80">A/B/C</strong> 응답이
        모두 동일한지 비교합니다. A=존재 계정+틀린 PW · B=없는 계정+틀린 PW · C=없는
        계정+맞는 PW (테스트 계정 비밀번호 사용).
      </p>

      <Check
        label="Strict 비교"
        hint="HTTP status·message·error code·body shape까지 비교"
        checked={options.strict}
        onChange={(strict) => onChange({ ...options, strict })}
      />

      <Check
        label="ZAP 40023 (Username Enumeration)"
        hint="ZAP active scan 보조 — Context 로그인 URL + 존재 계정 기준 (Beta 애드온 필요)"
        checked={options.useZap}
        onChange={(useZap) => onChange({ ...options, useZap })}
      />

      {options.useZap ? (
        <label className="block">
          <span className="mb-1 block text-[10px] font-medium text-white">ZAP 최대 시간 (분)</span>
          <input
            type="number"
            min={1}
            max={30}
            value={options.zapMaxMinutes}
            onChange={(e) => onChange({ ...options, zapMaxMinutes: Number(e.target.value) })}
            className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white"
          />
        </label>
      ) : null}

      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">
          Probe 계정 이메일 (선택)
        </span>
        <span className="mb-1.5 block text-[10px] text-cyber-muted">
          비우면 로그인 URL별 자동 선택 (admin URL → admin 계정 우선)
        </span>
        <input
          type="text"
          value={options.probeAccountEmail}
          onChange={(e) => onChange({ ...options, probeAccountEmail: e.target.value })}
          placeholder="yerin@travel.com"
          className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white"
        />
      </label>

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
    </div>
  );
}

export { DEFAULT_G62_OPTIONS };
