import type { G41DiagnosisOptions, G41ProbeMode } from "../lib/g41DiagnosisOptions";
import {
  DEFAULT_G41_OPTIONS,
  FULL_G41_OPTIONS,
  QUICK_G41_OPTIONS,
} from "../lib/g41DiagnosisOptions";

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
  mode: G41ProbeMode;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (mode: G41ProbeMode) => void;
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
        name="g41-probe-mode"
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

export function G41DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G41DiagnosisOptions;
  onChange: (next: G41DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onChange(QUICK_G41_OPTIONS)}
          className="rounded border border-cyber-border/60 px-2 py-1 text-[10px] text-cyber-muted hover:border-cyan-400/40 hover:text-cyan-300"
        >
          Quick
        </button>
        <button
          type="button"
          onClick={() => onChange(DEFAULT_G41_OPTIONS)}
          className="rounded border border-cyber-border/60 px-2 py-1 text-[10px] text-cyber-muted hover:border-cyan-400/40 hover:text-cyan-300"
        >
          Default
        </button>
        <button
          type="button"
          onClick={() => onChange(FULL_G41_OPTIONS)}
          className="rounded border border-cyber-border/60 px-2 py-1 text-[10px] text-cyber-muted hover:border-cyan-400/40 hover:text-cyan-300"
        >
          Full
        </button>
      </div>

      <div>
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-cyber-muted">
          Probe mode
        </p>
        <div className="space-y-2">
          <ProbeModeOption
            mode="base_only"
            title="Login matrix + cookie flags"
            hint="Verify login_entry_report + login Set-Cookie HttpOnly/Secure/SameSite (httpx 프로브 없음)"
            selected={options.probeMode === "base_only"}
            onSelect={(probeMode) => onChange({ ...options, probeMode })}
          />
          <ProbeModeOption
            mode="sample"
            title="Sample"
            hint="admin/민감 API 우선 + sample GET endpoints — cross-cookie + tamper"
            selected={options.probeMode === "sample"}
            onSelect={(probeMode) => onChange({ ...options, probeMode })}
          />
          <ProbeModeOption
            mode="full"
            title="Full api-tree"
            hint="후보 GET 전체 (시간 증가)"
            selected={options.probeMode === "full"}
            onSelect={(probeMode) => onChange({ ...options, probeMode })}
          />
        </div>
      </div>

      {options.probeMode !== "base_only" ? (
        <>
          <div className="grid grid-cols-2 gap-3">
            <label className="block text-[10px] text-cyber-muted">
              Sample size
              <input
                type="number"
                min={5}
                max={500}
                value={options.sampleSize}
                onChange={(e) =>
                  onChange({ ...options, sampleSize: Number(e.target.value) || 40 })
                }
                className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 font-mono text-xs text-white"
              />
            </label>
            <label className="block text-[10px] text-cyber-muted">
              Max endpoints
              <input
                type="number"
                min={10}
                max={500}
                value={options.maxEndpoints}
                onChange={(e) =>
                  onChange({ ...options, maxEndpoints: Number(e.target.value) || 80 })
                }
                className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 font-mono text-xs text-white"
              />
            </label>
            <label className="block text-[10px] text-cyber-muted">
              Timeout (s)
              <input
                type="number"
                min={1}
                max={60}
                step={0.5}
                value={options.timeout}
                onChange={(e) =>
                  onChange({ ...options, timeout: Number(e.target.value) || 8 })
                }
                className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 font-mono text-xs text-white"
              />
            </label>
            <label className="block text-[10px] text-cyber-muted">
              Max pairs / endpoint
              <input
                type="number"
                min={2}
                max={50}
                value={options.maxPairsPerEndpoint}
                onChange={(e) =>
                  onChange({
                    ...options,
                    maxPairsPerEndpoint: Number(e.target.value) || 12,
                  })
                }
                className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 font-mono text-xs text-white"
              />
            </label>
            <label className="block text-[10px] text-cyber-muted">
              Tamper max endpoints
              <input
                type="number"
                min={5}
                max={200}
                value={options.tamperMaxEndpoints}
                onChange={(e) =>
                  onChange({
                    ...options,
                    tamperMaxEndpoints: Number(e.target.value) || 30,
                  })
                }
                className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 font-mono text-xs text-white"
              />
            </label>
          </div>

          <div className="space-y-2">
            <Check
              label="Cross-account cookie"
              hint="Test Accounts × login entry 세션 조합 — admin/seller 라벨 없이 전체 페어"
              checked={options.crossCookieEnabled}
              onChange={(crossCookieEnabled) => onChange({ ...options, crossCookieEnabled })}
            />
            <Check
              label="Cookie tamper"
              hint="empty / garbage / JWT mutate variants"
              checked={options.tamperEnabled}
              onChange={(tamperEnabled) => onChange({ ...options, tamperEnabled })}
            />
          </div>
        </>
      ) : null}

      <div className="space-y-2">
        <Check
          label="Cookie flag analysis (HttpOnly / Secure / SameSite)"
          hint="Login entry POST → Set-Cookie 정적 분석 (Verify 캐시 우선)"
          checked={options.cookieAttrEnabled}
          onChange={(cookieAttrEnabled) => onChange({ ...options, cookieAttrEnabled })}
        />
        {options.cookieAttrEnabled ? (
          <Check
            label="Strict cookie flags"
            hint="SameSite 누락·session-like HttpOnly 누락도 보고"
            checked={options.cookieAttrStrict}
            onChange={(cookieAttrStrict) => onChange({ ...options, cookieAttrStrict })}
          />
        ) : null}
      </div>

      <p className="text-[10px] text-cyber-muted">
        Verify 후 login_entry_report와 Test Accounts 세션이 필요합니다. Phase B (Playwright web
        storage)는 별도 예정.
      </p>
    </div>
  );
}
