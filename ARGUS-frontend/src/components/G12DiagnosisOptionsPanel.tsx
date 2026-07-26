import type { G12DiagnosisOptions, G12VerificationMode } from "../lib/g12DiagnosisOptions";

const INJECTION_TYPE_OPTIONS = ["SQL", "NOSQL", "SSTI", "COMMAND", "XPATH", "GENERIC"] as const;

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

export function G12DiagnosisOptionsPanel({
  options,
  onChange,
  disabled,
}: {
  options: G12DiagnosisOptions;
  onChange: (next: G12DiagnosisOptions) => void;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">api-tree targets</p>
        <Check
          label="inventory 전체"
          hint="체크 시 max_targets 제한 없이 verified api-tree 전체"
          checked={options.scanAllInventory}
          disabled={disabled}
          onChange={(scanAllInventory) => onChange({ ...options, scanAllInventory })}
        />
        {!options.scanAllInventory ? (
          <label className="mt-2 block">
            <span className="mb-1 block text-[10px] font-medium text-white">max targets (direct)</span>
            <input
              type="number"
              min={5}
              max={500}
              disabled={disabled}
              value={options.maxTargets}
              onChange={(e) => onChange({ ...options, maxTargets: Number(e.target.value) })}
              className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white disabled:opacity-40"
            />
          </label>
        ) : null}
      </div>

      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Pipeline</p>
        <div className="space-y-2">
          <Check label="ZAP injection scan" hint="Spider + Active Scan (injection policy) → requests 재검증" checked={options.useZap} disabled={disabled} onChange={(useZap) => onChange({ ...options, useZap })} />
          <Check label="Direct requests" hint="api-tree 파라미터에 payload 주입 (requests, branch --direct)" checked={options.useDirect} disabled={disabled || !options.useInjector} onChange={(useDirect) => onChange({ ...options, useDirect })} />
          <Check label="Requests 검증 enabled" hint="ZAP 알림 재검증에 필요 (payload_injector / requests)" checked={options.useInjector} disabled={disabled} onChange={(useInjector) => onChange({ ...options, useInjector, useDirect: useInjector ? options.useDirect : false })} />
          {options.useZap ? (
            <label className="block">
              <span className="mb-1 block text-[10px] font-medium text-white">ZAP max minutes</span>
              <input type="number" min={1} max={120} disabled={disabled} value={options.zapMaxMinutes} onChange={(e) => onChange({ ...options, zapMaxMinutes: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white disabled:opacity-40" />
            </label>
          ) : null}
          <Check label="DELETE/PATCH 포함" hint="direct 모드에서만 적용" checked={options.includeUnsafeMethods} disabled={disabled || !options.useDirect} onChange={(includeUnsafeMethods) => onChange({ ...options, includeUnsafeMethods })} />
        </div>
      </div>

      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Verification</p>
        <select
          disabled={disabled}
          value={options.verificationMode}
          onChange={(e) => onChange({ ...options, verificationMode: e.target.value as G12VerificationMode })}
          className="mb-3 w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 text-xs text-white disabled:opacity-40"
        >
          <option value="strict">strict</option>
          <option value="balanced">balanced</option>
          <option value="aggressive">aggressive</option>
        </select>
        <p className="mb-2 text-[10px] text-cyber-muted">Injection types (direct)</p>
        <div className="flex flex-wrap gap-1.5">
          {INJECTION_TYPE_OPTIONS.map((t) => {
            const active = options.injectionTypes.includes(t);
            return (
              <button
                key={t}
                type="button"
                disabled={disabled}
                onClick={() => {
                  const next = active ? options.injectionTypes.filter((x) => x !== t) : [...options.injectionTypes, t];
                  onChange({ ...options, injectionTypes: next.length ? next : [t] });
                }}
                className={`rounded-md border px-2 py-1 font-mono text-[10px] transition ${
                  active ? "border-cyan-400/50 bg-cyan-500/15 text-cyan-200" : "border-cyber-border/50 text-cyber-muted hover:text-white"
                }`}
              >
                {t}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
