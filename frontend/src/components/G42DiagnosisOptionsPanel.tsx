import type { G42DiagnosisOptions } from "../lib/g42DiagnosisOptions";

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
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="mt-0.5 accent-cyan-400" />
      <span>
        <span className="block text-xs font-medium text-white">{label}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

export function G42DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G42DiagnosisOptions;
  onChange: (next: G42DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-amber-400/30 bg-amber-500/5 px-3 py-2 text-[10px] text-amber-200/90">
        Verify 세션 + login_entry_report 필요. 정적 토큰 분석은 항상 실행됩니다.
      </div>
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3 space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Lifecycle probes (httpx)</p>
        <Check label="Re-login token uniqueness" hint="재로그인 시 access token 변경 여부" checked={options.reloginEnabled} onChange={(reloginEnabled) => onChange({ ...options, reloginEnabled })} />
        <Check label="Duplicate login" hint="동일 계정 중복 세션" checked={options.duplicateLoginEnabled} onChange={(duplicateLoginEnabled) => onChange({ ...options, duplicateLoginEnabled })} />
        <Check label="Cross-IP duplicate login" hint="X-Forwarded-For IP 바인딩" checked={options.duplicateLoginIpEnabled} onChange={(duplicateLoginIpEnabled) => onChange({ ...options, duplicateLoginIpEnabled })} />
        <Check label="Server logout invalidation" hint="logout API 후 토큰 무효화" checked={options.logoutEnabled} onChange={(logoutEnabled) => onChange({ ...options, logoutEnabled })} />
        {options.logoutEnabled ? (
          <Check label="Client-only logout (SPA)" hint="서버 logout API 없을 때 client logout + refresh probe" checked={options.clientLogoutEnabled} onChange={(clientLogoutEnabled) => onChange({ ...options, clientLogoutEnabled })} />
        ) : null}
      </div>
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Probe 계정 이메일 (선택)</span>
        <input type="text" value={options.probeAccountEmail} onChange={(e) => onChange({ ...options, probeAccountEmail: e.target.value })} placeholder="비우면 자동 선택" className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Timeout (초)</span>
        <input type="number" min={1} max={60} value={options.timeout} onChange={(e) => onChange({ ...options, timeout: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
    </div>
  );
}
