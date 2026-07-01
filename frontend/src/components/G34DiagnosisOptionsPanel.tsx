import type { G34DiagnosisOptions, G34InventoryScope } from "../lib/g34DiagnosisOptions";

function ScopeOption({
  scope,
  title,
  hint,
  selected,
  onSelect,
}: {
  scope: G34InventoryScope;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (scope: G34InventoryScope) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        selected ? "border-cyan-400/40 bg-cyan-500/10" : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input type="radio" name="g34-scope" checked={selected} onChange={() => onSelect(scope)} className="mt-0.5 accent-cyan-400" />
      <span>
        <span className="block text-xs font-medium text-white">{title}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

export function G34DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G34DiagnosisOptions;
  onChange: (next: G34DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-amber-400/30 bg-amber-500/5 px-3 py-2 text-[10px] text-amber-200/90">
        httpx probe 없음 — login_entry_report + api-tree 정적 분석. Verify 후 login matrix 필요.
      </div>
      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">분석 범위</p>
        <ScopeOption scope="login_only" title="Login matrix만" hint="user/admin login URL · host separation — path heuristics 스킵" selected={options.inventoryScope === "login_only"} onSelect={(inventoryScope) => onChange({ ...options, inventoryScope })} />
        <ScopeOption scope="full" title="Login + api-tree 전체" hint="admin UI/API same-server · guessable path 포함" selected={options.inventoryScope === "full"} onSelect={(inventoryScope) => onChange({ ...options, inventoryScope })} />
      </div>
    </div>
  );
}
