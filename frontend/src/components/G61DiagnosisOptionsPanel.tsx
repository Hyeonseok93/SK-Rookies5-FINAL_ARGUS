import type { G61DiagnosisOptions, G61OptionsTab, G61ProbeMode } from "../lib/g61DiagnosisOptions";
import {
  G61_EXHAUSTIVE_PRESET,
  G61_SMOKE_PRESET,
  G61_TAB_HINTS,
  G61_TAB_LABELS,
  g61RequestCapLabel,
} from "../lib/g61DiagnosisOptions";

function Check({
  label,
  hint,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        checked
          ? "border-cyan-400/40 bg-cyan-500/10"
          : "border-cyber-border/50 hover:border-cyber-border"
      } ${disabled ? "pointer-events-none opacity-50" : ""}`}
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

function ProbeModeOption({
  mode,
  title,
  hint,
  selected,
  onSelect,
  disabled,
}: {
  mode: G61ProbeMode;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (mode: G61ProbeMode) => void;
  disabled?: boolean;
}) {
  return (
    <label
      className={`flex items-start gap-2 rounded-lg border px-3 py-2 transition ${
        disabled ? "pointer-events-none opacity-50" : "cursor-pointer"
      } ${
        selected
          ? "border-cyan-400/40 bg-cyan-500/10"
          : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input
        type="radio"
        name="g61-probe-mode"
        checked={selected}
        disabled={disabled}
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

function PresetSummary({ tab }: { tab: "smoke" | "exhaustive" }) {
  const preset = tab === "exhaustive" ? G61_EXHAUSTIVE_PRESET : G61_SMOKE_PRESET;
  const rows =
    tab === "exhaustive"
      ? [
          ["대상", "api-tree verified API 전체 (max_endpoints=0)"],
          ["퍼징", "모든 param · body · path · method · header"],
          ["인증", "익명 + 각 테스트 계정"],
          ["httpx", g61RequestCapLabel(preset.maxRequests)],
          ["ZAP unified", `${g61RequestCapLabel(preset.zapMaxRequests)} (동일 triggers)`],
          ["ZAP supplemental", `90022/10023 · ${preset.zapMaxMinutes}분 · seed ${preset.zapSeedCap <= 0 ? "전체" : preset.zapSeedCap}`],
        ]
      : [
          ["대상", `api-tree에서 무작위 ${preset.sampleSize}개 API`],
          ["퍼징", "선택된 API에 param/body/path/method/header 전수"],
          ["httpx", g61RequestCapLabel(preset.maxRequests)],
          ["ZAP", `unified+supplemental ${g61RequestCapLabel(preset.zapMaxRequests)} / ${preset.zapMaxMinutes}분`],
        ];

  return (
    <div className="rounded-lg border border-cyan-400/25 bg-cyan-500/5 px-3 py-2 text-[11px] text-cyber-muted">
      <p className="mb-2 font-medium text-cyan-300/90">{G61_TAB_HINTS[tab]}</p>
      <dl className="space-y-1">
        {rows.map(([k, v]) => (
          <div key={k} className="flex gap-2">
            <dt className="w-24 shrink-0 font-mono text-[10px] text-cyber-muted">{k}</dt>
            <dd className="text-white/90">{v}</dd>
          </div>
        ))}
      </dl>
      {tab === "exhaustive" ? (
        <p className="mt-2 text-[10px] text-emerald-300/80">
          요청·ZAP seed 상한 없이 api-tree 전체 API × 모든 트리거 × 인증 패스를 끝까지 실행합니다. API가
          많으면 시간이 오래 걸릴 수 있습니다.
        </p>
      ) : null}
    </div>
  );
}

export function G61DiagnosisOptionsPanel({
  activeTab,
  onTabChange,
  options,
  onChange,
}: {
  activeTab: G61OptionsTab;
  onTabChange: (tab: G61OptionsTab) => void;
  options: G61DiagnosisOptions;
  onChange: (next: G61DiagnosisOptions) => void;
}) {
  const presetLocked = activeTab === "smoke" || activeTab === "exhaustive";

  const selectTab = (tab: G61OptionsTab) => {
    onTabChange(tab);
    if (tab === "smoke") onChange({ ...G61_SMOKE_PRESET });
    else if (tab === "exhaustive") onChange({ ...G61_EXHAUSTIVE_PRESET });
  };

  const patch = (patch: Partial<G61DiagnosisOptions>) => {
    onChange({ ...options, ...patch });
    if (presetLocked) onTabChange("custom");
  };

  return (
    <div className="space-y-3">
      <div
        className="flex rounded-lg border border-cyber-border/60 bg-cyber-bg/40 p-0.5"
        role="tablist"
        aria-label="6-1 scan preset"
      >
        {(["smoke", "exhaustive", "custom"] as const).map((tab) => (
          <button
            key={tab}
            type="button"
            role="tab"
            aria-selected={activeTab === tab}
            onClick={() => selectTab(tab)}
            className={`flex-1 rounded-md px-2 py-2 text-center transition ${
              activeTab === tab
                ? tab === "exhaustive"
                  ? "bg-amber-500/20 text-amber-200"
                  : "bg-cyan-500/20 text-cyan-200"
                : "text-cyber-muted hover:text-white"
            }`}
          >
            <span className="block text-xs font-semibold">{G61_TAB_LABELS[tab]}</span>
            <span className="mt-0.5 block text-[9px] leading-tight opacity-80">
              {tab === "smoke" ? "40 API" : tab === "exhaustive" ? "전체 API" : "수동"}
            </span>
          </button>
        ))}
      </div>

      {activeTab === "smoke" ? <PresetSummary tab="smoke" /> : null}
      {activeTab === "exhaustive" ? <PresetSummary tab="exhaustive" /> : null}

      {activeTab === "custom" ? (
        <p className="text-[10px] text-cyber-muted">{G61_TAB_HINTS.custom}</p>
      ) : null}

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-muted">범위</p>
        <ProbeModeOption
          mode="sample"
          title="Sample"
          hint="sample_size개 API만 무작위 선택"
          selected={options.probeMode === "sample"}
          onSelect={(probeMode) => patch({ probeMode })}
          disabled={presetLocked}
        />
        <ProbeModeOption
          mode="full"
          title="Full"
          hint="api-tree API 전체 (max_endpoints=0이면 상한 없음)"
          selected={options.probeMode === "full"}
          onSelect={(probeMode) => patch({ probeMode })}
          disabled={presetLocked}
        />
      </div>

      <div className="grid grid-cols-2 gap-2">
        <label className={`block text-[10px] text-cyber-muted ${presetLocked ? "opacity-50" : ""}`}>
          sample_size
          <input
            type="number"
            min={5}
            max={500}
            disabled={presetLocked || options.probeMode === "full"}
            value={options.sampleSize}
            onChange={(e) => patch({ sampleSize: Number(e.target.value) })}
            className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 text-xs text-white disabled:opacity-60"
          />
        </label>
        <label className={`block text-[10px] text-cyber-muted ${presetLocked ? "opacity-50" : ""}`}>
          max_endpoints (0=무제한)
          <input
            type="number"
            min={0}
            max={500}
            disabled={presetLocked}
            value={options.maxEndpoints}
            onChange={(e) => patch({ maxEndpoints: Number(e.target.value) })}
            className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 text-xs text-white disabled:opacity-60"
          />
        </label>
        <label className={`block text-[10px] text-cyber-muted ${presetLocked ? "opacity-50" : ""}`}>
          max_requests (0=무제한)
          <input
            type="number"
            min={0}
            step={100}
            disabled={presetLocked}
            value={options.maxRequests}
            onChange={(e) => patch({ maxRequests: Number(e.target.value) })}
            className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 text-xs text-white disabled:opacity-60"
          />
        </label>
        <label className={`block text-[10px] text-cyber-muted ${presetLocked ? "opacity-50" : ""}`}>
          timeout (s)
          <input
            type="number"
            min={1}
            max={60}
            step={0.5}
            disabled={presetLocked}
            value={options.timeout}
            onChange={(e) => patch({ timeout: Number(e.target.value) })}
            className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 text-xs text-white disabled:opacity-60"
          />
        </label>
      </div>

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-muted">httpx</p>
        <Check
          label="httpx Phase A (ARGUS fuzz)"
          hint="param/body/path/method/header 전수 퍼징"
          checked={options.useHttpx}
          onChange={(useHttpx) => patch({ useHttpx })}
          disabled={presetLocked}
        />
      </div>

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-muted">ZAP</p>
        <Check
          label="ZAP enabled"
          hint="ZapTransport 동일 fuzz + native rules"
          checked={options.useZap}
          onChange={(useZap) => patch({ useZap })}
          disabled={presetLocked}
        />
        {options.useZap ? (
          <>
            <Check
              label="ZAP unified (param fuzz via sendRequest)"
              hint="httpx와 동일 triggers"
              checked={options.zapUnified}
              onChange={(zapUnified) => patch({ zapUnified })}
              disabled={presetLocked}
            />
            <Check
              label="ZAP supplemental (90022 + 10023)"
              hint="Native error disclosure rules"
              checked={options.zapSupplemental}
              onChange={(zapSupplemental) => patch({ zapSupplemental })}
              disabled={presetLocked}
            />
            <div className={`grid grid-cols-2 gap-2 ${presetLocked ? "opacity-50" : ""}`}>
              <label className="block text-[10px] text-cyber-muted">
                zap_max_requests (0=무제한)
                <input
                  type="number"
                  min={0}
                  step={100}
                  disabled={presetLocked}
                  value={options.zapMaxRequests}
                  onChange={(e) => patch({ zapMaxRequests: Number(e.target.value) })}
                  className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 text-xs text-white disabled:opacity-60"
                />
              </label>
              <label className="block text-[10px] text-cyber-muted">
                zap_max_minutes
                <input
                  type="number"
                  min={1}
                  max={480}
                  disabled={presetLocked}
                  value={options.zapMaxMinutes}
                  onChange={(e) => patch({ zapMaxMinutes: Number(e.target.value) })}
                  className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 text-xs text-white disabled:opacity-60"
                />
              </label>
              <label className="block text-[10px] text-cyber-muted">
                zap_seed_cap (0=전체)
                <input
                  type="number"
                  min={0}
                  disabled={presetLocked}
                  value={options.zapSeedCap}
                  onChange={(e) => patch({ zapSeedCap: Number(e.target.value) })}
                  className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 text-xs text-white disabled:opacity-60"
                />
              </label>
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
}
