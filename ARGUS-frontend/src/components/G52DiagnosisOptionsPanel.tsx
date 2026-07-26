import type { G52DiagnosisOptions, G52OptionsTab, G52ProbeMode } from "../lib/g52DiagnosisOptions";
import {
  G52_EXHAUSTIVE_PRESET,
  G52_SMOKE_PRESET,
  G52_TAB_HINTS,
  G52_TAB_LABELS,
} from "../lib/g52DiagnosisOptions";

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
        checked ? "border-cyan-400/40 bg-cyan-500/10" : "border-cyber-border/50 hover:border-cyber-border"
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

function PresetSummary({ tab }: { tab: "smoke" | "exhaustive" }) {
  const rows =
    tab === "exhaustive"
      ? [
          ["대상", "api-tree verified API 전체"],
          ["요청", "URL query/path · request body"],
          ["응답", "response body JSON/text"],
          ["탐지", "주민번호·전화·이메일·여권·계좌·카드·이름·경로·HTTP 평문"],
          ["인증", "익명 + 각 테스트 계정"],
        ]
      : [
          ["대상", "api-tree 무작위 40 API"],
          ["검사", "요청 URL/body + 응답 body PII"],
        ];

  return (
    <div className="rounded-lg border border-cyan-400/25 bg-cyan-500/5 px-3 py-2 text-[11px] text-cyber-muted">
      <p className="mb-2 font-medium text-cyan-300/90">{G52_TAB_HINTS[tab]}</p>
      <dl className="space-y-1">
        {rows.map(([k, v]) => (
          <div key={k} className="flex gap-2">
            <dt className="w-16 shrink-0 font-mono text-[10px]">{k}</dt>
            <dd className="text-white/90">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function G52DiagnosisOptionsPanel({
  activeTab,
  onTabChange,
  options,
  onChange,
}: {
  activeTab: G52OptionsTab;
  onTabChange: (tab: G52OptionsTab) => void;
  options: G52DiagnosisOptions;
  onChange: (next: G52DiagnosisOptions) => void;
}) {
  const presetLocked = activeTab === "smoke" || activeTab === "exhaustive";

  const selectTab = (tab: G52OptionsTab) => {
    onTabChange(tab);
    if (tab === "smoke") onChange({ ...G52_SMOKE_PRESET });
    else if (tab === "exhaustive") onChange({ ...G52_EXHAUSTIVE_PRESET });
  };

  const patch = (p: Partial<G52DiagnosisOptions>) => {
    onChange({ ...options, ...p });
    if (presetLocked) onTabChange("custom");
  };

  return (
    <div className="space-y-3">
      <div className="flex rounded-lg border border-cyber-border/60 bg-cyber-bg/40 p-0.5" role="tablist">
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
            <span className="block text-xs font-semibold">{G52_TAB_LABELS[tab]}</span>
          </button>
        ))}
      </div>

      {activeTab === "smoke" ? <PresetSummary tab="smoke" /> : null}
      {activeTab === "exhaustive" ? <PresetSummary tab="exhaustive" /> : null}

      <div className="grid grid-cols-2 gap-2 opacity-100">
        <label className={`block text-[10px] text-cyber-muted ${presetLocked ? "opacity-50" : ""}`}>
          probe_mode
          <select
            disabled={presetLocked}
            value={options.probeMode}
            onChange={(e) => patch({ probeMode: e.target.value as G52ProbeMode })}
            className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 text-xs text-white"
          >
            <option value="sample">sample</option>
            <option value="full">full</option>
          </select>
        </label>
        <label className={`block text-[10px] text-cyber-muted ${presetLocked ? "opacity-50" : ""}`}>
          max_endpoints (0=전체)
          <input
            type="number"
            min={0}
            disabled={presetLocked}
            value={options.maxEndpoints}
            onChange={(e) => patch({ maxEndpoints: Number(e.target.value) })}
            className="mt-1 w-full rounded border border-cyber-border/60 bg-cyber-bg/50 px-2 py-1 text-xs text-white"
          />
        </label>
      </div>

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-muted">검사 범위</p>
        <Check
          label="요청 URL (query/path)"
          hint="파라미터에 주민번호·전화·경로 등 노출"
          checked={options.checkRequestUrl}
          onChange={(v) => patch({ checkRequestUrl: v })}
          disabled={presetLocked}
        />
        <Check
          label="요청 body"
          hint="POST/PUT JSON·form 내 개인정보"
          checked={options.checkRequestBody}
          onChange={(v) => patch({ checkRequestBody: v })}
          disabled={presetLocked}
        />
        <Check
          label="응답 body"
          hint="마스킹 없는 PII in response"
          checked={options.checkResponseBody}
          onChange={(v) => patch({ checkResponseBody: v })}
          disabled={presetLocked}
        />
        <Check
          label="HTTP 평문 전송"
          hint="http:// 에 민감 데이터 포함 시"
          checked={options.checkHttpPlain}
          onChange={(v) => patch({ checkHttpPlain: v })}
          disabled={presetLocked}
        />
        <Check
          label="익명 + 각 테스트 계정"
          hint="인증별 응답 차이 확인"
          checked={options.enableAuthModes}
          onChange={(v) => patch({ enableAuthModes: v })}
          disabled={presetLocked}
        />
      </div>
    </div>
  );
}
