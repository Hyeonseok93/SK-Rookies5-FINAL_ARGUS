import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import { FindingEvidence } from "./DiagnosisReportPanel";
import {
  buildG16Groups,
  severityLabelKo,
  sortG16Groups,
  type G16CaseGroup,
  type G16Finding,
} from "../../lib/g16ReportView";

const SEVERITY_BADGE: Record<string, string> = {
  high: "border-rose-400/40 bg-rose-500/15 text-rose-200",
  medium: "border-amber-400/40 bg-amber-500/15 text-amber-200",
  low: "border-sky-400/40 bg-sky-500/15 text-sky-200",
  info: "border-cyber-border/60 bg-cyber-bg/40 text-cyber-muted",
};

function G16Overview({ groups, status }: { groups: G16CaseGroup[]; status: string }) {
  const total = groups.reduce((sum, g) => sum + g.count, 0);
  const high = groups.filter((g) => g.severity === "high").reduce((s, g) => s + g.count, 0);
  const medium = groups.filter((g) => g.severity === "medium").reduce((s, g) => s + g.count, 0);
  const low = groups.filter((g) => g.severity === "low").reduce((s, g) => s + g.count, 0);
  const headline =
    status === "pass"
      ? "입력 값 크기·무결성 검증 — 이상 없음"
      : high > 0
        ? "입력 값 크기·무결성 검증 — 검증 누락 확인, 즉시 조치 필요"
        : "입력 값 크기·무결성 검증 — 검토 필요";

  return (
    <div className="mb-3 rounded-lg border border-cyber-border/50 bg-cyber-bg/20 px-3 py-2.5">
      <p className="text-xs font-semibold text-white">{headline}</p>
      <p className="mt-1 text-[10px] text-cyber-muted">
        총 {total.toLocaleString()}건 · 높음 {high.toLocaleString()} · 중간 {medium.toLocaleString()} · 낮음{" "}
        {low.toLocaleString()}
      </p>
    </div>
  );
}

function G16DetailCard({ group }: { group: G16CaseGroup }) {
  const [open, setOpen] = useState(false);
  const badge = SEVERITY_BADGE[group.severity] ?? SEVERITY_BADGE.low;

  return (
    <li className="rounded-lg border border-cyber-border/30 bg-cyber-panel/20 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${badge}`}>
          {severityLabelKo(group.severity)}
        </span>
        <span className="font-mono text-[10px] text-cyan-300/90">{group.origin}</span>
        <span className="font-mono text-[10px] text-white/80">{group.count.toLocaleString()}건</span>
      </div>
      <p className="mt-1.5 text-xs font-medium text-white/95">{group.exception_type}</p>
      {group.sample_payload_names.length > 0 ? (
        <p className="mt-0.5 text-[10px] text-white/60">payload · {group.sample_payload_names.join(", ")}</p>
      ) : null}

      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="mt-2 flex items-center gap-1 text-[10px] text-cyber-muted transition hover:text-white/90"
      >
        <ChevronDown className={`h-3 w-3 transition ${open ? "rotate-180" : ""}`} />
        {open ? "상세 접기" : "상세 (샘플 URL · 증거 스크린샷)"}
      </button>

      {open ? (
        <div className="mt-2 space-y-2 border-t border-cyber-border/20 pt-2 text-[10px]">
          {group.sample_status_codes.length > 0 ? (
            <p className="text-cyber-muted">
              HTTP status · <span className="font-mono text-white/80">{group.sample_status_codes.join(", ")}</span>
            </p>
          ) : null}
          {group.sample_urls.length > 0 ? (
            <div className="rounded border border-cyber-border/20 bg-cyber-bg/40 px-2 py-1.5">
              <p className="mb-1 text-cyber-muted">샘플 URL ({group.sample_urls.length})</p>
              <ul className="space-y-0.5 font-mono text-cyan-300/80">
                {group.sample_urls.map((u) => (
                  <li key={u} className="break-all">
                    {u}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {group.sample_findings.map((f, i) => (
            <FindingEvidence key={i} evidence={f.evidence} sectionId="1-6" />
          ))}
        </div>
      ) : null}
    </li>
  );
}

export function G16FindingsPanel({
  findings,
  status,
}: {
  findings: G16Finding[];
  status: string;
}) {
  const groups = sortG16Groups(buildG16Groups(findings));

  return (
    <>
      <G16Overview groups={groups} status={status} />
      {groups.length === 0 ? (
        <div className="rounded-lg border border-emerald-400/25 bg-emerald-500/5 px-3 py-2.5">
          <p className="text-xs font-medium text-emerald-200/95">조치 필요 항목 없음</p>
        </div>
      ) : (
        <CollapsibleReportSection title={`케이스별 결과 보기 (${groups.length}개 그룹)`} defaultOpen={false}>
          <ul className="space-y-2">
            {groups.map((g) => (
              <G16DetailCard key={g.group_key} group={g} />
            ))}
          </ul>
        </CollapsibleReportSection>
      )}
    </>
  );
}
