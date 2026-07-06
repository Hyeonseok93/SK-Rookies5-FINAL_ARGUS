import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  buildG22SummaryRows,
  isG22IssueRow,
  parseG22Findings,
  type G22Finding,
  type G22SummaryRow,
} from "../../lib/g22ReportView";

const SEVERITY_STYLES: Record<string, string> = {
  high: "text-rose-300",
  medium: "text-amber-300",
  low: "text-sky-300",
};

const SEVERITY_BADGE: Record<string, string> = {
  high: "border-rose-400/40 bg-rose-500/15 text-rose-200",
  medium: "border-amber-400/40 bg-amber-500/15 text-amber-200",
  low: "border-sky-400/40 bg-sky-500/15 text-sky-200",
};

function G22EllipsisCell({
  value,
  className = "",
  mono = false,
}: {
  value: string | null | undefined;
  className?: string;
  mono?: boolean;
}) {
  const full = (value ?? "").trim() || "—";
  return (
    <span
      className={`block min-w-0 truncate ${mono ? "font-mono" : ""} ${className}`}
      title={full !== "—" ? full : undefined}
    >
      {full}
    </span>
  );
}

function G22DetailCard({ row }: { row: G22SummaryRow }) {
  const [open, setOpen] = useState(false);
  const badge = SEVERITY_BADGE[row.severity] ?? SEVERITY_BADGE.low;

  return (
    <li className="rounded-lg border border-cyber-border/30 bg-cyber-panel/20 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium leading-none ${badge}`}>
          {row.severityLabel}
        </span>
        <span className="text-[10px] text-cyan-300/85">{row.typeLabel}</span>
        <span className="font-mono text-[10px] text-cyan-300/90">{row.serverLabel}</span>
        {row.engines.length > 0 ? (
          <span className="text-[9px] text-cyber-muted">{row.engines.join(" · ")}</span>
        ) : null}
      </div>
      <p className="mt-1.5 font-mono text-xs text-white/95">{row.endpointHint}</p>
      <p className="mt-1 text-xs font-medium text-white/90">{row.issueLabel}</p>
      <p className="mt-0.5 text-[10px] leading-relaxed text-white/70">{row.headline}</p>

      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="mt-2 flex items-center gap-1 text-[10px] text-cyber-muted transition hover:text-white/90"
      >
        <ChevronDown className={`h-3 w-3 transition ${open ? "rotate-180" : ""}`} />
        {open ? "상세 접기" : "상세 (URL · payload · 추출 텍스트)"}
      </button>

      {open ? (
        <div className="mt-2 space-y-2 border-t border-cyber-border/20 pt-2 text-[10px]">
          <p className="leading-relaxed text-white/80">{row.plainExplanation}</p>
          {row.groupedCount > 1 ? (
            <div className="rounded border border-cyber-border/20 bg-cyber-bg/40 px-2 py-1.5">
              <p className="mb-1 text-cyber-muted">포함 API ({row.groupedCount}건)</p>
              <ul className="space-y-0.5 font-mono text-cyan-300/80">
                {row.members.map((m) => (
                  <li key={m.rowKey}>{m.endpointLabel}</li>
                ))}
              </ul>
            </div>
          ) : null}
          <ul className="space-y-1">
            {row.detailFields.map((f) => (
              <li key={f.label} className="rounded border border-cyber-border/20 bg-cyber-bg/40 px-2 py-1">
                <span className="text-cyber-muted">{f.label} · </span>
                <span className="break-all font-mono text-cyan-300/80">{f.value}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </li>
  );
}

function G22IssueSummaryTable({ rows }: { rows: G22SummaryRow[] }) {
  if (rows.length === 0) {
    return (
      <div className="mb-3 rounded-lg border border-emerald-400/25 bg-emerald-500/5 px-3 py-2.5">
        <p className="text-xs font-medium text-emerald-200/95">조치 필요 항목 없음</p>
      </div>
    );
  }

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">중요 파일 · path 조작 — 검토 필요</span>
        <p className="mt-0.5 text-[10px] text-cyber-muted">{rows.length}건</p>
      </div>
      <table className="w-full min-w-[40rem] table-fixed text-left text-[10px]">
        <colgroup>
          <col style={{ width: "18%" }} />
          <col style={{ width: "32%" }} />
          <col style={{ width: "14%" }} />
          <col style={{ width: "30%" }} />
          <col style={{ width: "6%" }} />
        </colgroup>
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1.5 font-normal">유형</th>
            <th className="px-2 py-1.5 font-normal">API</th>
            <th className="px-2 py-1.5 font-normal">서버</th>
            <th className="px-2 py-1.5 font-normal">문제</th>
            <th className="px-2 py-1.5 text-center font-normal">Sev</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={`${row.rowKey}|${row.endpointHint}`} className="border-b border-cyber-border/10 last:border-0">
              <td className="px-2 py-1.5 align-middle text-cyan-300/85">{row.typeLabel}</td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                <G22EllipsisCell value={row.endpointHint} className="text-white/90" mono />
              </td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                <G22EllipsisCell value={row.serverLabel} className="text-cyan-300/90" mono />
              </td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle text-white/85">
                <G22EllipsisCell value={row.issueLabel} />
              </td>
              <td className="px-2 py-1.5 text-center align-middle">
                <span
                  className={`inline-flex items-center font-mono text-[9px] leading-none uppercase ${SEVERITY_STYLES[row.severity] ?? ""}`}
                >
                  {row.severityLabel}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function G22FindingsPanel({ findings }: { findings: G22Finding[] }) {
  const { rows, other } = parseG22Findings(findings);
  const summaryRows = buildG22SummaryRows(rows).filter(isG22IssueRow);

  return (
    <>
      <G22IssueSummaryTable rows={summaryRows} />
      {summaryRows.length > 0 ? (
        <CollapsibleReportSection title="상세" defaultOpen={false}>
          <ul className="space-y-2">
            {summaryRows.map((row) => (
              <G22DetailCard key={`${row.rowKey}|${row.endpointHint}`} row={row} />
            ))}
          </ul>
        </CollapsibleReportSection>
      ) : null}
      {other.length > 0 ? (
        <CollapsibleReportSection title="기타" defaultOpen={false}>
          <ul className="space-y-2">
            {other.map((f, i) => (
              <li
                key={`other-${i}`}
                className="rounded border border-cyber-border/30 bg-cyber-panel/30 px-3 py-2 text-xs text-white/90"
              >
                {f.message}
              </li>
            ))}
          </ul>
        </CollapsibleReportSection>
      ) : null}
    </>
  );
}
