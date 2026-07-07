import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  formatG15TargetDisplay,
  isG15SummaryRow,
  parseG15Findings,
  type G15Finding,
  type G15Row,
} from "../../lib/g15ReportView";

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

function G15EllipsisCell({
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

function G15DetailCard({ row }: { row: G15Row }) {
  const [open, setOpen] = useState(false);
  const badge = SEVERITY_BADGE[row.severity] ?? SEVERITY_BADGE.low;

  return (
    <li className="rounded-lg border border-cyber-border/30 bg-cyber-panel/20 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${badge}`}>
          {row.severityLabel}
        </span>
        <span className="text-[10px] text-cyan-300/85">{row.categoryLabel}</span>
        <span className="font-mono text-[10px] text-cyan-300/90">{formatG15TargetDisplay(row)}</span>
      </div>
      <p className="mt-1.5 text-xs font-medium text-white/90">{row.issueLabel}</p>
      <p className="mt-0.5 text-[10px] leading-relaxed text-white/70">{row.headline}</p>

      {row.detailFields.length > 0 ? (
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="mt-2 flex items-center gap-1 text-[10px] text-cyber-muted transition hover:text-white/90"
        >
          <ChevronDown className={`h-3 w-3 transition ${open ? "rotate-180" : ""}`} />
          {open ? "상세 접기" : "상세 (URL · 헤더)"}
        </button>
      ) : null}

      {open ? (
        <div className="mt-2 space-y-2 border-t border-cyber-border/20 pt-2 text-[10px]">
          <p className="leading-relaxed text-white/80">{row.plainExplanation}</p>
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

function G15IssueSummaryTable({ rows }: { rows: G15Row[] }) {
  if (rows.length === 0) {
    return (
      <div className="mb-3 rounded-lg border border-emerald-400/25 bg-emerald-500/5 px-3 py-2.5">
        <p className="text-xs font-medium text-emerald-200/95">검토 필요 항목 없음</p>
        <p className="mt-1 text-[10px] text-emerald-300/80">
          외부 리다이렉트 · CORS · crossdomain — 이상 없음
        </p>
      </div>
    );
  }

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">리다이렉트 · CORS — 검토 필요</span>
        <p className="mt-0.5 text-[10px] text-cyber-muted">{rows.length}건</p>
      </div>
      <table className="w-full min-w-[36rem] table-fixed text-left text-[10px]">
        <colgroup>
          <col style={{ width: "18%" }} />
          <col style={{ width: "16%" }} />
          <col style={{ width: "32%" }} />
          <col style={{ width: "28%" }} />
          <col style={{ width: "6%" }} />
        </colgroup>
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1.5 font-normal">유형</th>
            <th className="px-2 py-1.5 font-normal">서버</th>
            <th className="px-2 py-1.5 font-normal">문제</th>
            <th className="px-2 py-1.5 font-normal">규모</th>
            <th className="px-2 py-1.5 text-center font-normal">Sev</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.rowKey} className="border-b border-cyber-border/10 last:border-0">
              <td className="px-2 py-1.5 align-middle text-cyan-300/85">{row.categoryLabel}</td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                <G15EllipsisCell
                  value={formatG15TargetDisplay(row)}
                  className="text-cyan-300/90"
                  mono
                />
              </td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle text-white/90">
                <G15EllipsisCell value={row.issueLabel} />
              </td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle text-white/75">
                <G15EllipsisCell value={row.scaleSummary} />
              </td>
              <td className="px-2 py-1.5 text-center align-middle">
                <span
                  className={`font-mono text-[9px] uppercase ${SEVERITY_STYLES[row.severity] ?? ""}`}
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

export function G15FindingsPanel({ findings }: { findings: G15Finding[] }) {
  const { rows, other } = parseG15Findings(findings);
  const issueRows = rows.filter(isG15SummaryRow);

  return (
    <>
      <G15IssueSummaryTable rows={issueRows} />
      {issueRows.length > 0 ? (
        <CollapsibleReportSection title="상세" defaultOpen={false}>
          <ul className="space-y-2">
            {issueRows.map((row) => (
              <G15DetailCard key={row.rowKey} row={row} />
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
