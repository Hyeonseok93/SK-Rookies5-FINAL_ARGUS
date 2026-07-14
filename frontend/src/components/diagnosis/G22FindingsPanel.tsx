import { useEffect, useMemo, useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  buildG22SummaryRows,
  g22EvidenceUrl,
  indexG22CaptureShots,
  isG22IssueRow,
  parseG22Findings,
  resolveG22ShotsForRow,
  type G22EvidenceShot,
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

function G22ShotStack({ shots }: { shots: G22EvidenceShot[] }) {
  if (shots.length === 0) return null;
  return (
    <div className="space-y-2">
      <p className="text-cyber-muted">증거 스크린샷 ({shots.length})</p>
      <div className="grid grid-cols-1 gap-2">
        {shots.map((shot) => (
          <figure
            key={`${shot.kind}-${shot.path}`}
            className="overflow-hidden rounded border border-cyber-border/30 bg-black/20"
          >
            <img
              src={g22EvidenceUrl(shot.path)}
              alt={shot.label}
              className="w-full object-contain"
              loading="lazy"
            />
            <figcaption className="border-t border-cyber-border/25 px-2 py-1 text-[10px] text-cyber-muted">
              {shot.label}
            </figcaption>
          </figure>
        ))}
      </div>
    </div>
  );
}

function G22DetailCard({
  row,
  shots,
}: {
  row: G22SummaryRow;
  shots: G22EvidenceShot[];
}) {
  const [open, setOpen] = useState(false);
  const badge = SEVERITY_BADGE[row.severity] ?? SEVERITY_BADGE.low;
  const detailHint =
    shots.length > 0 ? "상세 (URL · payload · 증거 스크린샷)" : "상세 (URL · payload · 추출 텍스트)";

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
        {open ? "상세 접기" : detailHint}
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
          <G22ShotStack shots={shots} />
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

function useG22ShotMap(rows: G22SummaryRow[]) {
  const [shotMap, setShotMap] = useState<Record<string, G22EvidenceShot[]>>({});
  const rowSignature = useMemo(
    () => rows.map((r) => `${r.rowKey}|${r.findingId ?? ""}|${r.members.map((m) => m.findingId ?? "").join(",")}`).join(";"),
    [rows],
  );

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/diagnosis/modules/2-2/evidence?path=capture-summary.json");
        if (!res.ok) {
          if (!cancelled) setShotMap({});
          return;
        }
        const summary = (await res.json()) as Parameters<typeof indexG22CaptureShots>[0];
        const byId = indexG22CaptureShots(summary);
        const next: Record<string, G22EvidenceShot[]> = {};
        await Promise.all(
          rows.map(async (row) => {
            const shots = await resolveG22ShotsForRow(row, byId);
            if (shots.length > 0) next[`${row.rowKey}|${row.endpointHint}`] = shots;
          }),
        );
        if (!cancelled) setShotMap(next);
      } catch {
        if (!cancelled) setShotMap({});
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [rowSignature, rows]);

  return shotMap;
}

export function G22FindingsPanel({ findings }: { findings: G22Finding[] }) {
  const { rows, other } = parseG22Findings(findings);
  const summaryRows = buildG22SummaryRows(rows).filter(isG22IssueRow);
  const shotMap = useG22ShotMap(summaryRows);

  return (
    <>
      <G22IssueSummaryTable rows={summaryRows} />
      {summaryRows.length > 0 ? (
        <CollapsibleReportSection title="상세" defaultOpen={false}>
          <ul className="space-y-2">
            {summaryRows.map((row) => {
              const key = `${row.rowKey}|${row.endpointHint}`;
              return <G22DetailCard key={key} row={row} shots={shotMap[key] ?? []} />;
            })}
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
