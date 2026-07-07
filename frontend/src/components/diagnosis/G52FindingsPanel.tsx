import { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  buildG52ApiDetailGroups,
  formatG52AuthSummary,
  formatG52SampleCount,
  mergeG52Findings,
  parseG52RawFindings,
  type G52ApiDetailGroup,
  type G52AuthColumn,
  type G52DetailCell,
  type G52DetailRow,
  type G52Finding,
  type G52MergedFinding,
} from "../../lib/g52ReportView";

const SEVERITY_STYLES: Record<string, string> = {
  high: "text-rose-300",
  medium: "text-amber-300",
  low: "text-sky-300",
  info: "text-cyber-muted",
};

const HOVER_LEAVE_MS = 140;

function G52SampleHoverCard({
  row,
}: {
  row: Pick<G52MergedFinding, "samples" | "fieldPath" | "ruleLabel" | "directionLabel">;
}) {
  const anchorRef = useRef<HTMLSpanElement>(null);
  const leaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ top: 0, left: 0 });

  const clearLeaveTimer = useCallback(() => {
    if (leaveTimer.current != null) {
      clearTimeout(leaveTimer.current);
      leaveTimer.current = null;
    }
  }, []);

  const updatePosition = useCallback(() => {
    const el = anchorRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const cardWidth = 300;
    const margin = 8;
    let left = rect.left;
    if (left + cardWidth > window.innerWidth - margin) {
      left = Math.max(margin, window.innerWidth - cardWidth - margin);
    }
    const top = rect.bottom + 6;
    setPos({ top, left });
  }, []);

  const showCard = useCallback(() => {
    clearLeaveTimer();
    updatePosition();
    setOpen(true);
  }, [clearLeaveTimer, updatePosition]);

  const scheduleHide = useCallback(() => {
    clearLeaveTimer();
    leaveTimer.current = setTimeout(() => setOpen(false), HOVER_LEAVE_MS);
  }, [clearLeaveTimer]);

  const countLabel = formatG52SampleCount(row.samples);
  if (row.samples.length === 0) {
    return <span className="text-cyber-muted">—</span>;
  }

  const popover =
    open && typeof document !== "undefined"
      ? createPortal(
          <div
            className="pointer-events-auto fixed z-[300] w-[min(300px,calc(100vw-1rem))] overflow-hidden rounded-lg border border-amber-400/35 bg-cyber-panel/98 shadow-[0_12px_40px_rgba(0,0,0,0.55)] backdrop-blur-md"
            style={{ top: pos.top, left: pos.left }}
            onMouseEnter={showCard}
            onMouseLeave={scheduleHide}
            role="tooltip"
          >
            <div className="border-b border-amber-400/20 bg-amber-500/10 px-3 py-2">
              <p className="text-[11px] font-semibold text-amber-100/95">
                샘플 {row.samples.length}건
              </p>
              <p className="mt-0.5 text-[9px] text-cyber-muted">
                {row.ruleLabel}
                {row.directionLabel ? ` · ${row.directionLabel}` : ""}
              </p>
              {row.fieldPath ? (
                <p className="mt-1 break-all font-mono text-[9px] text-cyan-300/70">{row.fieldPath}</p>
              ) : null}
            </div>
            <ul className="max-h-52 space-y-1 overflow-y-auto px-2 py-2">
              {row.samples.map((sample, index) => (
                <li
                  key={`${index}-${sample}`}
                  className="flex gap-2 rounded border border-cyber-border/25 bg-cyber-bg/50 px-2 py-1.5"
                >
                  <span className="shrink-0 font-mono text-[9px] text-cyber-muted">{index + 1}</span>
                  <span className="min-w-0 break-all font-mono text-[10px] leading-relaxed text-amber-100/95">
                    {sample}
                  </span>
                </li>
              ))}
            </ul>
          </div>,
          document.body,
        )
      : null;

  return (
    <>
      <span
        ref={anchorRef}
        onMouseEnter={showCard}
        onMouseLeave={scheduleHide}
        onFocus={showCard}
        onBlur={scheduleHide}
        tabIndex={0}
        className="inline-flex cursor-default rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-200/95 transition hover:border-amber-400/55 hover:bg-amber-500/20 focus:outline-none focus:ring-1 focus:ring-amber-400/40"
      >
        {countLabel}
      </span>
      {popover}
    </>
  );
}

function G52SummaryTable({ merged }: { merged: G52MergedFinding[] }) {
  if (merged.length === 0) return null;

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">주요정보 노출</span>
        <p className="mt-0.5 text-[10px] text-cyber-muted">
          동일 API·필드·유형은 계정별 중복 없이 한 줄로 묶었습니다. 배열 항목은{" "}
          <span className="font-mono text-cyan-300/70">[*]</span>로 표기합니다.
        </p>
      </div>
      <table className="w-full min-w-[36rem] text-left text-[10px]">
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-3 py-1.5 font-normal">API</th>
            <th className="px-2 py-1.5 font-normal">유형</th>
            <th className="px-2 py-1.5 font-normal">위치</th>
            <th className="px-2 py-1.5 font-normal">샘플</th>
            <th className="px-2 py-1.5 font-normal">인증</th>
            <th className="px-2 py-1.5 text-center font-normal">Severity</th>
          </tr>
        </thead>
        <tbody>
          {merged.map((row) => (
            <tr
              key={`${row.ruleId}|${row.method}|${row.apiPath}|${row.direction}|${row.fieldPath ?? ""}`}
              className="border-b border-cyber-border/10 last:border-0"
            >
              <td className="px-3 py-1.5 align-top">
                <span className="font-mono text-cyan-300/90">{row.method}</span>
                <span className="mt-0.5 block break-all font-mono text-white/80">{row.apiPath}</span>
              </td>
              <td className="px-2 py-1.5 align-top text-white/85">{row.ruleLabel}</td>
              <td className="px-2 py-1.5 align-top text-cyber-muted">
                <span>{row.directionLabel}</span>
                {row.fieldPath ? (
                  <span className="mt-0.5 block break-all font-mono text-[9px] text-cyan-300/60">
                    {row.fieldPath}
                  </span>
                ) : null}
              </td>
              <td className="px-2 py-1.5 align-top">
                <G52SampleHoverCard row={row} />
              </td>
              <td className="px-2 py-1.5 align-top text-cyan-300/80" title={row.authModes.join(", ")}>
                {row.authSummary}
              </td>
              <td className="px-2 py-1.5 text-center align-top">
                <span
                  className={`font-mono text-[9px] uppercase ${SEVERITY_STYLES[row.severity] ?? SEVERITY_STYLES.info}`}
                >
                  {row.severity}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G52AuthCell({
  cell,
  ruleLabel,
  directionLabel,
  fieldPath,
}: {
  cell: G52DetailCell | undefined;
  ruleLabel: string;
  directionLabel: string;
  fieldPath: string | null;
}) {
  if (!cell?.samples.length) {
    return <span className="text-cyber-muted">—</span>;
  }
  return (
    <div className="space-y-0.5">
      <G52SampleHoverCard
        row={{
          samples: cell.samples,
          fieldPath,
          ruleLabel,
          directionLabel,
        }}
      />
      {cell.statusCode != null && Number.isFinite(cell.statusCode) ? (
        <span className="block font-mono text-[9px] text-cyber-muted">HTTP {cell.statusCode}</span>
      ) : null}
    </div>
  );
}

function G52ApiAuthTable({
  authColumns,
  rows,
}: {
  authColumns: G52AuthColumn[];
  rows: G52DetailRow[];
}) {
  return (
    <div className="overflow-x-auto rounded border border-cyber-border/25 bg-cyber-bg/15">
      <table className="w-full min-w-[32rem] text-left text-[10px]">
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1.5 font-normal">유형</th>
            <th className="px-2 py-1.5 font-normal">위치</th>
            <th className="px-2 py-1.5 font-normal">필드</th>
            {authColumns.map((col) => (
              <th key={col.key} className="px-2 py-1.5 font-normal">
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.rowKey} className="border-b border-cyber-border/10 last:border-0 align-top">
              <td className="px-2 py-1.5 text-white/85">{row.ruleLabel}</td>
              <td className="px-2 py-1.5 text-cyber-muted">{row.directionLabel}</td>
              <td className="px-2 py-1.5">
                {row.fieldPath ? (
                  <span className="break-all font-mono text-[9px] text-cyan-300/70">{row.fieldPath}</span>
                ) : (
                  <span className="text-cyber-muted">—</span>
                )}
              </td>
              {authColumns.map((col) => (
                <td key={col.key} className="px-2 py-1.5">
                  <G52AuthCell
                    cell={row.byAuth[col.key]}
                    ruleLabel={row.ruleLabel}
                    directionLabel={row.directionLabel}
                    fieldPath={row.fieldPath}
                  />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G52ApiDetailGroupRow({ group }: { group: G52ApiDetailGroup }) {
  const [open, setOpen] = useState(false);
  const authSummary = formatG52AuthSummary(group.authColumns.map((c) => c.key));

  return (
    <li className="rounded border border-cyber-border/25 bg-cyber-panel/20">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-2 px-2.5 py-2 text-left"
      >
        <ChevronDown
          className={`mt-0.5 h-3.5 w-3.5 shrink-0 text-cyber-muted transition ${open ? "rotate-180" : ""}`}
        />
        <span className="min-w-0 flex-1">
          <span className="font-mono text-xs text-cyan-300/90">{group.method}</span>
          <span className="mt-0.5 block break-all font-mono text-xs text-white/90">{group.apiPath}</span>
          {group.sampleUrl ? (
            <span className="mt-1 block break-all font-mono text-[9px] text-cyber-muted">{group.sampleUrl}</span>
          ) : null}
        </span>
        <span className="shrink-0 text-right text-[10px] text-cyber-muted">
          <span className="block">{group.rows.length}유형</span>
          <span className="block text-cyan-300/80">{authSummary}</span>
        </span>
      </button>
      {open ? (
        <div className="border-t border-cyber-border/20 px-2.5 pb-2.5 pt-2">
          <G52ApiAuthTable authColumns={group.authColumns} rows={group.rows} />
        </div>
      ) : null}
    </li>
  );
}

function G52DetailSection({
  findings,
  stats,
  hasRawInStats,
}: {
  findings: G52Finding[];
  stats?: Record<string, unknown> | null;
  hasRawInStats: boolean;
}) {
  const rawHits = parseG52RawFindings(findings, stats);
  const groups = buildG52ApiDetailGroups(rawHits);

  if (groups.length === 0) {
    return null;
  }

  return (
    <CollapsibleReportSection title="상세 (계정별)" defaultOpen={false}>
      <p className="mb-2 text-[10px] text-cyber-muted">
        {hasRawInStats
          ? "merge 전 raw finding 기준 · API를 펼치면 계정(auth)별로 노출된 샘플 값을 확인할 수 있습니다."
          : "이 리포트는 구버전 형식입니다. 계정별 샘플 값을 보려면 5-2를 다시 실행하세요."}
      </p>
      <ul className="space-y-1.5">
        {groups.map((group) => (
          <G52ApiDetailGroupRow key={group.groupKey} group={group} />
        ))}
      </ul>
    </CollapsibleReportSection>
  );
}

export function G52FindingsPanel({
  findings,
  stats,
}: {
  findings: G52Finding[];
  stats?: Record<string, unknown> | null;
}) {
  const { merged, other } = mergeG52Findings(findings);
  const hasRawInStats = Array.isArray(stats?.raw_findings) && (stats.raw_findings as unknown[]).length > 0;

  if (findings.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  return (
    <>
      <G52SummaryTable merged={merged} />
      <G52DetailSection findings={findings} stats={stats} hasRawInStats={hasRawInStats} />
      {other.length > 0 ? (
        <CollapsibleReportSection title="기타">
          <ul className="space-y-2">
            {other.map((f, i) => (
              <li
                key={`other-${i}`}
                className="rounded border border-cyber-border/30 bg-cyber-panel/30 px-3 py-2"
              >
                <div className="flex items-start gap-2">
                  <span
                    className={`shrink-0 font-mono text-[10px] uppercase ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info}`}
                  >
                    {f.severity}
                  </span>
                  <span className="text-xs text-white/90">{f.message}</span>
                </div>
              </li>
            ))}
          </ul>
        </CollapsibleReportSection>
      ) : null}
    </>
  );
}
