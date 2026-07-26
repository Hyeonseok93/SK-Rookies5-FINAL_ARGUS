import { Fragment, useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  groupG34ByKind,
  parseG34Findings,
  type G34Finding,
  type G34Row,
  type G34SampleRow,
} from "../../lib/g34ReportView";

const SEVERITY_STYLES: Record<string, string> = {
  high: "text-rose-300",
  medium: "text-amber-300",
  low: "text-sky-300",
  info: "text-cyber-muted",
};

function G34EllipsisCell({
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

function G34SummaryTable({ rows }: { rows: G34Row[] }) {
  if (rows.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  const groups = groupG34ByKind(rows);

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">관리자·사용자 분리</span>
        <p className="mt-0.5 text-[10px] text-cyber-muted">
          user·admin이 같은 서버·URL·경로 패턴을 쓰는지 inventory 기준으로 점검
        </p>
      </div>
      <table className="w-full min-w-[40rem] table-fixed text-left text-[10px]">
        <colgroup>
          <col style={{ width: "10%" }} />
          <col style={{ width: "34%" }} />
          <col style={{ width: "16%" }} />
          <col style={{ width: "28%" }} />
          <col style={{ width: "12%" }} />
        </colgroup>
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1.5 font-normal">구분</th>
            <th className="px-2 py-1.5 font-normal">문제</th>
            <th className="px-2 py-1.5 font-normal">규모</th>
            <th className="px-2 py-1.5 font-normal">예시</th>
            <th className="px-2 py-1.5 text-center font-normal">Sev</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((group) => (
            <Fragment key={group.kind}>
              <tr className="border-b border-cyber-border/15 bg-cyber-panel/30">
                <td colSpan={5} className="px-2 py-1.5 text-xs font-semibold text-white/95">
                  {group.label}
                </td>
              </tr>
              {group.rows.map((row) => (
                <tr key={row.rowKey} className="border-b border-cyber-border/10 last:border-0">
                  <td className="px-2 py-1.5 align-middle text-cyan-300/85">{row.categoryLabel}</td>
                  <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle text-white/90">
                    <G34EllipsisCell value={row.problemSummary} />
                  </td>
                  <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                    <G34EllipsisCell value={row.scaleSummary} className="text-white/80" mono />
                  </td>
                  <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                    <G34EllipsisCell
                      value={row.sampleHint}
                      className="text-cyan-300/75"
                      mono
                    />
                  </td>
                  <td className="px-2 py-1.5 text-center align-middle">
                    <span
                      className={`font-mono text-[9px] uppercase ${SEVERITY_STYLES[row.severity] ?? SEVERITY_STYLES.info}`}
                    >
                      {row.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G34SampleTable({ samples }: { samples: G34SampleRow[] }) {
  if (samples.length === 0) return null;

  return (
    <div className="overflow-x-auto rounded border border-cyber-border/25 bg-cyber-bg/15">
      <table className="w-full min-w-[28rem] table-fixed text-left text-[10px]">
        <colgroup>
          <col style={{ width: "28%" }} />
          <col style={{ width: "72%" }} />
        </colgroup>
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1 font-normal">구분</th>
            <th className="px-2 py-1 font-normal">값</th>
          </tr>
        </thead>
        <tbody>
          {samples.map((s, i) => (
            <tr key={`${s.label}-${i}`} className="border-b border-cyber-border/10 last:border-0 align-top">
              <td className="px-2 py-1 text-cyber-muted">{s.label}</td>
              <td className="min-w-0 px-2 py-1 break-all font-mono text-cyan-300/80">{s.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G34DetailRow({ row }: { row: G34Row }) {
  const [open, setOpen] = useState(false);

  return (
    <li className="rounded border border-cyber-border/25 bg-cyber-panel/20 px-2.5 py-1.5">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-2 text-left"
      >
        <ChevronDown
          className={`mt-0.5 h-3.5 w-3.5 shrink-0 text-cyber-muted transition ${open ? "rotate-180" : ""}`}
        />
        <span className="shrink-0 text-[10px] text-cyan-300/85">{row.categoryLabel}</span>
        <span className="min-w-0 flex-1 truncate text-xs text-white/90">{row.problemSummary}</span>
        <span className="shrink-0 font-mono text-[10px] text-cyan-300/80">{row.scaleSummary}</span>
      </button>
      {open ? (
        <div className="mt-1.5 space-y-2 border-t border-cyber-border/20 pt-1.5 text-[10px]">
          <p className="break-words text-white/75">{row.message}</p>
          {row.trigger ? (
            <p className="font-mono text-[9px] text-cyber-muted">trigger · {row.trigger}</p>
          ) : null}
          <G34SampleTable samples={row.samples} />
        </div>
      ) : null}
    </li>
  );
}

export function G34FindingsPanel({
  findings,
}: {
  findings: G34Finding[];
  stats?: Record<string, unknown> | null;
  status?: string;
}) {
  const { rows, other } = parseG34Findings(findings);

  return (
    <>
      <G34SummaryTable rows={rows} />
      {rows.length > 0 ? (
        <CollapsibleReportSection title="상세" defaultOpen={false}>
          <p className="mb-2 text-[10px] text-cyber-muted">
            origin·로그인 URL·API/UI 경로 전체 목록. 요약 &apos;예시&apos;는 일부만 표시합니다.
          </p>
          <ul className="space-y-1.5">
            {rows.map((row) => (
              <G34DetailRow key={row.rowKey} row={row} />
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
