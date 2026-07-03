import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  buildG32PassNote,
  parseG32Findings,
  type G32Finding,
  type G32Row,
} from "../../lib/g32ReportView";

const SEVERITY_STYLES: Record<string, string> = {
  high: "text-rose-300",
  medium: "text-amber-300",
  low: "text-sky-300",
  info: "text-cyber-muted",
};

const RESULT_STYLES: Record<G32Row["kind"], string> = {
  issue: "text-amber-300",
  error: "text-rose-300/90",
  ok: "text-emerald-300",
};

function G32EllipsisCell({
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

function G32PassNoteLine({ note }: { note: string | null }) {
  if (!note) return null;
  return (
    <p className="border-t border-cyber-border/20 px-3 py-2 font-mono text-[10px] text-emerald-300/80">
      {note}
    </p>
  );
}

function G32IssueSummaryTable({ issueRows, passNote }: { issueRows: G32Row[]; passNote: string | null }) {
  if (issueRows.length === 0) {
    return (
      <div className="mb-3 rounded-lg border border-emerald-400/25 bg-emerald-500/5 px-3 py-2.5">
        <p className="text-xs font-medium text-emerald-200/95">검토 필요 항목 없음</p>
        {passNote ? (
          <p className="mt-1 font-mono text-[10px] text-emerald-300/80">{passNote}</p>
        ) : null}
      </div>
    );
  }

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">인증 실패 제한 — 검토 필요</span>
        <p className="mt-0.5 text-[10px] text-cyber-muted">{issueRows.length}건</p>
      </div>
      <table className="w-full min-w-[36rem] table-fixed text-left text-[10px]">
        <colgroup>
          <col style={{ width: "28%" }} />
          <col style={{ width: "18%" }} />
          <col style={{ width: "18%" }} />
          <col style={{ width: "22%" }} />
          <col style={{ width: "14%" }} />
        </colgroup>
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1.5 font-normal">Login</th>
            <th className="px-2 py-1.5 font-normal">계정</th>
            <th className="px-2 py-1.5 font-normal">결과</th>
            <th className="px-2 py-1.5 font-normal">시도</th>
            <th className="px-2 py-1.5 text-center font-normal">Sev</th>
          </tr>
        </thead>
        <tbody>
          {issueRows.map((row) => (
            <tr key={row.rowKey} className="border-b border-cyber-border/10 last:border-0">
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                <G32EllipsisCell value={row.loginLabel} className="text-cyan-300/90" mono />
              </td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                <G32EllipsisCell value={row.accountEmail} className="text-cyan-300/85" mono />
              </td>
              <td className={`min-w-0 overflow-hidden px-2 py-1.5 align-middle ${RESULT_STYLES[row.kind]}`}>
                <G32EllipsisCell value={row.resultLabel} />
              </td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                <G32EllipsisCell value={row.scaleSummary} className="text-white/80" mono />
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
        </tbody>
      </table>
      <G32PassNoteLine note={passNote} />
    </div>
  );
}

function G32AttemptTable({ row }: { row: G32Row }) {
  if (row.attempts.length === 0) return null;
  return (
    <div className="overflow-x-auto rounded border border-cyber-border/25 bg-cyber-bg/15">
      <table className="w-full min-w-[28rem] table-fixed text-left text-[10px]">
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1 font-normal">회차</th>
            <th className="px-2 py-1 text-center font-normal">HTTP</th>
            <th className="px-2 py-1 font-normal">코드</th>
            <th className="px-2 py-1 font-normal">메시지</th>
          </tr>
        </thead>
        <tbody>
          {row.attempts.map((a) => (
            <tr key={a.attempt} className="border-b border-cyber-border/10 last:border-0 align-top">
              <td className="px-2 py-1 font-mono text-white/80">{a.attempt}</td>
              <td className="px-2 py-1 text-center font-mono text-cyan-300/70">{a.httpStatus ?? "—"}</td>
              <td className="min-w-0 px-2 py-1 font-mono text-white/75">{a.errorCode ?? "—"}</td>
              <td className="min-w-0 px-2 py-1 break-words text-white/70">
                {a.error ?? a.primaryMessage ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G32DetailRow({ row }: { row: G32Row }) {
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
        <span className={`shrink-0 text-[10px] ${RESULT_STYLES[row.kind]}`}>{row.resultLabel}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-cyan-300/90">{row.loginLabel}</span>
        <span className="shrink-0 font-mono text-[10px] text-cyber-muted">{row.accountEmail}</span>
      </button>
      {open ? (
        <div className="mt-1.5 space-y-2 border-t border-cyber-border/20 pt-1.5 text-[10px]">
          <p className="break-all font-mono text-cyan-300/75">{row.loginUrl}</p>
          {row.limitTypeLabel ? (
            <p>
              <span className="text-cyber-muted">유형 · </span>
              <span className="text-white/80">{row.limitTypeLabel}</span>
            </p>
          ) : null}
          {row.reason ? (
            <p>
              <span className="text-cyber-muted">사유 · </span>
              <span className="break-words text-white/75">{row.reason}</span>
            </p>
          ) : null}
          <G32AttemptTable row={row} />
        </div>
      ) : null}
    </li>
  );
}

function G32OkSummaryTable({ rows }: { rows: G32Row[] }) {
  if (rows.length === 0) return null;
  return (
    <div className="mb-3 overflow-x-auto rounded border border-cyber-border/30 bg-cyber-bg/15">
      <p className="border-b border-cyber-border/20 px-2 py-1.5 text-[10px] font-medium text-white/90">
        제한 확인된 login ({rows.length}건)
      </p>
      <table className="w-full min-w-[32rem] table-fixed text-left text-[10px]">
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1 font-normal">Login</th>
            <th className="px-2 py-1 font-normal">계정</th>
            <th className="px-2 py-1 font-normal">유형</th>
            <th className="px-2 py-1 font-normal">감지</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.rowKey} className="border-b border-cyber-border/10 last:border-0">
              <td className="px-2 py-1 font-mono text-cyan-300/90">{row.loginLabel}</td>
              <td className="px-2 py-1 font-mono text-cyan-300/85">{row.accountEmail}</td>
              <td className="px-2 py-1 text-emerald-300/90">{row.limitTypeLabel ?? "—"}</td>
              <td className="px-2 py-1 font-mono text-white/80">{row.scaleSummary}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function G32FindingsPanel({
  findings,
}: {
  findings: G32Finding[];
  stats?: Record<string, unknown> | null;
}) {
  const { rows, other } = parseG32Findings(findings);
  const issueRows = rows.filter((r) => r.kind === "issue" || r.kind === "error");
  const okRows = rows.filter((r) => r.kind === "ok");
  const passNote = buildG32PassNote(rows);

  return (
    <>
      <G32IssueSummaryTable issueRows={issueRows} passNote={passNote} />
      {rows.length > 0 ? (
        <CollapsibleReportSection title="상세" defaultOpen={false}>
          {okRows.length > 0 ? <G32OkSummaryTable rows={okRows} /> : null}
          <p className="mb-2 text-[10px] text-cyber-muted">login별 wrong-password 시도 응답</p>
          <ul className="space-y-1.5">
            {rows.map((row) => (
              <G32DetailRow key={row.rowKey} row={row} />
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
