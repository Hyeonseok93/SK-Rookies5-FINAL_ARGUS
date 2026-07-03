import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  buildG35IssueSummary,
  buildG35Overview,
  buildG35PassNotes,
  extractG35InventorySummaryRows,
  extractG35PageRows,
  extractG35RobotsRows,
  filterG35DisplayFindings,
  pathFromProbeUrl,
  type G35Finding,
  type G35IssueSummaryRow,
  type G35PageRow,
  type G35PassNote,
} from "../../lib/g35ReportView";

const STATUS_STYLES: Record<string, string> = {
  present: "text-emerald-300",
  missing: "text-amber-300",
  unreachable: "text-rose-300/90",
};

function G35EllipsisCell({
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

function G35PassNotesLine({ notes, footer = false }: { notes: G35PassNote; footer?: boolean }) {
  const parts = [...notes.robotsOk, notes.pagesOk].filter(Boolean);
  if (parts.length === 0) return null;
  return (
    <p
      className={
        footer
          ? "border-t border-cyber-border/20 px-3 py-2 font-mono text-[10px] text-emerald-300/80"
          : "mt-1 font-mono text-[10px] text-emerald-300/80"
      }
    >
      {parts.join(" · ")}
    </p>
  );
}

function G35IssueSummaryTable({
  rows,
  passNotes,
}: {
  rows: G35IssueSummaryRow[];
  passNotes: G35PassNote;
}) {
  if (rows.length === 0) {
    return (
      <div className="mb-3 rounded-lg border border-emerald-400/25 bg-emerald-500/5 px-3 py-2.5">
        <p className="text-xs font-medium text-emerald-200/95">검토 필요 항목 없음</p>
        <G35PassNotesLine notes={passNotes} />
      </div>
    );
  }

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">검색엔진 노출 — 검토 필요</span>
        <p className="mt-0.5 text-[10px] text-cyber-muted">{rows.length}건</p>
      </div>
      <table className="w-full min-w-[32rem] table-fixed text-left text-[10px]">
        <colgroup>
          <col style={{ width: "28%" }} />
          <col style={{ width: "28%" }} />
          <col style={{ width: "16%" }} />
          <col style={{ width: "28%" }} />
        </colgroup>
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1.5 font-normal">점검</th>
            <th className="px-2 py-1.5 font-normal">문제</th>
            <th className="px-2 py-1.5 font-normal">규모</th>
            <th className="px-2 py-1.5 font-normal">예시 경로</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.rowKey} className="border-b border-cyber-border/10 last:border-0">
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle text-white/90">
                <G35EllipsisCell value={row.checkLabel} mono />
              </td>
              <td
                className={`min-w-0 overflow-hidden px-2 py-1.5 align-middle ${row.tone === "bad" ? "text-rose-300/90" : "text-amber-300"}`}
              >
                <G35EllipsisCell value={row.issueLabel} />
              </td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                <G35EllipsisCell value={row.scope} className="text-white/80" mono />
              </td>
              <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                <G35EllipsisCell value={row.pathHint} className="text-cyan-300/75" mono />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <G35PassNotesLine notes={passNotes} footer />
    </div>
  );
}

function G35RobotsDetailTable({ rows }: { rows: ReturnType<typeof extractG35RobotsRows> }) {
  if (rows.length === 0) return null;
  return (
    <div className="mb-3 overflow-x-auto rounded border border-cyber-border/30 bg-cyber-bg/15">
      <p className="border-b border-cyber-border/20 px-2 py-1.5 text-[10px] font-medium text-white/90">
        robots.txt 전체
      </p>
      <table className="w-full min-w-[36rem] table-fixed text-left text-[10px]">
        <colgroup>
          <col style={{ width: "22%" }} />
          <col style={{ width: "14%" }} />
          <col style={{ width: "12%" }} />
          <col style={{ width: "12%" }} />
          <col style={{ width: "14%" }} />
          <col style={{ width: "10%" }} />
        </colgroup>
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1 font-normal">Base</th>
            <th className="px-2 py-1 font-normal">상태</th>
            <th className="px-2 py-1 text-center font-normal">Disallow</th>
            <th className="px-2 py-1 text-center font-normal">Allow</th>
            <th className="px-2 py-1 text-center font-normal">Sitemap</th>
            <th className="px-2 py-1 text-center font-normal">HTTP</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.rowKey} className="border-b border-cyber-border/10 last:border-0">
              <td className="px-2 py-1 font-mono text-cyan-300/90">{row.baseLabel}</td>
              <td className={`px-2 py-1 ${STATUS_STYLES[row.status] ?? ""}`}>{row.statusLabel}</td>
              <td className="px-2 py-1 text-center font-mono text-white/80">{row.disallowCount}</td>
              <td className="px-2 py-1 text-center font-mono text-white/80">{row.allowCount}</td>
              <td className="px-2 py-1 text-center font-mono text-white/80">{row.sitemapCount}</td>
              <td className="px-2 py-1 text-center font-mono text-cyan-300/70">{row.httpStatus ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G35ScopeDetailTable({ rows }: { rows: ReturnType<typeof extractG35InventorySummaryRows> }) {
  if (rows.length === 0) return null;
  return (
    <div className="mb-3 overflow-x-auto rounded border border-cyber-border/30 bg-cyber-bg/15">
      <p className="border-b border-cyber-border/20 px-2 py-1.5 text-[10px] font-medium text-white/90">
        계정별 페이지 검사
      </p>
      <table className="w-full min-w-[32rem] table-fixed text-left text-[10px]">
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1 font-normal">인증</th>
            <th className="px-2 py-1 text-center font-normal">검사</th>
            <th className="px-2 py-1 text-center font-normal">noindex</th>
            <th className="px-2 py-1 text-center font-normal">nofollow</th>
            <th className="px-2 py-1 text-center font-normal">지침 없음</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.rowKey} className="border-b border-cyber-border/10 last:border-0">
              <td className="px-2 py-1 font-mono text-cyan-300/85">{row.authLabel}</td>
              <td className="px-2 py-1 text-center font-mono">{row.pagesProbed}</td>
              <td className="px-2 py-1 text-center font-mono">{row.noindex}</td>
              <td className="px-2 py-1 text-center font-mono">{row.nofollow}</td>
              <td
                className={`px-2 py-1 text-center font-mono ${row.noDirective > 0 ? "text-amber-300" : ""}`}
              >
                {row.noDirective}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G35PathList({ title, paths, urls }: { title: string; paths: string[]; urls?: string[] }) {
  const items =
    urls && urls.length > 0
      ? urls.map((url) => ({ path: pathFromProbeUrl(url), url }))
      : paths.map((path) => ({ path, url: null as string | null }));

  if (items.length === 0) return null;

  return (
    <div className="mb-3 rounded border border-cyber-border/30 bg-cyber-bg/15">
      <p className="border-b border-cyber-border/20 px-2 py-1.5 text-[10px] font-medium text-white/90">
        {title} ({items.length}건)
      </p>
      <ul className="max-h-56 space-y-0.5 overflow-y-auto px-2 py-1.5">
        {items.map((item) => (
          <li key={item.path + (item.url ?? "")} className="flex gap-2 font-mono text-[10px]">
            <span className="shrink-0 text-cyan-300/90">{item.path}</span>
            {item.url ? (
              <span className="min-w-0 truncate text-cyber-muted" title={item.url}>
                {item.url}
              </span>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

function G35PageDetailRow({ row }: { row: G35PageRow }) {
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
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-cyan-300/90">{row.path}</span>
        <span className="shrink-0 font-mono text-[10px] text-emerald-300/90">{row.directiveLabel}</span>
      </button>
      {open ? (
        <div className="mt-1.5 space-y-1 border-t border-cyber-border/20 pt-1.5 text-[10px]">
          <p className="break-all font-mono text-cyan-300/80">{row.url}</p>
          {row.metaRobots ? (
            <p>
              <span className="text-cyber-muted">meta · </span>
              <span className="font-mono text-white/80">{row.metaRobots}</span>
            </p>
          ) : null}
          {row.xRobotsTag ? (
            <p>
              <span className="text-cyber-muted">X-Robots-Tag · </span>
              <span className="font-mono text-white/80">{row.xRobotsTag}</span>
            </p>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

export function G35FindingsPanel({
  findings,
  stats,
}: {
  findings: G35Finding[];
  stats?: Record<string, unknown> | null;
}) {
  const overview = buildG35Overview(stats);
  const robotsRows = extractG35RobotsRows(findings);
  const scopeRows = extractG35InventorySummaryRows(findings);
  const pageRows = extractG35PageRows(findings);
  const issueRows = buildG35IssueSummary(robotsRows, scopeRows);
  const passNotes = buildG35PassNotes(robotsRows, scopeRows);
  const { other } = filterG35DisplayFindings(findings);

  const anonScope = scopeRows.find((r) => r.authLabel === "anonymous");
  const hasDetail =
    robotsRows.length > 0 ||
    scopeRows.length > 0 ||
    pageRows.length > 0 ||
    (anonScope?.indexableSample.length ?? 0) > 0;

  return (
    <>
      <G35IssueSummaryTable rows={issueRows} passNotes={passNotes} />
      {overview.inventoryFallback ? (
        <p className="mb-3 text-[10px] text-amber-300/80">api-tree 없음 — base `/`만 검사</p>
      ) : null}
      {hasDetail ? (
        <CollapsibleReportSection title="상세" defaultOpen={false}>
          <G35RobotsDetailTable rows={robotsRows} />
          <G35ScopeDetailTable rows={scopeRows} />
          {anonScope && anonScope.indexableSample.length > 0 ? (
            <G35PathList
              title="robots 지침 없는 페이지 (비로그인)"
              paths={[]}
              urls={anonScope.indexableSample}
            />
          ) : null}
          {pageRows.length > 0 ? (
            <>
              <p className="mb-2 text-[10px] text-cyber-muted">noindex / nofollow 페이지</p>
              <ul className="space-y-1.5">
                {pageRows.map((row) => (
                  <G35PageDetailRow key={row.rowKey} row={row} />
                ))}
              </ul>
            </>
          ) : null}
        </CollapsibleReportSection>
      ) : null}
      {other.length > 0 ? (
        <CollapsibleReportSection title="기타" defaultOpen={false}>
          <ul className="space-y-2">
            {other.map((f, i) => (
              <li
                key={`other-${i}`}
                className="rounded border border-cyber-border/30 bg-cyber-panel/30 px-3 py-2"
              >
                <span className="text-xs text-white/90">{f.message}</span>
              </li>
            ))}
          </ul>
        </CollapsibleReportSection>
      ) : null}
    </>
  );
}
