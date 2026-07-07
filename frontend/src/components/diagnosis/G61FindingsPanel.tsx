import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  G61_SK_COLUMNS,
  SK_CLASS_LABELS,
  buildG61Matrix,
  formatG61Engine,
  formatG61OriginLabel,
  g61Headline,
  pathFromUrl,
  severityLabelKo,
  sortG61Groups,
  triggerFamilyLabel,
  type G61ReportSummary,
  type G61SummaryGroup,
} from "../../lib/g61ReportView";

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

const SEVERITY_DOT: Record<string, string> = {
  high: "bg-rose-400",
  medium: "bg-amber-400",
  low: "bg-sky-400",
};

function MatrixCell({ cell }: { cell?: { severity: string; count: number } }) {
  if (!cell) return <span className="text-cyber-muted/40">—</span>;
  const dot = SEVERITY_DOT[cell.severity] ?? SEVERITY_DOT.low;
  return (
    <span className="inline-flex items-center gap-1" title={`${severityLabelKo(cell.severity)} · ${cell.count}건`}>
      <span className={`inline-block h-1.5 w-1.5 rounded-full ${dot}`} />
      <span className="font-mono text-[10px] text-white/80">{cell.count.toLocaleString()}</span>
    </span>
  );
}

function G61Overview({ summary, status }: { summary: G61ReportSummary; status: string }) {
  const stats = summary.stats ?? {};
  const k = summary.by_sk ?? {};
  return (
    <div className="mb-3 rounded-lg border border-cyber-border/50 bg-cyber-bg/20 px-3 py-2.5">
      <p className="text-xs font-semibold text-white">{g61Headline(summary, status)}</p>
      <p className="mt-1 text-[10px] text-cyber-muted">
        총 {summary.total_issues.toLocaleString()}건 · DBMS {(k.dbms ?? 0).toLocaleString()} · 익셉션{" "}
        {(k.exception ?? 0).toLocaleString()} · HTTP/서버 {(k.http ?? 0).toLocaleString()}
        {typeof stats.endpoints_probed === "number" ? (
          <> · API {String(stats.endpoints_probed)}개 · 요청 {String(stats.requests_sent ?? "—")}</>
        ) : null}
      </p>
    </div>
  );
}

function G61SkMatrix({ summary }: { summary: G61ReportSummary }) {
  const rows = buildG61Matrix(summary);
  if (rows.length === 0) return null;

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">SK Shielders 6-1 — Origin별 분류</span>
      </div>
      <table className="w-full min-w-[24rem] text-left text-[10px]">
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-3 py-1.5 font-normal">Origin</th>
            {G61_SK_COLUMNS.map((col) => (
              <th key={col.id} className="px-2 py-1.5 text-center font-normal">
                {col.label}
              </th>
            ))}
            <th className="px-3 py-1.5 text-right font-normal">합계</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.origin} className="border-b border-cyber-border/10 last:border-0">
              <td className="px-3 py-1.5 font-mono text-cyan-300/90">{row.displayLabel}</td>
              {G61_SK_COLUMNS.map((col) => (
                <td key={col.id} className="px-2 py-1.5 text-center">
                  <MatrixCell cell={row.cells[col.id]} />
                </td>
              ))}
              <td className="px-3 py-1.5 text-right font-mono text-cyber-muted">{row.total.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G61SummaryTable({ groups }: { groups: G61SummaryGroup[] }) {
  if (groups.length === 0) {
    return (
      <div className="mb-3 rounded-lg border border-emerald-400/25 bg-emerald-500/5 px-3 py-2.5">
        <p className="text-xs font-medium text-emerald-200/95">조치 필요 항목 없음</p>
      </div>
    );
  }

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">이슈 요약</span>
        <p className="mt-0.5 text-[10px] text-cyber-muted">{groups.length}개 그룹</p>
      </div>
      <table className="w-full min-w-[44rem] table-fixed text-left text-[10px]">
        <colgroup>
          <col style={{ width: "12%" }} />
          <col style={{ width: "10%" }} />
          <col style={{ width: "10%" }} />
          <col style={{ width: "22%" }} />
          <col style={{ width: "10%" }} />
          <col style={{ width: "8%" }} />
          <col style={{ width: "8%" }} />
          <col style={{ width: "6%" }} />
        </colgroup>
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1.5 font-normal">SK 6-1</th>
            <th className="px-2 py-1.5 font-normal">세부</th>
            <th className="px-2 py-1.5 font-normal">Origin</th>
            <th className="px-2 py-1.5 font-normal">문제</th>
            <th className="px-2 py-1.5 font-normal">유발</th>
            <th className="px-2 py-1.5 text-right font-normal">건수</th>
            <th className="px-2 py-1.5 font-normal">Engine</th>
            <th className="px-2 py-1.5 text-center font-normal">Sev</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((g) => (
            <tr key={g.group_key} className="border-b border-cyber-border/10 last:border-0">
              <td className="px-2 py-1.5 align-middle text-cyan-300/90">
                {SK_CLASS_LABELS[g.sk_class] ?? g.sk_label}
              </td>
              <td className="px-2 py-1.5 align-middle text-white/75">{g.category_label}</td>
              <td className="truncate px-2 py-1.5 align-middle font-mono text-cyan-300/90">
                {formatG61OriginLabel(g.origin)}
              </td>
              <td className="truncate px-2 py-1.5 align-middle text-white/90" title={g.rule_label}>
                {g.rule_label}
              </td>
              <td className="truncate px-2 py-1.5 align-middle text-white/70">
                {g.trigger_families[0] ? triggerFamilyLabel(g.trigger_families[0].family) : "—"}
              </td>
              <td className="px-2 py-1.5 text-right align-middle font-mono text-white/85">
                {g.count.toLocaleString()}
              </td>
              <td className="px-2 py-1.5 align-middle text-cyber-muted">
                {formatG61Engine(g.engine, g.engines)}
              </td>
              <td className="px-2 py-1.5 text-center align-middle">
                <span className={`font-mono text-[9px] uppercase ${SEVERITY_STYLES[g.severity] ?? ""}`}>
                  {severityLabelKo(g.severity)}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G61DetailCard({ group }: { group: G61SummaryGroup }) {
  const [open, setOpen] = useState(false);
  const badge = SEVERITY_BADGE[group.severity] ?? SEVERITY_BADGE.low;

  return (
    <li className="rounded-lg border border-cyber-border/30 bg-cyber-panel/20 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${badge}`}>
          {severityLabelKo(group.severity)}
        </span>
        <span className="text-[10px] text-cyan-300/85">{SK_CLASS_LABELS[group.sk_class] ?? group.sk_label}</span>
        <span className="text-[10px] text-white/70">{group.category_label}</span>
        <span className="font-mono text-[10px] text-cyan-300/90">{formatG61OriginLabel(group.origin)}</span>
        <span className="text-[9px] text-cyber-muted">{formatG61Engine(group.engine, group.engines)}</span>
        <span className="font-mono text-[10px] text-white/80">{group.count.toLocaleString()}건</span>
      </div>
      <p className="mt-1.5 text-xs font-medium text-white/95">{group.rule_label}</p>
      {group.explanation ? (
        <p className="mt-0.5 text-[10px] leading-relaxed text-white/70">{group.explanation}</p>
      ) : null}

      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="mt-2 flex items-center gap-1 text-[10px] text-cyber-muted transition hover:text-white/90"
      >
        <ChevronDown className={`h-3 w-3 transition ${open ? "rotate-180" : ""}`} />
        {open ? "상세 접기" : "상세 (샘플 URL · snippet · 조치)"}
      </button>

      {open ? (
        <div className="mt-2 space-y-2 border-t border-cyber-border/20 pt-2 text-[10px]">
          {group.trigger_families.length > 0 ? (
            <div className="rounded border border-cyber-border/20 bg-cyber-bg/40 px-2 py-1.5">
              <p className="mb-1 text-cyber-muted">유발 트리거</p>
              <p className="text-white/80">
                {group.trigger_families
                  .map((t) => `${triggerFamilyLabel(t.family)} ${t.count.toLocaleString()}`)
                  .join(" · ")}
              </p>
            </div>
          ) : null}
          {group.top_status_codes.length > 0 ? (
            <p className="text-cyber-muted">
              HTTP status · <span className="font-mono text-white/80">{group.top_status_codes.join(", ")}</span>
            </p>
          ) : null}
          {group.sample_urls.length > 0 ? (
            <div className="rounded border border-cyber-border/20 bg-cyber-bg/40 px-2 py-1.5">
              <p className="mb-1 text-cyber-muted">샘플 URL ({group.sample_urls.length})</p>
              <ul className="space-y-0.5 font-mono text-cyan-300/80">
                {group.sample_urls.map((u) => (
                  <li key={u} className="break-all">
                    {group.sample_methods[0] ? `${group.sample_methods[0].toUpperCase()} ` : ""}
                    {pathFromUrl(u)}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {group.sample_snippets.length > 0 ? (
            <div className="rounded border border-cyber-border/20 bg-cyber-bg/40 px-2 py-1.5">
              <p className="mb-1 text-cyber-muted">응답 snippet</p>
              {group.sample_snippets.map((s, i) => (
                <p key={i} className="break-all font-mono text-white/75">
                  {s}
                </p>
              ))}
            </div>
          ) : null}
          {group.remediation ? (
            <p className="rounded border border-cyber-border/20 bg-cyber-bg/40 px-2 py-1.5 text-white/80">
              <span className="text-cyber-muted">조치 · </span>
              {group.remediation}
            </p>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

export function G61FindingsPanel({
  summary,
  status,
}: {
  summary: G61ReportSummary;
  status: string;
}) {
  const groups = sortG61Groups(summary.groups);

  return (
    <>
      <G61Overview summary={summary} status={status} />
      <G61SkMatrix summary={summary} />
      <G61SummaryTable groups={groups} />
      {groups.length > 0 ? (
        <CollapsibleReportSection title="상세" defaultOpen={false}>
          <ul className="space-y-2">
            {groups.map((g) => (
              <G61DetailCard key={g.group_key} group={g} />
            ))}
          </ul>
        </CollapsibleReportSection>
      ) : null}
    </>
  );
}
