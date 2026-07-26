import { Fragment, useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  groupG42ByCategory,
  mergeG42Findings,
  type G42AccountHit,
  type G42Finding,
  type G42MergedFinding,
} from "../../lib/g42ReportView";

const SEVERITY_STYLES: Record<string, string> = {
  high: "text-rose-300",
  medium: "text-amber-300",
  low: "text-sky-300",
  info: "text-cyber-muted",
};

/** Shared column widths — one table so all category blocks align. */
const G42_SUMMARY_COLGROUP = (
  <colgroup>
    <col style={{ width: "26%" }} />
    <col style={{ width: "10%" }} />
    <col style={{ width: "40%" }} />
    <col style={{ width: "14%" }} />
    <col style={{ width: "10%" }} />
  </colgroup>
);

/** Ellipsis only when the cell actually overflows (no arbitrary char cap). */
function G42EllipsisCell({
  value,
  title,
  className = "",
  mono = false,
}: {
  value: string | null | undefined;
  title?: string;
  className?: string;
  mono?: boolean;
}) {
  const full = (value ?? "").trim() || "—";
  const tip = title ?? (full !== "—" ? full : undefined);
  return (
    <span
      className={`block min-w-0 truncate ${mono ? "font-mono" : ""} ${className}`}
      title={tip}
    >
      {full}
    </span>
  );
}

function G42SummaryTable({ merged }: { merged: G42MergedFinding[] }) {
  if (merged.length === 0) return null;

  const groups = groupG42ByCategory(merged);

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <table className="w-full min-w-[40rem] table-fixed text-left text-[10px]">
        {G42_SUMMARY_COLGROUP}
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1.5 font-normal">검사 항목</th>
            <th className="pl-1 pr-2 py-1.5 font-normal">영향</th>
            <th className="px-2 py-1.5 font-normal">사유</th>
            <th className="px-2 py-1.5 font-normal">Login</th>
            <th className="px-2 py-1.5 text-center font-normal">Severity</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((group) => (
            <Fragment key={group.category}>
              <tr className="border-b border-cyber-border/15 bg-cyber-panel/30">
                <td colSpan={5} className="px-2 py-1.5 text-xs font-semibold text-white/95">
                  {group.categoryLabel}
                </td>
              </tr>
              {group.findings.map((row) => {
                const reasonDiffers =
                  row.accounts.length > 1 &&
                  row.accounts.some((a) => a.reason && a.reason !== row.reason);
                return (
                  <tr
                    key={row.ruleId}
                    className="border-b border-cyber-border/10 last:border-0"
                  >
                    <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                      <G42EllipsisCell value={row.ruleLabel} className="text-white/90" />
                    </td>
                    <td className="min-w-0 overflow-hidden pl-1 pr-2 py-1.5 align-middle">
                      <G42EllipsisCell
                        value={row.emailSummary}
                        title={row.accounts
                          .map((a) => a.email)
                          .filter(Boolean)
                          .join(", ")}
                        className="text-cyan-300/85"
                        mono
                      />
                    </td>
                    <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                      <G42EllipsisCell value={row.reason} className="text-white/75" />
                      {reasonDiffers ? (
                        <span className="mt-0.5 block text-[9px] text-cyber-muted">계정별 상이</span>
                      ) : null}
                    </td>
                    <td className="min-w-0 overflow-hidden px-2 py-1.5 align-middle">
                      <G42EllipsisCell
                        value={row.loginPathSummary}
                        className="text-cyan-300/70"
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
                );
              })}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function extraDetailRows(hit: G42AccountHit): { label: string; value: string }[] {
  const ev = hit.evidence;
  const rows: { label: string; value: string }[] = [];
  const add = (label: string, key: string) => {
    const v = ev[key];
    if (v !== undefined && v !== null && v !== "") rows.push({ label, value: String(v) });
  };
  add("Token lifetime", "lifetime_sec");
  add("Max allowed", "max_lifetime_sec");
  add("Algorithm", "algorithm");
  add("Probe path", "probe_path");
  add("Probe (1st)", "probe_status_first");
  add("Probe (2nd)", "probe_status_second");
  add("Client IP (1st)", "first_client_ip");
  add("Client IP (2nd)", "second_client_ip");
  if (Array.isArray(ev.reused_fields) && ev.reused_fields.length > 0) {
    rows.push({ label: "Reused fields", value: ev.reused_fields.map(String).join(", ") });
  }
  return rows;
}

function G42AccountTable({ accounts }: { accounts: G42AccountHit[] }) {
  if (accounts.length === 0) return null;

  return (
    <div className="overflow-x-auto rounded border border-cyber-border/25 bg-cyber-bg/15">
      <table className="w-full min-w-[28rem] table-fixed text-left text-[10px]">
        <colgroup>
          <col className="w-[22%]" />
          <col className="w-[22%]" />
          <col className="w-[46%]" />
          <col className="w-[10%]" />
        </colgroup>
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1 font-normal">계정</th>
            <th className="px-2 py-1 font-normal">Login</th>
            <th className="px-2 py-1 font-normal">사유</th>
            <th className="px-2 py-1 text-center font-normal">Severity</th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((hit, i) => {
            const extras = extraDetailRows(hit);
            return (
              <tr key={`${hit.email ?? "global"}-${i}`} className="border-b border-cyber-border/10 last:border-0 align-top">
                <td className="min-w-0 overflow-hidden px-2 py-1">
                  <G42EllipsisCell value={hit.email} className="text-cyan-300/85" mono />
                </td>
                <td className="min-w-0 overflow-hidden px-2 py-1">
                  <G42EllipsisCell value={hit.loginPath} className="text-cyan-300/70" mono />
                </td>
                <td className="min-w-0 px-2 py-1 text-white/80">
                  <span className="break-words">{hit.reason ?? "—"}</span>
                  {extras.length > 0 ? (
                    <ul className="mt-1 space-y-0.5 text-[9px] text-cyber-muted">
                      {extras.map((e) => (
                        <li key={e.label}>
                          <span>{e.label}: </span>
                          <span className="font-mono text-cyan-300/60">{e.value}</span>
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </td>
                <td className="px-2 py-1 text-center">
                  <span
                    className={`font-mono text-[9px] uppercase ${SEVERITY_STYLES[hit.severity] ?? SEVERITY_STYLES.info}`}
                  >
                    {hit.severity}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function G42RuleDetailRow({ row }: { row: G42MergedFinding }) {
  const [open, setOpen] = useState(false);
  const showAccounts = row.accounts.length > 1 || row.accounts.some((a) => a.email);

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
        <span
          className={`shrink-0 font-mono text-[9px] uppercase ${SEVERITY_STYLES[row.severity] ?? SEVERITY_STYLES.info}`}
        >
          {row.severity}
        </span>
        <span className="min-w-0 flex-1 truncate text-xs text-white/90">
          <span className="text-white/85">{row.ruleLabel}</span>
          <span className="text-cyber-muted"> · </span>
          <span className="font-mono text-cyan-300/85">{row.emailSummary}</span>
        </span>
      </button>
      {open ? (
        <div className="mt-1.5 space-y-2 border-t border-cyber-border/20 pt-1.5 text-[10px]">
          {row.reason ? (
            <p>
              <span className="text-cyber-muted">사유 · </span>
              <span className="break-words text-white/80">{row.reason}</span>
            </p>
          ) : null}
          {showAccounts ? <G42AccountTable accounts={row.accounts} /> : null}
          {row.remediation ? (
            <p className="rounded border border-cyber-border/20 bg-cyber-bg/30 px-2 py-1.5">
              <span className="text-cyber-muted">조치 · </span>
              <span className="break-words text-white/75">{row.remediation}</span>
            </p>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

export function G42FindingsPanel({ findings }: { findings: G42Finding[] }) {
  const { merged, other } = mergeG42Findings(findings);

  if (findings.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  return (
    <>
      <G42SummaryTable merged={merged} />
      {merged.length > 0 ? (
        <CollapsibleReportSection title="상세" defaultOpen={false}>
          <p className="mb-2 text-[10px] text-cyber-muted">
            검사 항목별 계정·probe 상세. 요약에서 잘린 사유·Login은 여기서 전체 확인할 수 있습니다.
          </p>
          <ul className="space-y-1.5">
            {merged.map((row) => (
              <G42RuleDetailRow key={row.ruleId} row={row} />
            ))}
          </ul>
        </CollapsibleReportSection>
      ) : null}
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
