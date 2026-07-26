import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  formatG62DiffKindLabel,
  groupG62ByHost,
  mergeG62Findings,
  truncateMessage,
  type G62Finding,
  type G62MergedFinding,
  type G62Scenario,
} from "../../lib/g62ReportView";

const SEVERITY_STYLES: Record<string, string> = {
  high: "text-rose-300",
  medium: "text-amber-300",
  low: "text-sky-300",
  info: "text-cyber-muted",
};

function SourceBadges({ sources }: { sources: ("httpx" | "zap")[] }) {
  if (sources.length === 0) return null;
  const label = sources.length > 1 ? "httpx+ZAP" : sources[0];
  return (
    <span className="rounded border border-cyber-border/40 bg-cyber-bg/50 px-1.5 py-px font-mono text-[9px] uppercase text-cyan-300/70">
      {label}
    </span>
  );
}

function CodeBadge({ code, tone }: { code: string; tone: "existing" | "unknown" }) {
  const cls =
    tone === "existing"
      ? "border-amber-400/40 bg-amber-500/10 text-amber-200"
      : "border-rose-400/40 bg-rose-500/10 text-rose-200";
  return (
    <span className={`inline-block rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold ${cls}`}>
      {code}
    </span>
  );
}

function EnumerationResponseCell({ row }: { row: G62MergedFinding }) {
  if (row.codeOnlyDiff) {
    return (
      <div className="space-y-1">
        {row.sharedMessage ? (
          <p className="text-[9px] text-cyber-muted" title={row.sharedMessage}>
            메시지 동일 · {truncateMessage(row.sharedMessage, 36)}
          </p>
        ) : null}
        <div className="flex flex-wrap items-center gap-1.5">
          {row.existingCode ? <CodeBadge code={row.existingCode} tone="existing" /> : null}
          {row.existingCode && row.unknownCode ? (
            <span className="text-cyber-muted">↔</span>
          ) : null}
          {row.unknownCode ? <CodeBadge code={row.unknownCode} tone="unknown" /> : null}
        </div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-2">
      <div>
        <p className="mb-0.5 text-[9px] text-cyber-muted">존재</p>
        <p className="text-amber-200/90">{truncateMessage(row.existingMessage, 32)}</p>
        {row.existingCode ? (
          <p className="mt-0.5 font-mono text-[10px] text-cyan-300/80">{row.existingCode}</p>
        ) : null}
      </div>
      <div>
        <p className="mb-0.5 text-[9px] text-cyber-muted">없음</p>
        <p className="text-rose-200/90">{truncateMessage(row.unknownMessage, 32)}</p>
        {row.unknownCode ? (
          <p className="mt-0.5 font-mono text-[10px] text-cyan-300/80">{row.unknownCode}</p>
        ) : null}
      </div>
    </div>
  );
}

function G62EnumerationTable({ merged }: { merged: G62MergedFinding[] }) {
  const rows = merged.filter((r) => r.issueKind === "enumeration" || r.issueKind === "zap");
  if (rows.length === 0) return null;

  const hasCodeOnly = rows.some((r) => r.codeOnlyDiff);

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">계정 열거 위험</span>
        {hasCodeOnly ? (
          <p className="mt-0.5 text-[10px] text-cyber-muted">
            사용자 메시지는 같아도 오류 코드가 다르면 계정 열거로 판정됩니다.
          </p>
        ) : null}
      </div>
      <table className="w-full min-w-[32rem] text-left text-[10px]">
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-3 py-1.5 font-normal">Login</th>
            <th className="px-2 py-1.5 font-normal">응답 차이</th>
            <th className="px-2 py-1.5 font-normal">불일치</th>
            <th className="px-2 py-1.5 text-center font-normal">Severity</th>
            <th className="px-3 py-1.5 text-right font-normal">확인</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={`${row.loginUrl}|${row.issueKind}`}
              className="border-b border-cyber-border/10 last:border-0"
            >
              <td className="px-3 py-1.5 align-top">
                <span className="break-all font-mono text-cyan-300/90">{row.loginPath}</span>
                {row.issueKind === "zap" ? (
                  <span className="ml-1 text-cyber-muted">ZAP</span>
                ) : null}
              </td>
              <td className="max-w-[18rem] px-2 py-1.5 align-top">
                {row.issueKind === "enumeration" ? (
                  <EnumerationResponseCell row={row} />
                ) : (
                  truncateMessage(row.zapOther ?? row.leakSummary, 48)
                )}
              </td>
              <td className="px-2 py-1.5 align-top text-white/75">
                {row.issueKind === "enumeration"
                  ? formatG62DiffKindLabel(row.diffKinds, row.codeOnlyDiff)
                  : "—"}
              </td>
              <td className="px-2 py-1.5 text-center align-top">
                <span
                  className={`font-mono text-[9px] uppercase ${SEVERITY_STYLES[row.severity] ?? SEVERITY_STYLES.info}`}
                >
                  {row.severity}
                </span>
              </td>
              <td className="px-3 py-1.5 text-right align-top">
                <SourceBadges sources={row.sources} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScenarioTable({ scenarios }: { scenarios: G62Scenario[] }) {
  if (scenarios.length === 0) return null;

  const baseCode = scenarios.find((s) => s.key === "a")?.errorCode ?? null;

  return (
    <div className="overflow-x-auto rounded border border-cyber-border/25 bg-cyber-bg/15">
      <table className="w-full min-w-[24rem] text-left text-[10px]">
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-2 py-1 font-normal">시나리오</th>
            <th className="px-2 py-1 font-normal">HTTP</th>
            <th className="px-2 py-1 font-normal">계정</th>
            <th className="px-2 py-1 font-normal">메시지</th>
            <th className="px-2 py-1 font-normal">오류 코드</th>
          </tr>
        </thead>
        <tbody>
          {scenarios.map((s) => {
            const codeDiffers =
              Boolean(baseCode && s.errorCode && s.errorCode !== baseCode) ||
              Boolean(!baseCode && s.errorCode);
            return (
              <tr key={s.key} className="border-b border-cyber-border/10 last:border-0">
                <td className="px-2 py-1 text-white/80">{s.label}</td>
                <td className="px-2 py-1 font-mono text-cyan-300/80">{s.httpStatus ?? "—"}</td>
                <td
                  className="max-w-[8rem] truncate px-2 py-1 font-mono text-cyber-muted"
                  title={s.email ?? undefined}
                >
                  {s.email ?? "—"}
                </td>
                <td className="px-2 py-1 text-white/85">{s.message ?? "—"}</td>
                <td className="px-2 py-1">
                  {s.errorCode ? (
                    <span
                      className={`font-mono text-[11px] font-semibold ${
                        codeDiffers ? "text-amber-300" : "text-cyan-300/80"
                      }`}
                    >
                      {s.errorCode}
                    </span>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function G62FindingDetail({ f }: { f: G62MergedFinding }) {
  return (
    <div className="mt-1.5 space-y-2 border-t border-cyber-border/20 pt-1.5 text-[10px]">
      {f.codeOnlyDiff && f.codeDiffSummary ? (
        <div className="rounded border border-amber-400/30 bg-amber-500/5 px-2 py-1.5">
          <p className="text-amber-200/90">
            <span className="text-cyber-muted">판정 · </span>
            메시지는 동일하고 오류 코드만 다릅니다 ·{" "}
            <span className="font-mono font-semibold">{f.codeDiffSummary}</span>
          </p>
          {f.sharedMessage ? (
            <p className="mt-0.5 text-cyber-muted">공통 메시지 · {f.sharedMessage}</p>
          ) : null}
        </div>
      ) : null}
      <p className="break-all">
        <span className="text-cyber-muted">URL · </span>
        <span className="font-mono text-cyan-300/80">{f.loginUrl}</span>
      </p>
      {f.probeMode ? (
        <p>
          <span className="text-cyber-muted">Probe · </span>
          <span className="font-mono text-cyan-300/80">{f.probeMode}</span>
        </p>
      ) : null}
      {f.issueKind === "zap" && f.zapOther ? (
        <p>
          <span className="text-cyber-muted">ZAP · </span>
          <span className="text-white/80">{f.zapOther}</span>
        </p>
      ) : null}
      {f.issueKind === "unreachable" && f.zapOther ? (
        <p>
          <span className="text-cyber-muted">Error · </span>
          <span className="text-rose-300/80">{f.zapOther}</span>
        </p>
      ) : null}
      {f.scenarios.length > 0 ? <ScenarioTable scenarios={f.scenarios} /> : null}
      {f.remediation ? (
        <p>
          <span className="text-cyber-muted">조치 · </span>
          <span className="text-white/75">{f.remediation}</span>
        </p>
      ) : null}
    </div>
  );
}

function G62FindingRow({ f }: { f: G62MergedFinding }) {
  const [open, setOpen] = useState(false);
  const headline =
    f.issueKind === "enumeration"
      ? f.codeOnlyDiff && f.codeDiffSummary
        ? `메시지 동일 · ${f.codeDiffSummary}`
        : f.leakSummary
      : f.issueKind === "zap"
        ? f.zapAlert ?? f.leakSummary
        : f.rawMessage;

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
          className={`shrink-0 font-mono text-[9px] uppercase ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info}`}
        >
          {f.severity}
        </span>
        <span className="min-w-0 shrink-0 font-mono text-xs text-cyan-300/90">{f.loginPath}</span>
        <span className="min-w-0 flex-1 text-[10px] text-white/75">
          {f.codeOnlyDiff && f.codeDiffSummary ? (
            <span className="font-mono font-semibold text-amber-200">{f.codeDiffSummary}</span>
          ) : (
            headline
          )}
        </span>
        <SourceBadges sources={f.sources} />
      </button>
      {open ? <G62FindingDetail f={f} /> : null}
    </li>
  );
}

function G62HostSection({ group }: { group: ReturnType<typeof groupG62ByHost>[number] }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="mb-2 overflow-hidden rounded-lg border border-cyber-border/40 bg-cyber-bg/15">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition hover:bg-cyber-accent/5"
      >
        <ChevronDown
          className={`h-4 w-4 shrink-0 text-cyber-muted transition ${open ? "rotate-180" : ""}`}
        />
        <span className="font-mono text-xs text-cyan-300/90">{group.hostLabel}</span>
        <span className="text-[10px] text-cyber-muted">
          {group.findings.length} login{group.findings.length !== 1 ? "s" : ""}
        </span>
      </button>
      {open ? (
        <ul className="space-y-1.5 border-t border-cyber-border/25 px-2 py-2">
          {group.findings.map((f) => (
            <G62FindingRow key={`${f.loginUrl}|${f.issueKind}`} f={f} />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function G62FindingsPanel({ findings }: { findings: G62Finding[] }) {
  const { merged, other } = mergeG62Findings(findings);
  const groups = groupG62ByHost(merged);

  if (findings.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  return (
    <>
      <G62EnumerationTable merged={merged} />
      {groups.length > 0 ? (
        <CollapsibleReportSection title="상세">
          {groups.map((g) => (
            <G62HostSection key={g.hostLabel} group={g} />
          ))}
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
