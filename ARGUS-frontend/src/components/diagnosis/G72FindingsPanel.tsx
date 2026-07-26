import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
  formatG72BaseLabel,
  formatG72Path,
  groupG72ByBaseUrl,
  mergeG72Findings,
  type G72Finding,
  type G72MergedFinding,
} from "../../lib/g72ReportView";

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

function G72ExposureTable({ merged }: { merged: G72MergedFinding[] }) {
  if (merged.length === 0) return null;

  return (
    <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <div className="border-b border-cyber-border/30 px-3 py-2">
        <span className="text-xs font-semibold text-white">노출 경로</span>
      </div>
      <table className="w-full min-w-[24rem] text-left text-[10px]">
        <thead>
          <tr className="border-b border-cyber-border/20 text-cyber-muted">
            <th className="px-3 py-1.5 font-normal">Path</th>
            <th className="px-2 py-1.5 font-normal">Origin</th>
            <th className="px-2 py-1.5 font-normal">Listing</th>
            <th className="px-2 py-1.5 text-center font-normal">Severity</th>
            <th className="px-3 py-1.5 text-right font-normal">확인</th>
          </tr>
        </thead>
        <tbody>
          {merged.map((row) => (
            <tr
              key={`${row.baseUrl}|${formatG72Path(row.sampleUrl)}`}
              className="border-b border-cyber-border/10 last:border-0"
            >
              <td className="max-w-[14rem] px-3 py-1.5">
                <span className="break-all font-mono text-cyan-300/90">{formatG72Path(row.sampleUrl)}</span>
                {row.affectedCount > 1 ? (
                  <span className="ml-1 text-cyber-muted">+{row.affectedCount - 1}</span>
                ) : null}
              </td>
              <td className="px-2 py-1.5 font-mono text-white/70">
                {formatG72BaseLabel(row.baseUrl)}
              </td>
              <td className="px-2 py-1.5 text-white/80">{row.listingLabel}</td>
              <td className="px-2 py-1.5 text-center">
                <span
                  className={`font-mono text-[9px] uppercase ${SEVERITY_STYLES[row.severity] ?? SEVERITY_STYLES.info}`}
                >
                  {row.severity}
                </span>
              </td>
              <td className="px-3 py-1.5 text-right">
                <SourceBadges sources={row.sources} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function G72FindingDetail({ f }: { f: G72MergedFinding }) {
  const [showUrls, setShowUrls] = useState(false);

  return (
    <div className="mt-1.5 space-y-1 border-t border-cyber-border/20 pt-1.5 text-[10px]">
      {f.matchedPatterns.length > 0 ? (
        <p>
          <span className="text-cyber-muted">Patterns · </span>
          <span className="font-mono text-cyan-300/80">{f.matchedPatterns.join(", ")}</span>
        </p>
      ) : null}
      {f.fileLinkCount != null && f.fileLinkCount > 0 ? (
        <p>
          <span className="text-cyber-muted">File links · </span>
          <span className="font-mono text-cyan-300/80">{f.fileLinkCount}</span>
        </p>
      ) : null}
      {f.remediation ? (
        <p>
          <span className="text-cyber-muted">Remediation · </span>
          <span className="text-cyan-300/80">{f.remediation}</span>
        </p>
      ) : null}
      {f.httpStatus != null ? (
        <p>
          <span className="text-cyber-muted">HTTP · </span>
          <span className="font-mono text-cyan-300/80">{String(f.httpStatus)}</span>
        </p>
      ) : null}
      {f.sampleUrl ? (
        <p className="break-all">
          <span className="text-cyber-muted">URL · </span>
          <span className="font-mono text-cyan-300/80">{f.sampleUrl}</span>
        </p>
      ) : null}
      {f.affectedUrls.length > 1 ? (
        <div>
          <button
            type="button"
            onClick={() => setShowUrls((v) => !v)}
            className="text-cyan-400/80 hover:text-cyan-300"
          >
            {showUrls ? "URL 목록 접기" : `동일 listing ${f.affectedUrls.length}개 URL 보기`}
          </button>
          {showUrls ? (
            <ul className="mt-1 max-h-32 space-y-0.5 overflow-y-auto font-mono text-cyan-300/70">
              {f.affectedUrls.map((u) => (
                <li key={u} className="break-all">
                  {u}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function G72FindingRow({ f }: { f: G72MergedFinding }) {
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
        <span
          className={`shrink-0 font-mono text-[9px] uppercase ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info}`}
        >
          {f.severity}
        </span>
        <span className="min-w-0 flex-1 font-mono text-xs text-cyan-300/90">
          {formatG72Path(f.sampleUrl)}
        </span>
        <span className="shrink-0 text-[10px] text-white/70">{f.listingLabel}</span>
        <SourceBadges sources={f.sources} />
      </button>
      {open ? <G72FindingDetail f={f} /> : null}
    </li>
  );
}

function G72BaseUrlSection({ group }: { group: ReturnType<typeof groupG72ByBaseUrl>[number] }) {
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
        <span className="font-mono text-xs text-cyan-300/90">{group.displayLabel}</span>
        <span className="text-[10px] text-cyber-muted">
          {group.findings.length} path{group.findings.length !== 1 ? "s" : ""}
        </span>
      </button>
      {open ? (
        <ul className="space-y-1.5 border-t border-cyber-border/25 px-2 py-2">
          {group.findings.map((f) => (
            <G72FindingRow key={`${f.baseUrl}|${formatG72Path(f.sampleUrl)}`} f={f} />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function G72FindingsPanel({ findings }: { findings: G72Finding[] }) {
  const { merged, other } = mergeG72Findings(findings);
  const groups = groupG72ByBaseUrl(merged);

  if (findings.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  return (
    <>
      <G72ExposureTable merged={merged} />
      {groups.length > 0 ? (
        <CollapsibleReportSection
          title="상세"
        >
          {groups.map((g) => (
            <G72BaseUrlSection key={g.baseUrl} group={g} />
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
