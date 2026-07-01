import { MethodBadge, Panel } from "./ui";
import { OutcomeTag } from "./OutcomeTag";
import type { VerifyReportSummary, VerifyResultSummary, VerifyOutcome } from "../types";

const STATUS_LABEL: Record<string, string> = {
  confirmed: "Confirmed",
  params_issue: "Params issue",
  not_found: "Not found",
  method_not_allowed: "405",
  unreachable: "Unreachable",
  server_error: "Server error",
  unknown: "Unknown",
  error: "Error",
};

const STATUS_STYLE: Record<string, string> = {
  confirmed: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  params_issue: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  not_found: "bg-rose-500/15 text-rose-400 border-rose-500/30",
  method_not_allowed: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  unreachable: "bg-red-500/15 text-red-400 border-red-500/30",
  server_error: "bg-violet-500/15 text-violet-400 border-violet-500/30",
  unknown: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  error: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_STYLE[status] ?? STATUS_STYLE.unknown;
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${cls}`}>
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

function outcomeCount(summary: VerifyReportSummary, outcome: VerifyOutcome): number {
  if (outcome === "final") return summary.final_count;
  if (outcome === "discovered") return summary.discovered_count;
  return summary.rejected;
}

export function VerifyResultsPanel({
  available,
  checkedAt,
  summary,
  outcome,
  onOutcomeChange,
  filter,
  onFilterChange,
  items,
  total,
}: {
  available: boolean;
  checkedAt: string | null;
  summary: VerifyReportSummary;
  outcome: VerifyOutcome;
  onOutcomeChange: (outcome: VerifyOutcome) => void;
  filter: string;
  onFilterChange: (value: string) => void;
  items: VerifyResultSummary[];
  total: number;
}) {
  const checkedLabel = checkedAt
    ? new Date(checkedAt).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : null;

  const probeNote =
    summary.probe_runs && summary.probe_runs > summary.total_checked
      ? `${summary.probe_runs} probes (guest + saved accounts)`
      : null;

  return (
    <Panel
      title="Verify Results"
      action={
        available ? (
          <div className="flex flex-wrap items-center justify-center gap-2">
            <OutcomeTag
              active={outcome === "final"}
              label="Final"
              count={summary.final_count}
              onClick={() => onOutcomeChange("final")}
              tone="final"
            />
            <OutcomeTag
              active={outcome === "discovered"}
              label="Discover"
              count={summary.discovered_count}
              onClick={() => onOutcomeChange("discovered")}
              tone="discovered"
            />
            <OutcomeTag
              active={outcome === "rejected"}
              label="Rejected"
              count={summary.rejected}
              onClick={() => onOutcomeChange("rejected")}
              tone="rejected"
            />
          </div>
        ) : undefined
      }
      trailing={
        available ? (
          <input
            type="search"
            placeholder="Filter path…"
            value={filter}
            onChange={(e) => onFilterChange(e.target.value)}
            className="rounded border border-cyber-border bg-cyber-bg px-3 py-1.5 text-xs text-white placeholder:text-cyber-muted focus:border-cyber-accent/50 focus:outline-none"
          />
        ) : undefined
      }
    >
      {!available ? (
        <p className="py-6 text-center text-xs text-cyber-muted">
          Verify 실행 후 Final / Discover / Rejected 결과가 여기에 표시됩니다.
        </p>
      ) : (
        <>
          <p className="mb-3 text-xs text-cyber-muted">
            {checkedLabel ? `Last run ${checkedLabel}` : null}
            {checkedLabel ? " · " : null}
            {summary.total_checked} endpoints
            {probeNote ? ` · ${probeNote}` : null}
            {total < outcomeCount(summary, outcome) ? (
              <span>
                {" "}
                · showing {items.length} of {total}
              </span>
            ) : null}
          </p>
          <div className="max-h-[min(22rem,calc(100vh-24rem))] overflow-x-auto overflow-y-auto rounded-lg border border-cyber-border/40">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 z-10 bg-cyber-panel/95 backdrop-blur-sm">
                <tr className="border-b border-cyber-border text-cyber-muted">
                  <th className="px-1 pb-2 pt-1 pr-4 font-normal">Method</th>
                  <th className="pb-2 pt-1 pr-4 font-normal">Path</th>
                  <th className="pb-2 pt-1 pr-4 font-normal">Base</th>
                  <th className="pb-2 pt-1 pr-4 font-normal">HTTP</th>
                  <th className="pb-2 pt-1 pr-4 font-normal">Status</th>
                  <th className="pb-2 pt-1 font-normal">Note</th>
                </tr>
              </thead>
              <tbody>
                {items.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-cyber-muted">
                      {filter ? "No matches" : "No entries"}
                    </td>
                  </tr>
                ) : (
                  items.map((row) => (
                    <tr
                      key={row.endpoint_id}
                      className="border-b border-cyber-border/50 transition hover:bg-cyber-accent/5"
                    >
                      <td className="py-2.5 pr-4">
                        <MethodBadge method={row.method} />
                      </td>
                      <td className="max-w-xs truncate py-2.5 pr-4 font-medium text-white" title={row.path}>
                        {row.path}
                      </td>
                      <td className="py-2.5 pr-4 text-cyber-muted">
                        {row.base_url.replace("http://", "")}
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-cyber-muted">
                        {row.http_status ?? "—"}
                      </td>
                      <td className="py-2.5 pr-4">
                        <StatusBadge status={row.status} />
                      </td>
                      <td className="max-w-[14rem] truncate py-2.5 text-cyber-muted" title={row.note}>
                        {row.note}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Panel>
  );
}
