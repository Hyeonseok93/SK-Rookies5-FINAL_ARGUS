import { Panel } from "./ui";
import type { LoginEntryReportResponse } from "../types";

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}`;
  } catch {
    return url;
  }
}

export function LoginEntriesPanel({
  report,
}: {
  report: LoginEntryReportResponse;
}) {
  const checkedLabel = report.checked_at
    ? new Date(report.checked_at).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : null;

  if (!report.available) {
    return (
      <Panel title="Login entry points">
        <p className="px-5 py-6 text-xs text-cyber-muted">
          Verify 실행 후 인벤토리에서 탐지한 로그인 API별 계정 성공 여부가 표시됩니다.
        </p>
      </Panel>
    );
  }

  return (
    <Panel
      title="Login entry points"
      action={
        checkedLabel ? (
          <span className="text-[10px] text-cyber-muted">Checked {checkedLabel}</span>
        ) : null
      }
    >
      <div className="space-y-4 px-5 py-4">
        <div className="overflow-x-auto rounded-lg border border-cyber-border/50">
          <table className="w-full text-left text-[11px]">
            <thead>
              <tr className="border-b border-cyber-border/60 bg-cyber-bg/30 text-cyber-muted">
                <th className="px-3 py-2 font-normal">Account</th>
                <th className="px-3 py-2 font-normal">Login OK</th>
                <th className="px-3 py-2 font-normal">Login failed</th>
                <th className="px-3 py-2 font-normal">Note</th>
              </tr>
            </thead>
            <tbody>
              {report.accounts.map((row) => (
                <tr key={row.email} className="border-b border-cyber-border/30">
                  <td className="px-3 py-2 font-medium text-white">{row.email}</td>
                  <td className="px-3 py-2">
                    {row.successful_login_urls.length === 0 ? (
                      <span className="text-rose-400">none</span>
                    ) : (
                      <ul className="space-y-0.5">
                        {row.successful_login_urls.map((url) => (
                          <li key={url} className="font-mono text-emerald-400" title={url}>
                            {shortUrl(url)}
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {row.failed_login_urls.length === 0 ? (
                      <span className="text-cyber-muted">—</span>
                    ) : (
                      <ul className="space-y-0.5">
                        {row.failed_login_urls.map((url) => (
                          <li key={url} className="font-mono text-cyber-muted" title={url}>
                            {shortUrl(url)}
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td className="px-3 py-2 text-cyber-muted">
                    {row.entry_specific && row.exclusive_login_url ? (
                      <span className="text-amber-300">exclusive · {shortUrl(row.exclusive_login_url)}</span>
                    ) : row.successful_login_urls.length > 1 ? (
                      "multi-entry"
                    ) : row.successful_login_urls.length === 1 ? (
                      "single entry"
                    ) : (
                      "no login"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <p className="text-[10px] text-cyber-muted">
          Sessions collected: {report.session_count} · Probe uses every successful session (no path hardcoding).
        </p>

        <div className="space-y-4 border-t border-cyber-border/50 pt-4">
          <div>
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
              Configured entries ({report.login_entries.length})
            </p>
            <div className="flex flex-wrap gap-2">
              {report.login_entries.map((entry) => (
                <span
                  key={entry.url}
                  className="rounded border border-cyber-border/60 bg-cyber-bg/40 px-2 py-1 text-[11px] text-white"
                  title={entry.url}
                >
                  {entry.label}{" "}
                  <span className="text-cyber-muted">· {shortUrl(entry.url)}</span>
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </Panel>
  );
}
