import { ChevronDown, ChevronRight } from "lucide-react";
import { Fragment, useState, type ReactNode } from "react";
import { MethodBadge } from "./ui";
import { fetchEndpointDetail } from "../lib/api";
import type { EndpointDetail, EndpointSummary, InventoryView } from "../types";

function HeadersTable({ headers, emptyLabel }: { headers: EndpointDetail["request_headers"]; emptyLabel: string }) {
  if (headers.length === 0) {
    return <p className="px-3 py-2 text-xs text-cyber-muted">{emptyLabel}</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[11px]">
        <thead>
          <tr className="border-b border-cyber-border/60 text-cyber-muted">
            <th className="px-3 py-1.5 font-normal">Name</th>
            <th className="px-3 py-1.5 font-normal">Sample</th>
            <th className="px-3 py-1.5 font-normal">Role</th>
            <th className="px-3 py-1.5 font-normal">Required</th>
            <th className="px-3 py-1.5 font-normal">Sources</th>
          </tr>
        </thead>
        <tbody>
          {headers.map((hdr) => (
            <tr key={hdr.name} className="border-b border-cyber-border/30">
              <td className="px-3 py-1.5 font-medium text-white">{hdr.name}</td>
              <td className="max-w-[12rem] truncate px-3 py-1.5 font-mono text-cyber-muted" title={hdr.sample ?? undefined}>
                {hdr.sample ?? "—"}
              </td>
              <td className="px-3 py-1.5 text-cyber-muted">{hdr.role}</td>
              <td className="px-3 py-1.5 text-cyber-muted">{hdr.required ? "yes" : "—"}</td>
              <td className="px-3 py-1.5 text-cyber-muted">{hdr.sources.join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ParamsTable({ params, emptyLabel }: { params: EndpointDetail["request_params"]; emptyLabel: string }) {
  if (params.length === 0) {
    return <p className="px-3 py-2 text-xs text-cyber-muted">{emptyLabel}</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[11px]">
        <thead>
          <tr className="border-b border-cyber-border/60 text-cyber-muted">
            <th className="px-3 py-1.5 font-normal">In</th>
            <th className="px-3 py-1.5 font-normal">Name</th>
            <th className="px-3 py-1.5 font-normal">Type</th>
            <th className="px-3 py-1.5 font-normal">Required</th>
            <th className="px-3 py-1.5 font-normal">Sample</th>
            <th className="px-3 py-1.5 font-normal">Sources</th>
          </tr>
        </thead>
        <tbody>
          {params.map((inp) => (
            <tr key={`${inp.in}-${inp.name}`} className="border-b border-cyber-border/30">
              <td className="px-3 py-1.5 font-mono text-cyber-accent">{inp.in}</td>
              <td className="px-3 py-1.5 font-medium text-white">{inp.name}</td>
              <td className="px-3 py-1.5 text-cyber-muted">{inp.type}</td>
              <td className="px-3 py-1.5 text-cyber-muted">{inp.required ? "yes" : "—"}</td>
              <td className="max-w-[10rem] truncate px-3 py-1.5 font-mono text-cyber-muted" title={inp.sample ?? undefined}>
                {inp.sample ?? "—"}
              </td>
              <td className="px-3 py-1.5 text-cyber-muted">{inp.sources.join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AccountAccessPanel({ rows }: { rows: EndpointDetail["account_access"] }) {
  if (rows.length === 0) {
    return (
      <p className="px-3 py-2 text-xs text-cyber-muted">
        Verify 실행 후 계정별 접근 결과가 표시됩니다.
      </p>
    );
  }

  const works = rows.filter((r) => r.allowed);
  const blocked = rows.filter((r) => !r.allowed);

  return (
    <div className="space-y-3 px-3 py-2">
      {works.length > 0 ? (
        <div>
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-400">
            접근 가능 ({works.length})
          </p>
          <div className="flex flex-wrap gap-1.5">
            {works.map((row) => (
              <span
                key={row.auth_mode}
                className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-300"
                title={row.note || undefined}
              >
                {row.auth_mode}
                {row.http_status != null ? ` · ${row.http_status}` : ""}
              </span>
            ))}
          </div>
        </div>
      ) : null}
      {blocked.length > 0 ? (
        <div>
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-rose-400">
            접근 불가 / 미검증 ({blocked.length})
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11px]">
              <thead>
                <tr className="border-b border-cyber-border/60 text-cyber-muted">
                  <th className="py-1.5 pr-3 font-normal">Account</th>
                  <th className="py-1.5 pr-3 font-normal">HTTP</th>
                  <th className="py-1.5 pr-3 font-normal">Status</th>
                  <th className="py-1.5 font-normal">Note</th>
                </tr>
              </thead>
              <tbody>
                {blocked.map((row) => (
                  <tr key={row.auth_mode} className="border-b border-cyber-border/30">
                    <td className="py-1.5 pr-3 font-medium text-white">{row.auth_mode}</td>
                    <td className="py-1.5 pr-3 font-mono text-cyber-muted">{row.http_status ?? "—"}</td>
                    <td className="py-1.5 pr-3 text-cyber-muted">{row.status || "—"}</td>
                    <td className="max-w-[14rem] truncate py-1.5 text-cyber-muted" title={row.note || undefined}>
                      {row.note || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function DetailSection({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-cyber-border/50 bg-cyber-panel/40">
      <div className="border-b border-cyber-border/50 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-cyber-muted">
        {title} ({count})
      </div>
      {children}
    </div>
  );
}

export function EndpointTable({
  endpoints,
  emptyMessage,
  sourceDisplay,
  inventory,
}: {
  endpoints: EndpointSummary[];
  emptyMessage: string;
  sourceDisplay: Record<string, string>;
  inventory: InventoryView;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, EndpointDetail>>({});
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [errorId, setErrorId] = useState<string | null>(null);

  const toggleRow = async (id: string) => {
    if (expandedId === id) {
      setExpandedId(null);
      return;
    }

    setExpandedId(id);
    setErrorId(null);

    if (details[id]) {
      return;
    }

    setLoadingId(id);
    try {
      const detail = await fetchEndpointDetail(id, inventory);
      if (!detail.found) {
        setErrorId(id);
        return;
      }
      setDetails((prev) => ({ ...prev, [id]: detail }));
    } catch {
      setErrorId(id);
    } finally {
      setLoadingId(null);
    }
  };

  return (
    <table className="w-full text-left text-xs">
      <thead className="sticky top-0 z-10 bg-cyber-panel/95 backdrop-blur-sm">
        <tr className="border-b border-cyber-border text-cyber-muted">
          <th className="w-6 px-1 pb-2 pt-1 font-normal" aria-hidden />
          <th className="px-1 pb-2 pt-1 pr-4 font-normal">Method</th>
          <th className="pb-2 pt-1 pr-4 font-normal">Path</th>
          <th className="pb-2 pt-1 pr-4 font-normal">Base</th>
          <th className="pb-2 pt-1 pr-4 font-normal">Params</th>
          <th className="pb-2 pt-1 font-normal">Sources</th>
        </tr>
      </thead>
      <tbody>
        {endpoints.length === 0 ? (
          <tr>
            <td colSpan={6} className="py-8 text-center text-cyber-muted">
              {emptyMessage}
            </td>
          </tr>
        ) : (
          endpoints.map((ep) => {
            const expanded = expandedId === ep.id;
            const detail = details[ep.id];
            const loading = loadingId === ep.id;
            const failed = errorId === ep.id;

            return (
              <Fragment key={ep.id}>
                <tr
                  onClick={() => void toggleRow(ep.id)}
                  className={`cursor-pointer border-b border-cyber-border/50 transition hover:bg-cyber-accent/5 ${
                    expanded ? "bg-cyber-accent/5" : ""
                  }`}
                >
                  <td className="px-1 py-2.5 text-cyber-muted">
                    {expanded ? (
                      <ChevronDown className="h-3.5 w-3.5" strokeWidth={2} />
                    ) : (
                      <ChevronRight className="h-3.5 w-3.5" strokeWidth={2} />
                    )}
                  </td>
                  <td className="py-2.5 pr-4">
                    <MethodBadge method={ep.method} />
                  </td>
                  <td className="max-w-xs truncate py-2.5 pr-4 font-medium text-white">{ep.path}</td>
                  <td className="py-2.5 pr-4 text-cyber-muted">{ep.base_url.replace("http://", "")}</td>
                  <td className="py-2.5 pr-4">
                    <span className="text-cyber-accent">{ep.input_count}</span>
                    {ep.inputs_preview.length > 0 && !expanded && (
                      <span className="ml-2 text-cyber-muted">
                        {ep.inputs_preview.slice(0, 3).join(", ")}
                        {ep.inputs_preview.length > 3 ? "…" : ""}
                      </span>
                    )}
                  </td>
                  <td className="py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {ep.sources.map((source) => (
                        <span
                          key={source}
                          className="rounded border border-cyber-accent/25 bg-cyber-accent/10 px-1.5 py-0.5 text-[10px] text-cyber-muted"
                        >
                          {sourceDisplay[source] ?? source}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
                {expanded && (
                  <tr className="border-b border-cyber-border/50 bg-cyber-bg/40">
                    <td colSpan={6} className="px-3 py-3">
                      {loading ? (
                        <p className="text-xs text-cyber-muted">Loading details…</p>
                      ) : failed ? (
                        <p className="text-xs text-rose-400">Could not load endpoint details.</p>
                      ) : detail ? (
                        <div className="space-y-3">
                          {(detail.tags.length > 0 || detail.auth.length > 0) && (
                            <div className="flex flex-wrap gap-2 text-[11px] text-cyber-muted">
                              {detail.tags.length > 0 && (
                                <span>
                                  Tags: <span className="text-white">{detail.tags.join(", ")}</span>
                                </span>
                              )}
                              {detail.auth.length > 0 && (
                                <span>
                                  Auth: <span className="text-white">{detail.auth.join(", ")}</span>
                                </span>
                              )}
                            </div>
                          )}
                          <div className="grid gap-3 lg:grid-cols-2">
                            <DetailSection title="Request params" count={detail.request_params.length}>
                              <ParamsTable
                                params={detail.request_params}
                                emptyLabel="No request parameters recorded."
                              />
                            </DetailSection>
                            <DetailSection title="Response params" count={detail.response_params.length}>
                              <ParamsTable
                                params={detail.response_params}
                                emptyLabel="No response parameters observed yet."
                              />
                            </DetailSection>
                            <DetailSection title="Request headers" count={detail.request_headers.length}>
                              <HeadersTable
                                headers={detail.request_headers}
                                emptyLabel="No request headers observed yet."
                              />
                            </DetailSection>
                            <DetailSection title="Response headers" count={detail.response_headers.length}>
                              <HeadersTable
                                headers={detail.response_headers}
                                emptyLabel="No response headers observed yet."
                              />
                            </DetailSection>
                          </div>
                          <DetailSection title="Account access" count={detail.account_access.length}>
                            <AccountAccessPanel rows={detail.account_access} />
                          </DetailSection>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })
        )}
      </tbody>
    </table>
  );
}
