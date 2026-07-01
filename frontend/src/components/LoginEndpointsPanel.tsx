import { Check, CircleAlert, KeyRound, Plus, Trash2 } from "lucide-react";
import type { LoginEndpointEntry, LoginEndpointResolved } from "../types";

export type SavedLoginEndpointsSnapshot = Record<
  string,
  { url: string; kind: LoginEndpointEntry["kind"] }
>;

export function createEmptyLoginEndpoint(): LoginEndpointEntry {
  return {
    id: crypto.randomUUID(),
    url: "",
    kind: "api",
  };
}

export function buildSavedLoginEndpointsSnapshot(
  endpoints: LoginEndpointEntry[],
): SavedLoginEndpointsSnapshot {
  const snap: SavedLoginEndpointsSnapshot = {};
  for (const entry of endpoints) {
    if (entry.url.trim()) {
      snap[entry.id] = {
        url: entry.url.trim(),
        kind: entry.kind,
      };
    }
  }
  return snap;
}

export function isLoginEndpointSaved(
  entry: LoginEndpointEntry,
  snapshot: SavedLoginEndpointsSnapshot,
): boolean {
  const saved = snapshot[entry.id];
  if (!saved) return false;
  if (!entry.url.trim()) return false;
  return saved.url === entry.url.trim() && saved.kind === entry.kind;
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}`;
  } catch {
    return url;
  }
}

interface LoginEndpointsPanelProps {
  open: boolean;
  endpoints: LoginEndpointEntry[];
  resolved: LoginEndpointResolved[];
  savedSnapshot: SavedLoginEndpointsSnapshot;
  saving: boolean;
  saveError: string;
  onAdd: () => void;
  onChange: (id: string, field: "url" | "kind", value: string) => void;
  onRemove: (id: string) => void;
  onSave: () => void;
}

export function LoginEndpointsPanel({
  open,
  endpoints,
  resolved,
  savedSnapshot,
  saving,
  saveError,
  onAdd,
  onChange,
  onRemove,
  onSave,
}: LoginEndpointsPanelProps) {
  const savedCount = endpoints.filter((e) => isLoginEndpointSaved(e, savedSnapshot)).length;
  const inventoryCount = resolved.filter((r) => r.source === "inventory").length;
  const dashboardCount = resolved.filter((r) => r.source === "dashboard").length;

  return (
    <div
      className={`grid transition-all duration-500 ease-out ${
        open ? "mb-6 grid-rows-[1fr] opacity-100" : "mb-0 grid-rows-[0fr] opacity-0"
      }`}
    >
      <div className="overflow-hidden">
        <div className="rounded-xl border border-amber-500/25 bg-cyber-panel/90 shadow-[0_0_40px_rgba(245,158,11,0.06)] backdrop-blur-md">
          <div className="flex items-center justify-between border-b border-cyber-border px-5 py-3">
            <div className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-amber-400" strokeWidth={1.5} />
              <p className="font-display text-sm font-semibold tracking-wide text-amber-300">
                Login Endpoints
              </p>
            </div>
            <button
              type="button"
              onClick={onAdd}
              className="flex items-center gap-1.5 rounded-lg border border-amber-400/40 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-300 transition hover:bg-amber-500/20"
            >
              <Plus className="h-3.5 w-3.5" strokeWidth={2} />
              Add
            </button>
          </div>

          <p className="border-b border-cyber-border/60 px-5 py-3 text-xs leading-relaxed text-cyber-muted">
            로그인 API는 인벤토리에서 <strong className="text-white/80">자동 탐지</strong>됩니다.
            모달 로그인 등 인벤토리에 없을 때는 여기에{" "}
            <strong className="text-white/80">로그인 API URL</strong> 또는{" "}
            <strong className="text-white/80">페이지 URL</strong>을 추가하세요. 6-2·Verify·로그인
            프로브에 동일하게 사용됩니다.
          </p>

          {resolved.length > 0 && (
            <div className="border-b border-cyber-border/60 px-5 py-3">
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                Effective targets ({resolved.length})
              </p>
              <div className="flex flex-wrap gap-1.5">
                {resolved.map((row) => (
                  <span
                    key={row.url}
                    className={`rounded border px-2 py-0.5 text-[10px] ${
                      row.source === "dashboard"
                        ? "border-amber-500/40 bg-amber-500/10 text-amber-200"
                        : "border-cyber-border/60 bg-cyber-bg/40 text-white/90"
                    }`}
                    title={row.url}
                  >
                    {row.label}{" "}
                    <span className="text-cyber-muted">
                      · {row.kind} · {row.source} · {shortUrl(row.url)}
                    </span>
                  </span>
                ))}
              </div>
              <p className="mt-2 text-[10px] text-cyber-muted">
                inventory {inventoryCount} · dashboard {dashboardCount}
              </p>
            </div>
          )}

          <div className="p-5">
            {endpoints.length === 0 ? (
              <button
                type="button"
                onClick={onAdd}
                className="flex w-full flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-cyber-border py-10 text-cyber-muted transition hover:border-amber-400/40 hover:bg-amber-500/5 hover:text-amber-300"
              >
                <Plus className="h-6 w-6" strokeWidth={1.5} />
                <span className="text-xs font-medium">로그인 엔드포인트 추가</span>
              </button>
            ) : (
              <div className="space-y-3">
                {endpoints.map((entry, index) => {
                  const saved = isLoginEndpointSaved(entry, savedSnapshot);

                  return (
                    <div
                      key={entry.id}
                      className={`grid gap-2 rounded-lg border p-3 transition-all duration-200 sm:grid-cols-[auto_minmax(0,1.6fr)_minmax(0,0.8fr)_auto] sm:items-center sm:gap-3 ${
                        saved
                          ? "border-amber-400/45 bg-amber-500/10 shadow-[inset_0_0_24px_rgba(245,158,11,0.06)]"
                          : "border-cyber-border bg-cyber-bg/60"
                      }`}
                    >
                      <div className="flex items-end sm:items-center">
                        <div
                          className={`flex h-6 w-6 items-center justify-center rounded border transition ${
                            saved
                              ? "border-amber-400 bg-amber-400 text-cyber-bg"
                              : "border-cyber-border/80 bg-cyber-panel/40 text-transparent"
                          }`}
                        >
                          <Check className="h-3.5 w-3.5" strokeWidth={2.5} />
                        </div>
                        <span className="ml-2 text-[10px] font-mono text-cyber-muted sm:hidden">
                          #{index + 1}
                        </span>
                      </div>

                      <label className="block min-w-0">
                        <span className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-cyber-muted">
                          URL
                        </span>
                        <input
                          type="text"
                          value={entry.url}
                          onChange={(e) => onChange(entry.id, "url", e.target.value)}
                          placeholder="https://host/api/v1/auth/login or /api/v1/auth/login"
                          className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white placeholder:text-cyber-muted/60 focus:border-amber-400/50 focus:outline-none"
                        />
                      </label>

                      <label className="block">
                        <span className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-cyber-muted">
                          Kind
                        </span>
                        <select
                          value={entry.kind}
                          onChange={(e) =>
                            onChange(entry.id, "kind", e.target.value as LoginEndpointEntry["kind"])
                          }
                          className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 text-xs text-white focus:border-amber-400/50 focus:outline-none"
                        >
                          <option value="api">api</option>
                          <option value="page">page</option>
                        </select>
                      </label>

                      <div className="flex items-end justify-end sm:items-center">
                        <button
                          type="button"
                          onClick={() => onRemove(entry.id)}
                          className="rounded border border-cyber-border/60 p-1.5 text-cyber-muted transition hover:border-rose-400/50 hover:bg-rose-500/10 hover:text-rose-300"
                          aria-label="Remove login endpoint"
                        >
                          <Trash2 className="h-3.5 w-3.5" strokeWidth={2} />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {saveError ? (
              <div className="mt-3 flex items-center gap-2 rounded border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
                <CircleAlert className="h-3.5 w-3.5 shrink-0" strokeWidth={2} />
                {saveError}
              </div>
            ) : null}

            {endpoints.length > 0 ? (
              <div className="mt-4 flex items-center justify-between border-t border-cyber-border/40 pt-4">
                <span className="text-[10px] text-cyber-muted">
                  {savedCount}/{endpoints.filter((e) => e.url.trim()).length} saved
                </span>
                <button
                  type="button"
                  onClick={onSave}
                  disabled={saving}
                  className="rounded-lg border border-amber-400/50 bg-amber-500/15 px-4 py-1.5 text-xs font-semibold text-amber-300 transition hover:bg-amber-500/25 disabled:opacity-50"
                >
                  {saving ? "Saving…" : "Save Login Endpoints"}
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}
