import { Check, CircleAlert, Plus, Trash2, type LucideIcon } from "lucide-react";
import type { TransferEndpointEntry, TransferEndpointResolved } from "../types";

export type SavedTransferEndpointsSnapshot = Record<
  string,
  { url: string; method: string }
>;

export function createEmptyTransferEndpoint(defaultMethod: string): TransferEndpointEntry {
  return {
    id: crypto.randomUUID(),
    url: "",
    method: defaultMethod,
  };
}

export function buildSavedTransferEndpointsSnapshot(
  endpoints: TransferEndpointEntry[],
): SavedTransferEndpointsSnapshot {
  const snap: SavedTransferEndpointsSnapshot = {};
  for (const entry of endpoints) {
    if (entry.url.trim()) {
      snap[entry.id] = {
        url: entry.url.trim(),
        method: (entry.method || defaultMethodForEntry(entry)).trim().toUpperCase(),
      };
    }
  }
  return snap;
}

function defaultMethodForEntry(entry: TransferEndpointEntry): string {
  return entry.method || "GET";
}

export function isTransferEndpointSaved(
  entry: TransferEndpointEntry,
  snapshot: SavedTransferEndpointsSnapshot,
  defaultMethod: string,
): boolean {
  const saved = snapshot[entry.id];
  if (!saved) return false;
  if (!entry.url.trim()) return false;
  const method = (entry.method || defaultMethod).trim().toUpperCase();
  return saved.url === entry.url.trim() && saved.method === method;
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}`;
  } catch {
    return url;
  }
}

export interface TransferEndpointsPanelProps {
  open: boolean;
  title: string;
  description: string;
  icon: LucideIcon;
  accentClass: string;
  defaultMethod: string;
  methodOptions: string[];
  urlPlaceholder: string;
  saveLabel: string;
  emptyLabel: string;
  endpoints: TransferEndpointEntry[];
  resolved: TransferEndpointResolved[];
  savedSnapshot: SavedTransferEndpointsSnapshot;
  saving: boolean;
  saveError: string;
  onAdd: () => void;
  onChange: (id: string, field: "url" | "method", value: string) => void;
  onRemove: (id: string) => void;
  onSave: () => void;
}

export function TransferEndpointsPanel({
  open,
  title,
  description,
  icon: Icon,
  accentClass,
  defaultMethod,
  methodOptions,
  urlPlaceholder,
  saveLabel,
  emptyLabel,
  endpoints,
  resolved,
  savedSnapshot,
  saving,
  saveError,
  onAdd,
  onChange,
  onRemove,
  onSave,
}: TransferEndpointsPanelProps) {
  const savedCount = endpoints.filter((e) =>
    isTransferEndpointSaved(e, savedSnapshot, defaultMethod),
  ).length;

  return (
    <div
      className={`grid transition-all duration-500 ease-out ${
        open ? "mb-6 grid-rows-[1fr] opacity-100" : "mb-0 grid-rows-[0fr] opacity-0"
      }`}
    >
      <div className="overflow-hidden">
        <div
          className={`rounded-xl border bg-cyber-panel/90 backdrop-blur-md shadow-[0_0_40px_rgba(0,0,0,0.08)] ${accentClass}`}
        >
          <div className="flex items-center justify-between border-b border-cyber-border px-5 py-3">
            <div className="flex items-center gap-2">
              <Icon className="h-4 w-4" strokeWidth={1.5} />
              <p className="font-display text-sm font-semibold tracking-wide">{title}</p>
            </div>
            <button
              type="button"
              onClick={onAdd}
              className="flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition hover:opacity-90"
            >
              <Plus className="h-3.5 w-3.5" strokeWidth={2} />
              Add
            </button>
          </div>

          <p className="border-b border-cyber-border/60 px-5 py-3 text-xs leading-relaxed text-cyber-muted">
            {description}
          </p>

          {resolved.length > 0 && (
            <div className="border-b border-cyber-border/60 px-5 py-3">
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                Saved targets ({resolved.length})
              </p>
              <div className="flex flex-wrap gap-1.5">
                {resolved.map((row) => (
                  <span
                    key={`${row.method}:${row.url}`}
                    className="rounded border border-cyber-border/60 bg-cyber-bg/40 px-2 py-0.5 text-[10px] text-white/90"
                    title={row.url}
                  >
                    {row.method} {row.label}{" "}
                    <span className="text-cyber-muted">· {shortUrl(row.url)}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="p-5">
            {endpoints.length === 0 ? (
              <button
                type="button"
                onClick={onAdd}
                className="flex w-full flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-cyber-border py-10 text-cyber-muted transition hover:border-cyber-accent/40 hover:bg-cyber-accent/5 hover:text-white"
              >
                <Plus className="h-6 w-6" strokeWidth={1.5} />
                <span className="text-xs font-medium">{emptyLabel}</span>
              </button>
            ) : (
              <div className="space-y-3">
                {endpoints.map((entry) => {
                  const saved = isTransferEndpointSaved(entry, savedSnapshot, defaultMethod);
                  const method = entry.method || defaultMethod;

                  return (
                    <div
                      key={entry.id}
                      className={`grid gap-2 rounded-lg border p-3 transition-all duration-200 sm:grid-cols-[auto_minmax(0,1.6fr)_minmax(0,0.6fr)_auto] sm:items-center sm:gap-3 ${
                        saved
                          ? "border-cyber-accent/45 bg-cyber-accent/10"
                          : "border-cyber-border bg-cyber-bg/60"
                      }`}
                    >
                      <div className="flex items-end sm:items-center">
                        <div
                          className={`flex h-6 w-6 items-center justify-center rounded border transition ${
                            saved
                              ? "border-cyber-accent bg-cyber-accent text-cyber-bg"
                              : "border-cyber-border/80 bg-cyber-panel/40 text-transparent"
                          }`}
                        >
                          <Check className="h-3.5 w-3.5" strokeWidth={2.5} />
                        </div>
                      </div>

                      <label className="block min-w-0">
                        <span className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-cyber-muted">
                          URL
                        </span>
                        <input
                          type="text"
                          value={entry.url}
                          onChange={(e) => onChange(entry.id, "url", e.target.value)}
                          placeholder={urlPlaceholder}
                          className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 font-mono text-xs text-white placeholder:text-cyber-muted/60 focus:border-cyber-accent/50 focus:outline-none"
                        />
                      </label>

                      <label className="block">
                        <span className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-cyber-muted">
                          Method
                        </span>
                        <select
                          value={method}
                          onChange={(e) => onChange(entry.id, "method", e.target.value)}
                          className="w-full rounded border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 text-xs text-white focus:border-cyber-accent/50 focus:outline-none"
                        >
                          {methodOptions.map((m) => (
                            <option key={m} value={m}>
                              {m}
                            </option>
                          ))}
                        </select>
                      </label>

                      <div className="flex items-end justify-end sm:items-center">
                        <button
                          type="button"
                          onClick={() => onRemove(entry.id)}
                          className="rounded border border-cyber-border/60 p-1.5 text-cyber-muted transition hover:border-rose-400/50 hover:bg-rose-500/10 hover:text-rose-300"
                          aria-label={`Remove ${title} entry`}
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
                  className="rounded-lg border border-cyber-accent/50 bg-cyber-accent/15 px-4 py-1.5 text-xs font-semibold text-cyber-accent transition hover:bg-cyber-accent/25 disabled:opacity-50"
                >
                  {saving ? "Saving…" : saveLabel}
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}
