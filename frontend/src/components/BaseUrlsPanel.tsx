import { Check, CircleAlert, Globe2, Plus, Trash2 } from "lucide-react";

import type { BaseUrlEntry } from "../types";



export type SavedBaseUrlsSnapshot = Record<string, { url: string }>;



export function createEmptyBaseUrl(): BaseUrlEntry {

  return {

    id: crypto.randomUUID(),

    url: "",

  };

}



export function buildSavedBaseUrlsSnapshot(urls: BaseUrlEntry[]): SavedBaseUrlsSnapshot {

  const snap: SavedBaseUrlsSnapshot = {};

  for (const entry of urls) {

    if (entry.url.trim()) {

      snap[entry.id] = {

        url: normalizeUrl(entry.url),

      };

    }

  }

  return snap;

}



export function normalizeUrl(raw: string): string {

  let url = raw.trim().replace(/\/+$/, "");

  if (!url) return "";

  if (!url.startsWith("http://") && !url.startsWith("https://")) {

    url = `http://${url}`;

  }

  return url;

}



export function isBaseUrlSaved(entry: BaseUrlEntry, snapshot: SavedBaseUrlsSnapshot): boolean {

  const saved = snapshot[entry.id];

  if (!saved) return false;

  if (!entry.url.trim()) return false;

  return saved.url === normalizeUrl(entry.url);

}



interface BaseUrlsPanelProps {

  open: boolean;

  urls: BaseUrlEntry[];

  savedSnapshot: SavedBaseUrlsSnapshot;

  saving: boolean;

  saveError: string;

  onAdd: () => void;

  onChange: (id: string, value: string) => void;

  onRemove: (id: string) => void;

  onSave: () => void;

}



export function BaseUrlsPanel({

  open,

  urls,

  savedSnapshot,

  saving,

  saveError,

  onAdd,

  onChange,

  onRemove,

  onSave,

}: BaseUrlsPanelProps) {

  const savedCount = urls.filter((u) => isBaseUrlSaved(u, savedSnapshot)).length;



  return (

    <div

      className={`grid transition-all duration-500 ease-out ${

        open ? "grid-rows-[1fr] opacity-100 mb-6" : "grid-rows-[0fr] opacity-0 mb-0"

      }`}

    >

      <div className="overflow-hidden">

        <div className="rounded-xl border border-sky-500/25 bg-cyber-panel/90 shadow-[0_0_40px_rgba(56,189,248,0.06)] backdrop-blur-md">

          <div className="flex items-center justify-between border-b border-cyber-border px-5 py-3">

            <div className="flex items-center gap-2">

              <Globe2 className="h-4 w-4 text-sky-400" strokeWidth={1.5} />

              <p className="font-display text-sm font-semibold tracking-wide text-sky-300">

                Base URLs

              </p>

            </div>

            <button

              type="button"

              onClick={onAdd}

              className="flex items-center gap-1.5 rounded-lg border border-sky-400/40 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-300 transition hover:bg-sky-500/20"

            >

              <Plus className="h-3.5 w-3.5" strokeWidth={2} />

              Add URL

            </button>

          </div>



          <p className="border-b border-cyber-border/60 px-5 py-3 text-xs leading-relaxed text-cyber-muted">

            스캔·진단 대상 API/웹 베이스 URL을 등록하세요. 로그인 API는 인벤토리(api-tree)에서

            자동 탐지됩니다.

          </p>



          <div className="p-5">

            {urls.length === 0 ? (

              <button

                type="button"

                onClick={onAdd}

                className="flex w-full flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-cyber-border py-10 text-cyber-muted transition hover:border-sky-400/40 hover:bg-sky-500/5 hover:text-sky-300"

              >

                <Plus className="h-6 w-6" strokeWidth={1.5} />

                <span className="text-xs font-medium">Base URL 추가</span>

              </button>

            ) : (

              <div className="space-y-3">

                {urls.map((entry, index) => {

                  const saved = isBaseUrlSaved(entry, savedSnapshot);



                  return (

                    <div

                      key={entry.id}

                      className={`grid gap-2 rounded-lg border p-3 transition-all duration-200 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:items-center sm:gap-3 ${

                        saved

                          ? "border-sky-400/45 bg-sky-500/10 shadow-[inset_0_0_24px_rgba(56,189,248,0.06)]"

                          : "border-cyber-border bg-cyber-bg/60"

                      }`}

                    >

                      <div className="flex items-end sm:items-center sm:self-center">

                        {index === 0 && (

                          <span className="mb-1 block text-[10px] uppercase tracking-wider text-transparent sm:hidden">

                            —

                          </span>

                        )}

                        <div

                          className={`flex h-6 w-6 items-center justify-center rounded border transition ${

                            saved

                              ? "border-sky-400 bg-sky-400 text-cyber-bg"

                              : "border-cyber-border/80 bg-cyber-panel/40 text-transparent"

                          }`}

                        >

                          {saved && <Check className="h-3.5 w-3.5" strokeWidth={3} />}

                        </div>

                      </div>

                      <div>

                        {index === 0 && (

                          <label className="mb-1 block text-[10px] uppercase tracking-wider text-cyber-muted">

                            Base URL

                          </label>

                        )}

                        <input

                          type="url"

                          autoComplete="off"

                          placeholder="http://localhost:8080"

                          value={entry.url}

                          onChange={(e) => onChange(entry.id, e.target.value)}

                          className={`w-full rounded border px-3 py-2 text-xs text-white placeholder:text-cyber-muted focus:outline-none ${

                            saved

                              ? "border-sky-400/30 bg-cyber-panel/80 focus:border-sky-400/60"

                              : "border-cyber-border bg-cyber-panel focus:border-sky-400/50"

                          }`}

                        />

                      </div>

                      <button

                        type="button"

                        onClick={() => onRemove(entry.id)}

                        className="self-start rounded-lg p-2 text-cyber-muted transition hover:bg-cyber-danger/10 hover:text-cyber-danger sm:self-center"

                        aria-label="Remove base URL"

                      >

                        <Trash2 className="h-4 w-4" strokeWidth={1.5} />

                      </button>

                    </div>

                  );

                })}

              </div>

            )}

          </div>



          <div className="flex items-center justify-between gap-2 border-t border-cyber-border px-5 py-3">

            <div className="text-xs text-cyber-muted">

              {savedCount > 0 ? (

                <span>

                  <span className="text-sky-300">{savedCount} saved</span>

                  {urls.length > savedCount && (

                    <span> · {urls.length - savedCount} unsaved</span>

                  )}

                </span>

              ) : (

                <span>{urls.length} URL(s)</span>

              )}

              {saveError && (

                <span className="mt-1 flex items-center gap-1 text-cyber-danger">

                  <CircleAlert className="inline h-3 w-3" strokeWidth={2} />

                  {saveError}

                </span>

              )}

            </div>

            <button

              type="button"

              onClick={onSave}

              disabled={saving}

              className="rounded-lg border border-sky-400/50 bg-sky-500/15 px-5 py-2 text-xs font-semibold text-sky-300 transition hover:bg-sky-500/25 disabled:opacity-40"

            >

              {saving ? "Saving…" : "Save Base URLs"}

            </button>

          </div>

        </div>

      </div>

    </div>

  );

}

