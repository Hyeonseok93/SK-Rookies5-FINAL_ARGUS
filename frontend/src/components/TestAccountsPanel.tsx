import { Check, CircleAlert, Plus, Shield, Trash2 } from "lucide-react";
import type { TestAccountEntry } from "../types";

export type SavedAccountsSnapshot = Record<string, { email: string; password: string }>;

export function createEmptyAccount(): TestAccountEntry {
  return {
    id: crypto.randomUUID(),
    email: "",
    password: "",
  };
}

export function buildSavedSnapshot(accounts: TestAccountEntry[]): SavedAccountsSnapshot {
  const snap: SavedAccountsSnapshot = {};
  for (const account of accounts) {
    if (account.email.trim() || account.password) {
      snap[account.id] = { email: account.email, password: account.password };
    }
  }
  return snap;
}

export function isAccountSaved(
  account: TestAccountEntry,
  snapshot: SavedAccountsSnapshot,
): boolean {
  const saved = snapshot[account.id];
  if (!saved) return false;
  if (!account.email.trim() && !account.password) return false;
  return saved.email === account.email && saved.password === account.password;
}

interface TestAccountsPanelProps {
  open: boolean;
  accounts: TestAccountEntry[];
  savedSnapshot: SavedAccountsSnapshot;
  saving: boolean;
  saveError: string;
  onAdd: () => void;
  onChange: (id: string, field: keyof Omit<TestAccountEntry, "id">, value: string) => void;
  onRemove: (id: string) => void;
  onSave: () => void;
}

export function TestAccountsPanel({
  open,
  accounts,
  savedSnapshot,
  saving,
  saveError,
  onAdd,
  onChange,
  onRemove,
  onSave,
}: TestAccountsPanelProps) {
  const savedCount = accounts.filter((a) => isAccountSaved(a, savedSnapshot)).length;

  return (
    <div
      className={`grid transition-all duration-500 ease-out ${
        open ? "grid-rows-[1fr] opacity-100 mb-6" : "grid-rows-[0fr] opacity-0 mb-0"
      }`}
    >
      <div className="overflow-hidden">
        <div className="rounded-xl border border-violet-500/25 bg-cyber-panel/90 shadow-[0_0_40px_rgba(139,92,246,0.06)] backdrop-blur-md">
          <div className="flex items-center justify-between border-b border-cyber-border px-5 py-3">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-violet-400" strokeWidth={1.5} />
              <p className="font-display text-sm font-semibold tracking-wide text-violet-300">
                Test Accounts
              </p>
            </div>
            <button
              type="button"
              onClick={onAdd}
              className="flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-1.5 text-xs font-semibold text-violet-300 transition hover:bg-violet-500/20"
            >
              <Plus className="h-3.5 w-3.5" strokeWidth={2} />
              Add Account
            </button>
          </div>

          <p className="border-b border-cyber-border/60 px-5 py-3 text-xs leading-relaxed text-cyber-muted">
            테스트에 사용할 계정을 추가해 주세요. 저장된 계정은 이후 모든 로그인 엔드포인트에 순서대로
            시도됩니다.
          </p>

          <div className="p-5">
            {accounts.length === 0 ? (
              <button
                type="button"
                onClick={onAdd}
                className="flex w-full flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-cyber-border py-10 text-cyber-muted transition hover:border-violet-400/40 hover:bg-violet-500/5 hover:text-violet-300"
              >
                <Plus className="h-6 w-6" strokeWidth={1.5} />
                <span className="text-xs font-medium">테스트 계정 추가</span>
              </button>
            ) : (
              <div className="space-y-3">
                {accounts.map((account, index) => {
                  const saved = isAccountSaved(account, savedSnapshot);

                  return (
                    <div
                      key={account.id}
                      className={`grid gap-2 rounded-lg border p-3 transition-all duration-200 sm:grid-cols-[auto_minmax(0,1.2fr)_minmax(0,1fr)_auto] sm:items-center sm:gap-3 ${
                        saved
                          ? "border-violet-400/45 bg-violet-500/10 shadow-[inset_0_0_24px_rgba(139,92,246,0.06)]"
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
                              ? "border-violet-400 bg-violet-400 text-cyber-bg"
                              : "border-cyber-border/80 bg-cyber-panel/40 text-transparent"
                          }`}
                          title={saved ? "Saved" : "Not saved yet"}
                        >
                          {saved && <Check className="h-3.5 w-3.5" strokeWidth={3} />}
                        </div>
                      </div>
                      <div>
                        {index === 0 && (
                          <label className="mb-1 block text-[10px] uppercase tracking-wider text-cyber-muted">
                            Email
                          </label>
                        )}
                        <input
                          type="email"
                          autoComplete="off"
                          placeholder="Email"
                          value={account.email}
                          onChange={(e) => onChange(account.id, "email", e.target.value)}
                          className={`w-full rounded border px-3 py-2 text-xs text-white placeholder:text-cyber-muted focus:outline-none ${
                            saved
                              ? "border-violet-400/30 bg-cyber-panel/80 focus:border-violet-400/60"
                              : "border-cyber-border bg-cyber-panel focus:border-violet-400/50"
                          }`}
                        />
                      </div>
                      <div>
                        {index === 0 && (
                          <label className="mb-1 block text-[10px] uppercase tracking-wider text-cyber-muted">
                            Password
                          </label>
                        )}
                        <input
                          type="password"
                          autoComplete="new-password"
                          placeholder="Password"
                          value={account.password}
                          onChange={(e) => onChange(account.id, "password", e.target.value)}
                          className={`w-full rounded border px-3 py-2 text-xs text-white placeholder:text-cyber-muted focus:outline-none ${
                            saved
                              ? "border-violet-400/30 bg-cyber-panel/80 focus:border-violet-400/60"
                              : "border-cyber-border bg-cyber-panel focus:border-violet-400/50"
                          }`}
                        />
                      </div>
                      <button
                        type="button"
                        onClick={() => onRemove(account.id)}
                        className="self-end rounded-lg p-2 text-cyber-muted transition hover:bg-cyber-danger/10 hover:text-cyber-danger sm:self-center"
                        aria-label="Remove account"
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
                  <span className="text-violet-300">{savedCount} saved</span>
                  {accounts.length > savedCount && (
                    <span> · {accounts.length - savedCount} unsaved</span>
                  )}
                </span>
              ) : (
                <span>{accounts.length} account(s)</span>
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
              className="rounded-lg border border-violet-400/50 bg-violet-500/15 px-5 py-2 text-xs font-semibold text-violet-300 transition hover:bg-violet-500/25 disabled:opacity-40"
            >
              {saving ? "Saving…" : "Save Test Accounts"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
