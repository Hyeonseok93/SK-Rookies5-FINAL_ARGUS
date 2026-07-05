import { useEffect, useState } from "react";
import { Stethoscope, Upload, User, X } from "lucide-react";
import { fetchTestAccounts } from "../lib/api";
import {
  g21OptionsSummary,
  g21OptionsValid,
  type G21DiagnosisOptions,
} from "../lib/g21DiagnosisOptions";

function Field({
  label,
  hint,
  type = "text",
  value,
  onChange,
  placeholder,
  required,
}: {
  label: string;
  hint?: string;
  type?: string;
  value: string | number;
  onChange: (v: string) => void;
  placeholder?: string;
  required?: boolean;
}) {
  return (
    <label className="block">
      <span className="mb-1 flex items-center gap-1 text-[10px] font-medium text-white">
        {label}
        {required ? <span className="text-rose-400">*</span> : null}
      </span>
      {hint ? <span className="mb-1 block text-[10px] text-cyber-muted">{hint}</span> : null}
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white"
      />
    </label>
  );
}

export function G21DiagnosisStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: G21DiagnosisOptions;
  onClose: () => void;
  onStart: (options: G21DiagnosisOptions) => void;
}) {
  const [options, setOptions] = useState<G21DiagnosisOptions>(initialOptions);

  useEffect(() => {
    if (!open) return;
    setOptions(initialOptions);
    void fetchTestAccounts()
      .then((res) => {
        const accounts = res.accounts ?? [];
        if (accounts.length === 0) return;
        setOptions((prev) => ({
          ...prev,
          userEmail: prev.userEmail || accounts[0]?.email || "",
          userPassword: prev.userPassword || accounts[0]?.password || "",
          sellerEmail:
            prev.sellerEmail ||
            accounts.find((a) => /seller|car|travel|onde/i.test(a.email))?.email ||
            accounts[1]?.email ||
            accounts[0]?.email ||
            "",
          sellerPassword:
            prev.sellerPassword ||
            accounts.find((a) => /seller|car|travel|onde/i.test(a.email))?.password ||
            accounts[1]?.password ||
            accounts[0]?.password ||
            "",
        }));
      })
      .catch(() => undefined);
  }, [open, initialOptions]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const valid = g21OptionsValid(options);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" aria-hidden />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="g21-start-title"
        className="relative z-10 flex max-h-[90vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-cyber-border bg-cyber-panel shadow-2xl"
      >
        <div className="border-b border-cyber-border/40 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 id="g21-start-title" className="font-display text-base font-semibold text-white">
                2-1 악성코드 파일 업로드
              </h2>
              <p className="mt-1 text-xs text-cyber-muted">
                셀러 계정으로 숙소·렌터카 썸네일 업로드 probe (게시판은 일반 계정 선택)
              </p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="rounded p-1 text-cyber-muted transition hover:bg-cyber-border/30 hover:text-white"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <div className="rounded-xl border border-amber-400/30 bg-amber-500/5 p-3">
            <div className="mb-2 flex items-center gap-2 text-amber-200">
              <Upload className="h-4 w-4" />
              <span className="text-xs font-semibold">셀러 계정 (필수)</span>
            </div>
            <div className="space-y-3">
              <Field
                label="셀러 이메일"
                required
                value={options.sellerEmail}
                onChange={(sellerEmail) => setOptions({ ...options, sellerEmail })}
                placeholder="seller@example.com"
              />
              <Field
                label="셀러 비밀번호"
                required
                type="password"
                value={options.sellerPassword}
                onChange={(sellerPassword) => setOptions({ ...options, sellerPassword })}
              />
              <Field
                label="Seller ID"
                required
                hint="POST /seller/accommodations · /seller/cars 의 sellerId 파라미터"
                type="number"
                value={options.sellerId || ""}
                onChange={(v) =>
                  setOptions({ ...options, sellerId: Math.max(0, parseInt(v, 10) || 0) })
                }
                placeholder="예: 1"
              />
            </div>
          </div>

          <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
            <div className="mb-2 flex items-center gap-2 text-cyber-muted">
              <User className="h-4 w-4" />
              <span className="text-xs font-semibold text-white">일반 계정 (선택)</span>
            </div>
            <p className="mb-3 text-[10px] text-cyber-muted">
              게시판 POST/PUT (/api/v1/posts) probe — 비우면 숙소·렌터카만 실행
            </p>
            <div className="space-y-3">
              <Field
                label="유저 이메일"
                value={options.userEmail}
                onChange={(userEmail) => setOptions({ ...options, userEmail })}
              />
              <Field
                label="유저 비밀번호"
                type="password"
                value={options.userPassword}
                onChange={(userPassword) => setOptions({ ...options, userPassword })}
              />
            </div>
          </div>

          <Field
            label="Timeout (초)"
            type="number"
            value={String(options.timeout)}
            onChange={(v) =>
              setOptions({
                ...options,
                timeout: Math.min(60, Math.max(3, parseInt(v, 10) || 10)),
              })
            }
          />
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-cyber-border/40 bg-cyber-panel/80 px-5 py-3">
          <p className="hidden min-w-0 truncate font-mono text-[10px] text-cyan-300/70 sm:block">
            {g21OptionsSummary(options)}
          </p>
          <div className="flex shrink-0 justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-cyber-border px-3 py-2 text-xs font-medium text-cyber-muted transition hover:text-white"
            >
              취소
            </button>
            <button
              type="button"
              disabled={!valid}
              onClick={() => onStart(options)}
              className="flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Stethoscope className="h-3.5 w-3.5" />
              진단 시작
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
