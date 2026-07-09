import { useEffect, useState } from "react";
import { Gauge, Settings2, Stethoscope, Upload, User, X, Zap, ZapOff } from "lucide-react";
import { fetchTestAccounts } from "../lib/api";
import {
  g21OptionsSummary,
  g21OptionsValid,
  type G21DiagnosisOptions,
} from "../lib/g21DiagnosisOptions";

type G21DiagnosisPreset = "minimal" | "full" | "manual";

const TABS: { id: G21DiagnosisPreset; icon: typeof Gauge; desc: string }[] = [
  { id: "minimal", icon: ZapOff, desc: "업로드 권한 계정만 테스트" },
  { id: "full", icon: Zap, desc: "다중 계정 복합 검증" },
  { id: "manual", icon: Settings2, desc: "계정 직접 설정" },
];

const PRESET_LABELS: Record<G21DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 스캔",
  manual: "수동 입력",
};

function PresetOverview({ preset, options }: { preset: "minimal" | "full"; options: G21DiagnosisOptions }) {
  const isMinimal = preset === "minimal";
  const checks = isMinimal
    ? ["필수 셀러 계정으로만 숙소/렌터카 업로드 테스트", "timeout 10초, 기본 썸네일 검증", "테스트 계정 자동 사용"]
    : ["일반 유저 계정(게시판) 포함 복합 업로드 시도", "timeout 10초, 다양한 페이로드 검증", "테스트 계정 자동 사용"];
  return (
    <div className={`rounded-xl border p-4 ${isMinimal ? "border-cyan-400/30 bg-gradient-to-br from-cyan-500/10 to-transparent" : "border-amber-400/30 bg-gradient-to-br from-amber-500/10 to-transparent"}`}>
      <div className="mb-3 flex items-center gap-2">
        <span className={`flex h-8 w-8 items-center justify-center rounded-lg ${isMinimal ? "bg-cyan-500/20 text-cyan-300" : "bg-amber-500/20 text-amber-200"}`}>
          {isMinimal ? <Gauge className="h-4 w-4" /> : <Zap className="h-4 w-4" />}
        </span>
        <div>
          <p className="text-sm font-semibold text-white">{PRESET_LABELS[preset]}</p>
          <p className="text-[10px] text-cyber-muted">악성코드 업로드 (Verify)</p>
        </div>
      </div>
      <ul className="mb-3 space-y-1.5">
        {checks.map((line) => (
          <li key={line} className="flex items-start gap-2 text-[11px] text-cyber-muted">
            <span className={`mt-1.5 h-1 w-1 shrink-0 rounded-full ${isMinimal ? "bg-cyan-400" : "bg-amber-400"}`} />
            <span>{line}</span>
          </li>
        ))}
      </ul>
      <div className="rounded-lg border border-cyber-border/40 bg-cyber-bg/50 px-3 py-2">
        <p className="text-[10px] font-medium uppercase tracking-wider text-cyber-muted">실행 프로필</p>
        <p className="mt-1 font-mono text-[10px] leading-relaxed text-cyan-300/90">{g21OptionsSummary(options)}</p>
      </div>
    </div>
  );
}

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
  const [tab, setTab] = useState<G21DiagnosisPreset>("minimal");
  const [options, setOptions] = useState<G21DiagnosisOptions>(initialOptions);

  useEffect(() => {
    if (!open) return;
    setTab("minimal");
    setOptions(initialOptions);
    void fetchTestAccounts()
      .then((res) => {
        const accounts = res.accounts ?? [];
        if (accounts.length === 0) return;
        setOptions((prev) => ({
          ...prev,
          userEmail: prev.userEmail || "",
          userPassword: prev.userPassword || "",
          sellerEmail:
            prev.sellerEmail ||
            accounts.find((a) => /seller|air/i.test(a.email))?.email ||
            accounts[0]?.email ||
            "",
          sellerPassword:
            prev.sellerPassword ||
            accounts.find((a) => /seller|air/i.test(a.email))?.password ||
            accounts[0]?.password ||
            "",
          adminEmail:
            prev.adminEmail ||
            accounts.find((a) => /admin/i.test(a.email))?.email ||
            "",
          adminPassword:
            prev.adminPassword ||
            accounts.find((a) => /admin/i.test(a.email))?.password ||
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
        className="relative z-10 flex max-h-[90vh] w-full max-w-xl flex-col overflow-hidden rounded-xl border border-cyber-border bg-cyber-panel shadow-2xl"
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
          <div className="mt-4 grid grid-cols-3 gap-1 rounded-lg border border-cyber-border/50 bg-cyber-bg/40 p-1" role="tablist">
            {TABS.map(({ id, icon: Icon, desc }) => {
              const active = tab === id;
              return (
                <button key={id} type="button" role="tab" aria-selected={active} onClick={() => setTab(id)} className={`rounded-md px-2 py-2.5 text-center transition ${active ? "bg-cyber-panel shadow-sm ring-1 ring-cyan-400/40" : "text-cyber-muted hover:text-white"}`}>
                  <Icon className={`mx-auto mb-1 h-4 w-4 ${active ? "text-cyan-300" : "opacity-70"}`} />
                  <span className="block text-[11px] font-semibold text-white">{PRESET_LABELS[id]}</span>
                  <span className="mt-0.5 block text-[9px] leading-tight text-cyber-muted">{desc}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {tab === "minimal" ? <PresetOverview preset="minimal" options={options} /> : null}
          {tab === "full" ? <PresetOverview preset="full" options={options} /> : null}
          
          {tab === "manual" ? (
            <div className="space-y-4">
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

              <div className="rounded-xl border border-purple-500/30 bg-purple-500/5 p-3">
                <div className="mb-2 flex items-center gap-2 text-purple-300">
                  <Settings2 className="h-4 w-4" />
                  <span className="text-xs font-semibold">관리자 계정 (선택)</span>
                </div>
                <p className="mb-3 text-[10px] text-cyber-muted">
                  대시보드 이미지 업로드 probe — 비우면 관리자 항목은 스킵됨
                </p>
                <div className="space-y-3">
                  <Field
                    label="관리자 이메일"
                    value={options.adminEmail}
                    onChange={(adminEmail) => setOptions({ ...options, adminEmail })}
                  />
                  <Field
                    label="관리자 비밀번호"
                    type="password"
                    value={options.adminPassword}
                    onChange={(adminPassword) => setOptions({ ...options, adminPassword })}
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
          ) : null}
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
              onClick={() => {
                if (tab === "minimal") {
                  onStart({ ...options, userEmail: "", userPassword: "", adminEmail: "", adminPassword: "" });
                } else {
                  onStart(options);
                }
              }}
              className="flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Stethoscope className="h-3.5 w-3.5" />
              {PRESET_LABELS[tab]} 시작
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
