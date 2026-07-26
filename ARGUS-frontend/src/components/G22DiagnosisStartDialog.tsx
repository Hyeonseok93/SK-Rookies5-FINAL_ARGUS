import { useEffect, useMemo, useState } from "react";
import { AlertCircle, Download, Gauge, Loader2, Settings2, Stethoscope, X, Zap } from "lucide-react";
import { G22DiagnosisOptionsPanel } from "./G22DiagnosisOptionsPanel";
import { fetchDownloadEndpoints } from "../lib/api";
import {
  G22_PRESET_LABELS,
  g22OptionsForPreset,
  type G22DiagnosisOptions,
  type G22DiagnosisPreset,
} from "../lib/g22DiagnosisOptions";
import type { TransferEndpointResolved } from "../types";

const TABS: { id: G22DiagnosisPreset; icon: typeof Gauge }[] = [
  { id: "registered", icon: Download },
  { id: "full", icon: Zap },
  { id: "manual", icon: Settings2 },
];

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}`;
  } catch {
    return url;
  }
}

function RegisteredEndpointsOverview({
  loading,
  resolved,
}: {
  loading: boolean;
  resolved: TransferEndpointResolved[];
}) {
  return (
    <div className="rounded-xl border border-cyan-400/30 bg-gradient-to-br from-cyan-500/10 to-transparent p-4">
      <p className="text-xs leading-relaxed text-cyber-muted">
        Attack Surface에 등록한 <strong className="text-white/90">Download Endpoints</strong>만
        점검합니다. <strong className="text-white/90">경로 조작</strong>과{" "}
        <strong className="text-white/90">비인증 다운로드</strong>만 검사합니다.
      </p>

      {loading ? (
        <div className="mt-4 flex items-center gap-2 text-xs text-cyber-muted">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          등록된 엔드포인트 불러오는 중…
        </div>
      ) : resolved.length === 0 ? (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber-400/30 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-200/90">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            등록된 다운로드 URL이 없습니다. Attack Surface → Build Attack Tree → Download
            Endpoints에서 추가한 뒤 저장하세요.
          </span>
        </div>
      ) : (
        <div className="mt-4">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
            등록된 대상 ({resolved.length})
          </p>
          <ul className="max-h-48 space-y-1.5 overflow-y-auto">
            {resolved.map((row) => (
              <li
                key={`${row.method}:${row.url}`}
                className="rounded-lg border border-cyber-border/50 bg-cyber-bg/50 px-3 py-2"
                title={row.url}
              >
                <p className="font-mono text-[11px] text-cyan-300/90">
                  <span className="text-cyber-muted">{row.method}</span> {shortUrl(row.url)}
                </p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function FullScanOverview() {
  return (
    <div className="rounded-xl border border-amber-400/30 bg-gradient-to-br from-amber-500/10 to-transparent p-4">
      <p className="text-xs leading-relaxed text-cyber-muted">
        인벤토리(<strong className="text-white/90">api-tree</strong>)에 확인된{" "}
        <strong className="text-white/90">API 전체</strong>를 대상으로 파일 다운로드·경로 조작
        취약점을 점검합니다.
      </p>
      <p className="mt-3 text-xs leading-relaxed text-cyber-muted">
        점수 필터 없이 inventory의 모든 엔드포인트를 순회하므로, 등록된 엔드포인트 진단보다{" "}
        <strong className="text-amber-200/90">시간이 크게 늘어날 수 있습니다</strong>.
      </p>
    </div>
  );
}

export function G22DiagnosisStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: G22DiagnosisOptions;
  onClose: () => void;
  onStart: (options: G22DiagnosisOptions) => void;
}) {
  const [tab, setTab] = useState<G22DiagnosisPreset>("registered");
  const [manualOptions, setManualOptions] = useState<G22DiagnosisOptions>(initialOptions);
  const [downloadResolved, setDownloadResolved] = useState<TransferEndpointResolved[]>([]);
  const [downloadLoading, setDownloadLoading] = useState(false);

  useEffect(() => {
    if (open) {
      setTab("registered");
      setManualOptions(initialOptions);
    }
  }, [open, initialOptions]);

  useEffect(() => {
    if (!open) return;
    setDownloadLoading(true);
    fetchDownloadEndpoints()
      .then((res) => setDownloadResolved(res.resolved))
      .catch(() => setDownloadResolved([]))
      .finally(() => setDownloadLoading(false));
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const activeOptions = useMemo(() => {
    if (tab === "manual") return manualOptions;
    return g22OptionsForPreset(tab);
  }, [tab, manualOptions]);

  if (!open) return null;

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
        aria-labelledby="g22-start-title"
        className="relative z-10 flex max-h-[90vh] w-full max-w-xl flex-col overflow-hidden rounded-xl border border-cyber-border bg-cyber-panel shadow-2xl"
      >
        <div className="border-b border-cyber-border/40 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 id="g22-start-title" className="font-display text-base font-semibold text-white">
                2-2 중요 정보 파일 다운로드
              </h2>
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
          <div
            className="mt-4 grid grid-cols-3 gap-1 rounded-lg border border-cyber-border/50 bg-cyber-bg/40 p-1"
            role="tablist"
          >
            {TABS.map(({ id, icon: Icon }) => {
              const active = tab === id;
              return (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setTab(id)}
                  className={`rounded-md px-2 py-2.5 text-center transition ${
                    active
                      ? "bg-cyber-panel shadow-sm ring-1 ring-cyan-400/40"
                      : "text-cyber-muted hover:text-white"
                  }`}
                >
                  <Icon className={`mx-auto mb-1 h-4 w-4 ${active ? "text-cyan-300" : "opacity-70"}`} />
                  <span className="block text-[11px] font-semibold text-white">
                    {G22_PRESET_LABELS[id]}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {tab === "registered" ? (
            <RegisteredEndpointsOverview loading={downloadLoading} resolved={downloadResolved} />
          ) : null}
          {tab === "full" ? <FullScanOverview /> : null}
          {tab === "manual" ? (
            <G22DiagnosisOptionsPanel options={manualOptions} onChange={setManualOptions} />
          ) : null}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-cyber-border/40 bg-cyber-panel/80 px-5 py-3">
          <button
            type="button"
            onClick={() => onStart(activeOptions)}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-4 py-2 text-xs font-semibold text-cyan-300 transition hover:bg-cyan-500/25"
          >
            <Stethoscope className="h-3.5 w-3.5" />
            {G22_PRESET_LABELS[tab]} 시작
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-cyber-border px-3 py-2 text-xs font-medium text-cyber-muted transition hover:text-white"
          >
            취소
          </button>
        </div>
      </div>
    </div>
  );
}
