import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertCircle, ChevronDown, Loader2, Stethoscope } from "lucide-react";
import { G32DiagnosisStartDialog } from "./G32DiagnosisStartDialog";
import { G35DiagnosisStartDialog } from "./G35DiagnosisStartDialog";
import { G36DiagnosisStartDialog } from "./G36DiagnosisStartDialog";
import { G15DiagnosisStartDialog } from "./G15DiagnosisStartDialog";
import { G41DiagnosisStartDialog } from "./G41DiagnosisStartDialog";
import { G52DiagnosisStartDialog } from "./G52DiagnosisStartDialog";
import { G61DiagnosisStartDialog } from "./G61DiagnosisStartDialog";
import { G62DiagnosisStartDialog } from "./G62DiagnosisStartDialog";
import { G71DiagnosisStartDialog } from "./G71DiagnosisStartDialog";
import { G22DiagnosisStartDialog } from "./G22DiagnosisStartDialog";
import { G72DiagnosisStartDialog } from "./G72DiagnosisStartDialog";
import { G73DiagnosisStartDialog } from "./G73DiagnosisStartDialog";
import { G74DiagnosisStartDialog } from "./G74DiagnosisStartDialog";
import { fetchDiagnosisCatalog, fetchDiagnosisProgress, fetchDiagnosisReport, runDiagnosisSection } from "../lib/api";
import {
  DEFAULT_G15_OPTIONS,
  g15OptionsSummary,
  g15OptionsToPayload,
  type G15DiagnosisOptions,
} from "../lib/g15DiagnosisOptions";
import {
  DEFAULT_G41_OPTIONS,
  g41OptionsSummary,
  g41OptionsToPayload,
  type G41DiagnosisOptions,
} from "../lib/g41DiagnosisOptions";
import {
  DEFAULT_G22_OPTIONS,
  g22OptionsToPayload,
  type G22DiagnosisOptions,
} from "../lib/g22DiagnosisOptions";
import {
  DEFAULT_G52_OPTIONS,
  g52OptionsToPayload,
  g52OptionsSummary,
  type G52DiagnosisOptions,
} from "../lib/g52DiagnosisOptions";
import {
  DEFAULT_G61_OPTIONS,
  g61OptionsToPayload,
  g61OptionsSummary,
  type G61DiagnosisOptions,
} from "../lib/g61DiagnosisOptions";
import {
  DEFAULT_G62_OPTIONS,
  g62OptionsToPayload,
  g62OptionsSummary,
  type G62DiagnosisOptions,
} from "../lib/g62DiagnosisOptions";
import {
  DEFAULT_G32_OPTIONS,
  g32OptionsToPayload,
  g32OptionsSummary,
  type G32DiagnosisOptions,
} from "../lib/g32DiagnosisOptions";
import {
  DEFAULT_G35_OPTIONS,
  g35OptionsToPayload,
  g35OptionsSummary,
  type G35DiagnosisOptions,
} from "../lib/g35DiagnosisOptions";
import {
  DEFAULT_G36_OPTIONS,
  g36OptionsToPayload,
  g36OptionsSummary,
  type G36DiagnosisOptions,
} from "../lib/g36DiagnosisOptions";
import {
  DEFAULT_G72_OPTIONS,
  g72OptionsToPayload,
  g72OptionsSummary,
  type G72DiagnosisOptions,
} from "../lib/g72DiagnosisOptions";
import {
  DEFAULT_G71_OPTIONS,
  g71OptionsToPayload,
  g71OptionsSummary,
  type G71DiagnosisOptions,
} from "../lib/g71DiagnosisOptions";
import {
  DEFAULT_G73_OPTIONS,
  g73OptionsToPayload,
  g73OptionsSummary,
  type G73DiagnosisOptions,
} from "../lib/g73DiagnosisOptions";
import {
  DEFAULT_G74_OPTIONS,
  g74OptionsToPayload,
  g74OptionsSummary,
  type G74DiagnosisOptions,
} from "../lib/g74DiagnosisOptions";
import { GUIDELINE_SECTIONS } from "../lib/guidelineSections";
import type { DiagnosisCatalogModule, DiagnosisProgressResponse, DiagnosisSectionReport } from "../types";

const START_BTN =
  "flex shrink-0 items-center gap-1 rounded-lg border font-semibold transition disabled:cursor-not-allowed disabled:opacity-40";

const START_BTN_ACTIVE =
  "border-cyan-400/50 bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25";

const START_BTN_IDLE =
  "border-cyber-border/60 bg-cyber-bg/40 text-cyber-muted hover:border-cyber-border hover:text-cyber-muted";

const UNAVAILABLE_BTN =
  "border-amber-400/50 bg-amber-500/15 text-amber-300 cursor-not-allowed";

const STATUS_STYLES: Record<string, string> = {
  pass: "border-emerald-400/50 bg-emerald-500/10 text-emerald-300",
  warn: "border-amber-400/50 bg-amber-500/10 text-amber-300",
  warning: "border-amber-400/50 bg-amber-500/10 text-amber-300",
  fail: "border-rose-400/50 bg-rose-500/10 text-rose-300",
  error: "border-rose-400/50 bg-rose-500/10 text-rose-300",
  skipped: "border-amber-400/40 bg-amber-500/5 text-amber-200/80",
  not_implemented: "border-cyber-border/60 bg-cyber-bg/40 text-cyber-muted",
  not_diagnosable: "border-amber-400/50 bg-amber-500/10 text-amber-300",
  pending: "border-cyber-border/60 bg-cyber-bg/40 text-cyber-muted",
  no_targets: "border-amber-400/40 bg-amber-500/5 text-amber-200/80",
};

const SEVERITY_STYLES: Record<string, string> = {
  high: "text-rose-300",
  medium: "text-amber-300",
  low: "text-sky-300",
  info: "text-cyber-muted",
};

function DiagnosisStartButton({
  compact = false,
  disabled,
  loading,
  implemented,
  onClick,
}: {
  compact?: boolean;
  disabled?: boolean;
  loading?: boolean;
  implemented?: boolean;
  onClick?: () => void;
}) {
  const style = implemented ? START_BTN_ACTIVE : START_BTN_IDLE;
  return (
    <button
      type="button"
      disabled={disabled || loading}
      onClick={onClick}
      title={
        !implemented
          ? "아직 구현되지 않은 항목입니다"
          : loading
            ? "진단 실행 중…"
            : "이 항목 진단 시작"
      }
      className={`${START_BTN} ${style} ${compact ? "px-2.5 py-1 text-[10px]" : "px-4 py-1.5 text-xs"}`}
    >
      {loading ? (
        <Loader2 className={`animate-spin ${compact ? "h-3 w-3" : "h-3.5 w-3.5"}`} />
      ) : (
        <Stethoscope className={compact ? "h-3 w-3" : "h-3.5 w-3.5"} />
      )}
      {loading ? "실행 중…" : "진단 시작"}
    </button>
  );
}

function DiagnosisReviewLaterButton({ compact = false }: { compact?: boolean }) {
  return (
    <button
      type="button"
      disabled
      title="추후 검토 항목"
      className={`${START_BTN} ${UNAVAILABLE_BTN} ${compact ? "px-2.5 py-1 text-[10px]" : "px-4 py-1.5 text-xs"}`}
    >
      <AlertCircle className={compact ? "h-3 w-3" : "h-3.5 w-3.5"} />
      추후 검토
    </button>
  );
}

function DiagnosisManualCheckButton({
  label,
  compact = false,
}: {
  label: string;
  compact?: boolean;
}) {
  return (
    <button
      type="button"
      disabled
      title={label}
      className={`${START_BTN} ${UNAVAILABLE_BTN} ${compact ? "px-2.5 py-1 text-[10px]" : "px-4 py-1.5 text-xs"}`}
    >
      <AlertCircle className={compact ? "h-3 w-3" : "h-3.5 w-3.5"} />
      {label}
    </button>
  );
}

function moduleBadgeLabel(mod: {
  implemented: boolean;
  diagnosable: boolean;
  review_later: boolean;
  status_label: string | null;
  engine: string;
}): string | null {
  if (mod.implemented) return mod.engine;
  if (mod.status_label || mod.review_later) return null;
  if (!mod.diagnosable) return "미구현";
  return mod.engine !== "pending" ? mod.engine : "미구현";
}

function FindingEvidence({ evidence }: { evidence: Record<string, unknown> }) {
  const rows: { label: string; value: string }[] = [];
  const add = (label: string, key: string) => {
    const v = evidence[key];
    if (v !== undefined && v !== null && v !== "") {
      rows.push({ label, value: String(v) });
    }
  };

  add("Login URL", "login_url");
  add("Login label", "login_label");
  add("Probe mode", "probe_mode");
  add("Reason", "reason");
  add("Remediation", "remediation");

  const scenarioA = evidence.scenario_a as Record<string, unknown> | undefined;
  if (scenarioA) {
    const msg = scenarioA.primary_message ?? scenarioA.body_preview ?? "";
    rows.push({
      label: "A · exists + wrong PW",
      value: `${scenarioA.http_status ?? "—"} · ${scenarioA.email ?? ""} · ${String(msg).slice(0, 160)}`,
    });
  }
  const scenarioB = evidence.scenario_b as Record<string, unknown> | undefined;
  if (scenarioB) {
    const msg = scenarioB.primary_message ?? scenarioB.body_preview ?? "";
    rows.push({
      label: "B · missing + wrong PW",
      value: `${scenarioB.http_status ?? "—"} · ${scenarioB.email ?? ""} · ${String(msg).slice(0, 160)}`,
    });
  }
  const scenarioC = evidence.scenario_c as Record<string, unknown> | undefined;
  if (scenarioC) {
    const msg = scenarioC.primary_message ?? scenarioC.body_preview ?? "";
    rows.push({
      label: "C · missing + valid PW",
      value: `${scenarioC.http_status ?? "—"} · ${scenarioC.email ?? ""} · ${String(msg).slice(0, 160)}`,
    });
  }
  const diffs = evidence.differences;
  if (Array.isArray(diffs) && diffs.length > 0) {
    rows.push({ label: "Differences", value: diffs.map(String).join(" · ") });
  }

  add("Classification", "classification");
  add("Trigger", "trigger_label");
  add("Trigger code", "trigger");
  add("Rule", "rule_id");
  add("Category", "category");
  add("Direction", "direction");
  add("Field", "field_path");
  add("Sample", "sample");
  add("Param", "param");
  add("Param in", "param_in");
  add("Payload", "payload");
  add("Payloads tried", "payloads_tried_count");
  add("HTTP", "http_status");
  add("Baseline HTTP", "baseline_http_status");
  add("Baseline SHA256", "baseline_sha256");
  add("Response SHA256", "response_sha256");
  add("Same body as baseline", "bodies_identical");
  add("Payload leak confirmed", "payload_leak_confirmed");
  add("PDF text overlap", "pdf_text_overlap");
  add("Extracted text preview", "extracted_text_preview");
  add("Content-Type", "content_type");
  add("Content-Disposition", "content_disposition");
  add("Baseline attachment", "baseline_attachment");
  add("Listing type", "listing_type");
  add("Matched patterns", "matched_patterns");
  add("File links", "file_link_count");
  add("Body preview", "body_preview");
  add("Anonymous HTTP", "anonymous_http_status");
  add("Authenticated HTTP", "authenticated_http_status");
  add("Account", "account_email");
  add("Auth comparison", "auth_comparison");
  add("URL", "url");
  add("Base URL", "base_url");
  add("Header", "header");
  add("Header value", "header_value");
  add("Affected count", "affected_count");
  add("ZAP plugin", "plugin_id");

  const patterns = evidence.matched_patterns;
  if (Array.isArray(patterns) && patterns.length > 0) {
    rows.push({ label: "Patterns", value: patterns.map(String).join(", ") });
  }
  const affected = evidence.affected_urls;
  if (Array.isArray(affected) && affected.length > 1) {
    const preview = affected
      .slice(0, 8)
      .map(String)
      .join(", ");
    rows.push({
      label: "Affected URLs",
      value: affected.length > 8 ? `${preview}, … (+${affected.length - 8})` : preview,
    });
  }

  const tried = evidence.payloads_tried;
  if (Array.isArray(tried) && tried.length > 0) {
    const summary = tried
      .slice(0, 12)
      .map((t) => {
        const row = t as Record<string, unknown>;
        const cat = row.category ?? "?";
        const p = row.payload ?? "";
        return `${p} → ${cat}`;
      })
      .join("; ");
    rows.push({
      label: "Payload results",
      value: tried.length > 12 ? `${summary}; … (+${tried.length - 12})` : summary,
    });
  }

  if (rows.length === 0) return null;

  const leak = evidence.payload_leak_markers;
  if (Array.isArray(leak) && leak.length > 0) {
    rows.push({ label: "Payload leak markers", value: leak.map(String).join("; ") });
  }
  const sensitive = evidence.sensitive_markers;
  if (Array.isArray(sensitive) && sensitive.length > 0) {
    rows.push({ label: "Sensitive markers", value: sensitive.map(String).join("; ") });
  }

  return (
    <dl className="mt-2 space-y-1 border-t border-cyber-border/20 pt-2 text-[10px]">
      {rows.map(({ label, value }) => (
        <div key={label} className="grid grid-cols-[7rem_1fr] gap-2">
          <dt className="text-cyber-muted">{label}</dt>
          <dd className="break-all font-mono text-cyan-300/80">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_STYLES[status] ?? STATUS_STYLES.pending;
  return (
    <span className={`shrink-0 rounded border px-2 py-0.5 font-mono text-[10px] uppercase ${cls}`}>
      {status}
    </span>
  );
}

function FindingListItem({
  f,
}: {
  f: { severity: string; message: string; evidence?: Record<string, unknown> };
}) {
  return (
    <li className="rounded border border-cyber-border/30 bg-cyber-panel/30 px-3 py-2">
      <div className="flex items-start gap-2">
        <span
          className={`shrink-0 font-mono text-[10px] uppercase ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info}`}
        >
          {f.severity}
        </span>
        <span className="text-xs text-white/90">{f.message}</span>
      </div>
      {f.evidence && Object.keys(f.evidence).length > 0 ? (
        <FindingEvidence evidence={f.evidence} />
      ) : null}
    </li>
  );
}

function findingBucket(f: {
  severity: string;
  evidence?: Record<string, unknown>;
}): "httpx" | "zap" | "info" | "inventory" | "other" {
  if (f.severity === "info") return "info";
  const ev = f.evidence;
  if (ev?.rule_id === "2-2-design") return "info";
  const engine = String(ev?.engine ?? ev?.source ?? "");
  if (engine === "inventory") return "inventory";
  if (engine === "httpx") return "httpx";
  if (engine === "zap") return "zap";
  return "other";
}

function CollapsibleFindingsSection({
  title,
  subtitle,
  count,
  defaultOpen,
  findings,
}: {
  title: string;
  subtitle?: string;
  count: number;
  defaultOpen: boolean;
  findings: { severity: string; message: string; evidence?: Record<string, unknown> }[];
}) {
  const [open, setOpen] = useState(defaultOpen);
  if (count === 0) return null;

  return (
    <div className="mb-3 overflow-hidden rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition hover:bg-cyber-accent/5"
      >
        <ChevronDown className={`h-4 w-4 shrink-0 text-cyber-muted transition ${open ? "rotate-180" : ""}`} />
        <span className="text-xs font-semibold text-white">{title}</span>
        <span className="font-mono text-[10px] text-cyan-300/90">{count}</span>
        {subtitle ? <span className="ml-1 text-[10px] text-cyber-muted">{subtitle}</span> : null}
      </button>
      {open ? (
        <ul className="space-y-2 border-t border-cyber-border/30 px-3 py-2">
          {findings.map((f, i) => (
            <FindingListItem key={`${title}-${f.severity}-${i}`} f={f} />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function GroupedFindingsPanel({
  findings,
  sectionId,
}: {
  findings: { severity: string; message: string; evidence?: Record<string, unknown> }[];
  sectionId: string;
}) {
  const httpx = findings.filter((f) => findingBucket(f) === "httpx");
  const zap = findings.filter((f) => findingBucket(f) === "zap");
  const inventory = findings.filter((f) => findingBucket(f) === "inventory");
  const info = findings.filter((f) => findingBucket(f) === "info");
  const other = findings.filter((f) => findingBucket(f) === "other");

  if (findings.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  const httpxSubtitle =
    sectionId === "2-2" ? "· ARGUS 통합 로직 (본진)" : "· httpx probe";
  const zapSubtitle =
    sectionId === "2-2" ? "· unified + native supplemental" : "· ZAP scan";

  return (
    <>
      <CollapsibleFindingsSection
        title="httpx"
        subtitle={httpxSubtitle}
        count={httpx.length}
        defaultOpen={false}
        findings={httpx}
      />
      <CollapsibleFindingsSection
        title="ZAP"
        subtitle={zapSubtitle}
        count={zap.length}
        defaultOpen={false}
        findings={zap}
      />
      <CollapsibleFindingsSection
        title="inventory"
        subtitle="· api-tree + login report 분석"
        count={inventory.length}
        defaultOpen={sectionId === "3-4"}
        findings={inventory}
      />
      <CollapsibleFindingsSection
        title="info"
        count={info.length}
        defaultOpen={sectionId === "3-4"}
        findings={info}
      />
      {other.length > 0 ? (
        <CollapsibleFindingsSection
          title="기타"
          count={other.length}
          defaultOpen={false}
          findings={other}
        />
      ) : null}
    </>
  );
}

function ZapStatsLine({ zap }: { zap: unknown }) {
  if (!zap) return null;
  const z = zap as {
    error?: string;
    alerts?: number;
    unified_findings?: number;
    native_findings?: number;
    findings?: number;
  };
  const unified =
    typeof z.unified_findings === "number" ? ` · unified ${z.unified_findings}` : "";
  const native = typeof z.native_findings === "number" ? ` · native ${z.native_findings}` : "";
  const total = typeof z.findings === "number" ? z.findings : z.alerts;
  return (
    <>
      {" · ZAP "}
      {typeof z.error === "string"
        ? `(스킵: ${z.error})`
        : `완료 · findings ${String(total ?? 0)}${unified}${native}`}
    </>
  );
}

function ReportPanel({ report }: { report: DiagnosisSectionReport }) {
  const statsMessages = new Set([
    "1-5 scan statistics",
    "4-1 scan statistics",
    "4-2 scan statistics",
    "2-2 scan statistics",
    "3-2 scan statistics",
    "3-4 scan statistics",
    "3-5 scan statistics",
    "3-6 scan statistics",
    "5-2 scan statistics",
    "6-1 scan statistics",
    "6-2 scan statistics",
    "7-1 scan statistics",
    "7-2 scan statistics",
    "7-3 scan statistics",
    "7-4 scan statistics",
  ]);
  const findings = report.findings.filter((f) => !statsMessages.has(f.message));
  const statsFinding = report.findings.find((f) => statsMessages.has(f.message));
  const stats = statsFinding?.evidence?.stats as Record<string, unknown> | undefined;
  const isG15Stats = statsFinding?.message === "1-5 scan statistics";
  const isG41Stats = statsFinding?.message === "4-1 scan statistics";
  const isG42Stats = statsFinding?.message === "4-2 scan statistics";
  const isG22Stats = statsFinding?.message === "2-2 scan statistics";
  const isG71Stats = statsFinding?.message === "7-1 scan statistics";
  const isG72Stats = statsFinding?.message === "7-2 scan statistics";
  const isG73Stats = statsFinding?.message === "7-3 scan statistics";
  const isG74Stats = statsFinding?.message === "7-4 scan statistics";
  const isG52Stats = statsFinding?.message === "5-2 scan statistics";
  const isG61Stats = statsFinding?.message === "6-1 scan statistics";
  const isG62Stats = statsFinding?.message === "6-2 scan statistics";
  const isG32Stats = statsFinding?.message === "3-2 scan statistics";
  const isG34Stats = statsFinding?.message === "3-4 scan statistics";
  const isG35Stats = statsFinding?.message === "3-5 scan statistics";
  const isG36Stats = statsFinding?.message === "3-6 scan statistics";

  return (
    <div className="border-t border-cyber-border/40 bg-cyber-bg/30 px-4 py-3">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <StatusBadge status={report.status} />
        {report.checked_at ? (
          <span className="text-[10px] text-cyber-muted">{report.checked_at}</span>
        ) : null}
        {report.message ? (
          <span className="text-xs text-cyber-muted">{report.message}</span>
        ) : null}
      </div>

      {stats ? (
        <div className="mb-3 rounded border border-cyber-border/40 bg-cyber-panel/40 px-3 py-2 text-[11px] text-cyber-muted">
          {isG15Stats ? (
            <>
              sink{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.sink_base ?? "—")}</span>
              {" · mode "}
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {typeof stats.phase_a_jobs === "number" ? (
                <span> · phase A {stats.phase_a_jobs}</span>
              ) : null}
              {typeof stats.phase_b_jobs === "number" ? (
                <span> · phase B {stats.phase_b_jobs}</span>
              ) : null}
              {typeof (stats.redirect as { open_redirects?: number })?.open_redirects === "number" &&
              (stats.redirect as { open_redirects?: number }).open_redirects! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · open redirect {(stats.redirect as { open_redirects?: number }).open_redirects}
                </span>
              ) : null}
              {typeof (stats.cors as { issues?: number })?.issues === "number" &&
              (stats.cors as { issues?: number }).issues! > 0 ? (
                <span className="text-amber-300/90">
                  {" "}
                  · CORS {(stats.cors as { issues?: number }).issues}
                </span>
              ) : null}
            </>
          ) : null}
          {isG41Stats ? (
            <>
              sessions{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.sessions ?? "—")}</span>
              {" · mode "}
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {typeof stats.endpoints === "number" ? (
                <span> · endpoints {stats.endpoints}</span>
              ) : null}
              {Array.isArray(stats.session_emails) && stats.session_emails.length > 0 ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · accounts {stats.session_emails.length}
                </span>
              ) : null}
              {typeof stats.auth_source === "string" ? (
                <span className="text-cyan-300/80"> · auth {stats.auth_source}</span>
              ) : null}
              {typeof (stats.cookie_attr as { issues?: number })?.issues === "number" ? (
                <span>
                  {" "}
                  · cookie flags {(stats.cookie_attr as { issues?: number }).issues}
                  {typeof (stats.cookie_attr as { from_cache?: number })?.from_cache === "number" &&
                  (stats.cookie_attr as { from_cache?: number }).from_cache! > 0 ? (
                    <span className="text-cyan-300/80">
                      {" "}
                      (cache {(stats.cookie_attr as { from_cache?: number }).from_cache})
                    </span>
                  ) : null}
                </span>
              ) : null}
              {typeof (stats.cross_cookie as { cross_accepted?: number })?.cross_accepted ===
                "number" &&
              (stats.cross_cookie as { cross_accepted?: number }).cross_accepted! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · cross {(stats.cross_cookie as { cross_accepted?: number }).cross_accepted}
                </span>
              ) : null}
              {typeof (stats.tamper as { tamper_accepted?: number })?.tamper_accepted === "number" &&
              (stats.tamper as { tamper_accepted?: number }).tamper_accepted! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · tamper {(stats.tamper as { tamper_accepted?: number }).tamper_accepted}
                </span>
              ) : null}
              {typeof (stats.by_severity as { high?: number })?.high === "number" &&
              (stats.by_severity as { high?: number }).high! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · high {(stats.by_severity as { high?: number }).high}
                </span>
              ) : null}
            </>
          ) : null}
          {isG42Stats ? (
            <>
              sessions{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.sessions ?? "—")}</span>
              {typeof stats.auth_source === "string" ? (
                <span className="text-cyan-300/80"> · auth {stats.auth_source}</span>
              ) : null}
              {typeof (stats.token_analysis as { tokens_analyzed?: number })?.tokens_analyzed ===
              "number" ? (
                <span>
                  {" "}
                  · tokens analyzed{" "}
                  {(stats.token_analysis as { tokens_analyzed?: number }).tokens_analyzed}
                </span>
              ) : null}
              {typeof (stats.by_severity as { high?: number })?.high === "number" &&
              (stats.by_severity as { high?: number }).high! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · high {(stats.by_severity as { high?: number }).high}
                </span>
              ) : null}
              {typeof (stats.by_severity as { medium?: number })?.medium === "number" &&
              (stats.by_severity as { medium?: number }).medium! > 0 ? (
                <span className="text-amber-300/90">
                  {" "}
                  · medium {(stats.by_severity as { medium?: number }).medium}
                </span>
              ) : null}
              {typeof stats.client_logout_findings === "number" ? (
                <span> · client logout findings {stats.client_logout_findings}</span>
              ) : null}
              {stats.auth_logout_gap ? (
                <span className="text-amber-300/80"> · no server logout API</span>
              ) : null}
              {typeof stats.duplicate_login_ip_findings === "number" ? (
                <span> · cross-IP login {stats.duplicate_login_ip_findings}</span>
              ) : null}
            </>
          ) : null}
          {isG22Stats ? (
            <>
              대상{" "}
              <span className="font-mono text-cyan-300/90">
                {String((stats.candidates as { total?: number })?.total ?? "—")}
              </span>
              {stats.selection_mode === "all_inventory" ? (
                <span className="text-amber-300/90"> · api-tree 전체</span>
              ) : (
                <span> · 2-2 후보 상위</span>
              )}
              {typeof stats.inventory_endpoints === "number" ? (
                <span> / inventory {stats.inventory_endpoints}</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              {typeof stats.httpx_findings === "number" ? (
                <span> · httpx finding {stats.httpx_findings}</span>
              ) : null}
              <ZapStatsLine zap={stats.zap} />
              {typeof stats.zap_findings === "number" && stats.zap_findings > 0 ? (
                <span> · zap finding {stats.zap_findings}</span>
              ) : null}
            </>
          ) : null}
          {isG72Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · "}
              probe{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.wordlist_paths === "number" ? (
                <span> · wordlist {stats.wordlist_paths}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span> · unique finding {stats.collapsed_issues}</span>
              ) : null}
              {typeof stats.raw_issues === "number" &&
              typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted"> (raw {stats.raw_issues} → deduped)</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG71Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · "}
              probe{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.targets === "number" ? (
                <span> / URL {stats.targets}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span> · unique finding {stats.collapsed_issues}</span>
              ) : typeof stats.issues === "number" ? (
                <span> · finding {stats.issues}</span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted">
                  {" "}
                  (raw {stats.raw_issues} → deduped)
                </span>
              ) : null}
              {typeof stats.unreachable === "number" && stats.unreachable > 0 ? (
                <span className="text-amber-300/90"> · unreachable {stats.unreachable}</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.strict_risky ? (
                <span className="text-rose-300/80"> · strict risky</span>
              ) : (
                <span> · TRACE/TRACK only</span>
              )}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음 (base만)</span>
              ) : null}
            </>
          ) : null}
          {isG73Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · "}
              probe{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.targets === "number" ? (
                <span> / URL {stats.targets}</span>
              ) : null}
              {typeof stats.inventory_endpoints === "number" && stats.inventory_endpoints > 0 ? (
                <span> · inventory {stats.inventory_endpoints}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span> · unique finding {stats.collapsed_issues}</span>
              ) : typeof stats.issues === "number" ? (
                <span> · finding {stats.issues}</span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted">
                  {" "}
                  (raw {stats.raw_issues} → deduped)
                </span>
              ) : null}
              {typeof stats.unreachable === "number" && stats.unreachable > 0 ? (
                <span className="text-amber-300/90"> · unreachable {stats.unreachable}</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.strict ? (
                <span className="text-rose-300/80"> · strict</span>
              ) : (
                <span> · standard</span>
              )}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음 (base만)</span>
              ) : null}
            </>
          ) : null}
          {isG74Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · "}
              probe{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.targets === "number" ? (
                <span> / URL {stats.targets}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span> · unique finding {stats.collapsed_issues}</span>
              ) : typeof stats.issues === "number" ? (
                <span> · finding {stats.issues}</span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted">
                  {" "}
                  (raw {stats.raw_issues} → deduped)
                </span>
              ) : null}
              {typeof stats.unreachable === "number" && stats.unreachable > 0 ? (
                <span className="text-amber-300/90"> · unreachable {stats.unreachable}</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.strict ? (
                <span className="text-rose-300/80"> · strict</span>
              ) : (
                <span> · standard</span>
              )}
              {stats.check_cookies === false ? (
                <span> · cookies off</span>
              ) : (
                <span> · cookies</span>
              )}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음 (base만)</span>
              ) : null}
            </>
          ) : null}
          {isG32Stats ? (
            <>
              login entries{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.login_entries ?? "—")}</span>
              {" · attempts "}
              <span className="font-mono text-cyan-300/90">{String(stats.max_attempts ?? "—")}</span>
              {typeof stats.limit_detected === "number" ? (
                <span className="text-emerald-300/90"> · limit ok {stats.limit_detected}</span>
              ) : null}
              {typeof stats.no_limit === "number" && stats.no_limit > 0 ? (
                <span className="text-rose-300/90"> · no limit {stats.no_limit}</span>
              ) : null}
              {stats.strict ? (
                <span className="text-rose-300/80"> · strict</span>
              ) : (
                <span> · standard</span>
              )}
            </>
          ) : null}
          {isG34Stats ? (
            <>
              login{" "}
              <span className="font-mono text-cyan-300/90">
                user {String(stats.user_login_entries ?? "—")} / admin {String(stats.admin_login_entries ?? "—")}
              </span>
              {" · admin UI "}
              <span className="font-mono text-cyan-300/90">{String(stats.admin_frontend_paths ?? "—")}</span>
              {" · admin API "}
              <span className="font-mono text-cyan-300/90">{String(stats.admin_api_paths ?? "—")}</span>
              {typeof (stats.by_severity as { medium?: number })?.medium === "number" &&
              (stats.by_severity as { medium?: number }).medium! > 0 ? (
                <span className="text-amber-300/90">
                  {" "}
                  · medium {(stats.by_severity as { medium?: number }).medium}
                </span>
              ) : null}
              {Array.isArray(stats.admin_subdomain_pairs) && stats.admin_subdomain_pairs.length > 0 ? (
                <span className="text-emerald-300/90"> · subdomain 분리</span>
              ) : null}
              {typeof stats.guessable_paths === "number" && stats.guessable_paths > 0 ? (
                <span> · guessable path {stats.guessable_paths}</span>
              ) : null}
            </>
          ) : null}
          {isG35Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {" · robots "}
              <span className="font-mono text-cyan-300/90">
                {String((stats.robots as { robots_probed?: number })?.robots_probed ?? "—")}
              </span>
              {" · pages "}
              <span className="font-mono text-cyan-300/90">
                {String(
                  (stats.pages_anonymous as { pages_probed?: number })?.pages_probed ??
                    (stats.pages as { pages_probed?: number })?.pages_probed ??
                    "—",
                )}
              </span>
              {typeof (stats.pages_anonymous as { with_noindex?: number })?.with_noindex === "number" ? (
                <span className="text-emerald-300/90">
                  {" "}
                  · anon noindex {(stats.pages_anonymous as { with_noindex?: number }).with_noindex}
                </span>
              ) : null}
              {typeof (stats.pages_authenticated as { with_noindex?: number })?.with_noindex === "number" ? (
                <span className="text-cyan-300/90">
                  {" "}
                  · auth noindex {(stats.pages_authenticated as { with_noindex?: number }).with_noindex}
                </span>
              ) : null}
              {stats.auth_configured === false ? (
                <span className="text-amber-300/90"> · auth skip</span>
              ) : typeof stats.auth_sessions === "number" && stats.auth_sessions > 0 ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · {1 + stats.auth_sessions} passes ({stats.auth_sessions} auth)
                </span>
              ) : stats.auth_configured ? (
                <span className="text-cyan-300/80"> · multi pass</span>
              ) : null}
              {typeof stats.robots === "object" && stats.robots !== null ? (
                <span>
                  {" "}
                  · robots present {(stats.robots as { robots_present?: number }).robots_present ?? 0}
                  /missing {(stats.robots as { robots_missing?: number }).robots_missing ?? 0}
                </span>
              ) : null}
              {typeof stats.frontend_bases === "number" && stats.frontend_bases > 0 ? (
                <span> · frontend base {stats.frontend_bases}</span>
              ) : null}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG36Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · probed "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.wordlist_total === "number" ? (
                <span> · wordlist {stats.wordlist_total}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span className="text-rose-300/90"> · issues {stats.collapsed_issues}</span>
              ) : null}
              {typeof stats.httpx_findings === "number" ? (
                <span> · httpx {stats.httpx_findings}</span>
              ) : null}
              {stats.auth_configured === false ? (
                <span className="text-amber-300/90"> · auth skip</span>
              ) : typeof stats.auth_sessions === "number" && stats.auth_sessions > 0 ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · {1 + stats.auth_sessions} passes ({stats.auth_sessions} auth)
                </span>
              ) : stats.auth_configured ? (
                <span className="text-cyan-300/80"> · multi pass</span>
              ) : null}
              {typeof (stats.authenticated as { issues?: number })?.issues === "number" &&
              (stats.authenticated as { issues?: number }).issues! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · auth issues {(stats.authenticated as { issues?: number }).issues}
                </span>
              ) : null}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG52Stats ? (
            <>
              mode{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {" · endpoints "}
              <span className="font-mono text-cyan-300/90">
                {String(stats.endpoints_probed ?? "—")}/{String(stats.endpoints_selected ?? stats.endpoints_total ?? "—")}
              </span>
              {typeof (stats.coverage as { requests?: number })?.requests === "number" ? (
                <span>
                  {" "}
                  · HTTP {(stats.coverage as { requests?: number }).requests}
                  {typeof (stats.coverage as { responses_with_body?: number })?.responses_with_body === "number" ? (
                    <span>
                      {" "}
                      (body {(stats.coverage as { responses_with_body?: number }).responses_with_body})
                    </span>
                  ) : null}
                </span>
              ) : null}
              {typeof (stats.coverage as { status_2xx?: number })?.status_2xx === "number" ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · 2xx {(stats.coverage as { status_2xx?: number }).status_2xx}
                </span>
              ) : null}
              {typeof (stats.coverage as { status_401?: number })?.status_401 === "number" &&
              (stats.coverage as { status_401?: number }).status_401! > 0 ? (
                <span className="text-amber-300/90">
                  {" "}
                  · 401 {(stats.coverage as { status_401?: number }).status_401}
                </span>
              ) : null}
              {typeof (stats.coverage as { connection_errors?: number })?.connection_errors ===
                "number" &&
              (stats.coverage as { connection_errors?: number }).connection_errors! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · unreachable {(stats.coverage as { connection_errors?: number }).connection_errors}
                </span>
              ) : null}
              {typeof stats.issues === "number" ? (
                <span className={stats.issues > 0 ? "text-rose-300/90" : "text-emerald-300/90"}>
                  {" "}
                  · unmasked PII {stats.issues}
                </span>
              ) : null}
              {typeof (stats.coverage as { emails_seen?: number })?.emails_seen === "number" &&
              (stats.coverage as { emails_seen?: number }).emails_seen! > 0 ? (
                <span>
                  {" "}
                  · emails in JSON {(stats.coverage as { emails_seen?: number }).emails_seen}
                </span>
              ) : null}
              {typeof (stats.coverage as { phones_seen?: number })?.phones_seen === "number" &&
              (stats.coverage as { phones_seen?: number }).phones_seen! > 0 ? (
                <span>
                  {" "}
                  · phones in JSON {(stats.coverage as { phones_seen?: number }).phones_seen}
                </span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span> · raw {stats.raw_issues}</span>
              ) : null}
              {typeof stats.auth_passes === "number" ? (
                <span> · auth passes {stats.auth_passes}</span>
              ) : null}
              {stats.inventory === false ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG61Stats ? (
            <>
              mode{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {" · endpoints "}
              <span className="font-mono text-cyan-300/90">
                {String(stats.endpoints_probed ?? "—")}/{String(stats.endpoints_total ?? "—")}
              </span>
              {" · requests "}
              <span className="font-mono text-cyan-300/90">
                {String(stats.requests_sent ?? "—")}/{String(stats.requests_cap ?? "—")}
              </span>
              {" · payloads "}
              <span className="font-mono text-cyan-300/90">{String(stats.payloads ?? "—")}</span>
              {typeof stats.httpx_leaks === "number" ? (
                <span> · httpx leaks {stats.httpx_leaks}</span>
              ) : typeof stats.leaks === "number" && stats.leaks > 0 ? (
                <span className="text-rose-300/90"> · leaks {stats.leaks}</span>
              ) : null}
              {typeof stats.zap_unified_leaks === "number" ? (
                <span> · ZAP unified {stats.zap_unified_leaks}</span>
              ) : null}
              {typeof stats.zap_native_alerts === "number" && stats.zap_native_alerts > 0 ? (
                <span className="text-rose-300/90"> · ZAP native {stats.zap_native_alerts}</span>
              ) : null}
              {typeof stats.auth_passes === "number" ? (
                <span> · auth passes {stats.auth_passes}</span>
              ) : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.inventory === false ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG62Stats ? (
            <>
              login entries{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.login_entries ?? "—")}</span>
              {" · probed "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.uniform === "number" ? (
                <span className="text-emerald-300/90"> · uniform {stats.uniform}</span>
              ) : null}
              {typeof stats.enumeration_risk === "number" && stats.enumeration_risk > 0 ? (
                <span className="text-rose-300/90"> · enumeration {stats.enumeration_risk}</span>
              ) : null}
              {stats.strict ? (
                <span className="text-rose-300/80"> · strict</span>
              ) : (
                <span> · standard</span>
              )}
              {typeof stats.accounts_available === "number" ? (
                <span> · accounts {stats.accounts_available}</span>
              ) : null}
              <ZapStatsLine zap={stats.zap} />
              {typeof stats.zap_findings === "number" && stats.zap_findings > 0 ? (
                <span className="text-rose-300/90"> · zap 40023 {stats.zap_findings}</span>
              ) : null}
            </>
          ) : null}
        </div>
      ) : null}

      {findings.length === 0 ? (
        <p className="text-xs text-cyber-muted">finding 없음</p>
      ) : (
        <GroupedFindingsPanel findings={findings} sectionId={report.section_id} />
      )}
    </div>
  );
}

export function DiagnosisPage() {
  const [openId, setOpenId] = useState<string | null>(null);
  const [catalog, setCatalog] = useState<Record<string, DiagnosisCatalogModule>>({});
  const [reports, setReports] = useState<Record<string, DiagnosisSectionReport>>({});
  const [runningId, setRunningId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [g15DialogOpen, setG15DialogOpen] = useState(false);
  const [g15Options, setG15Options] = useState<G15DiagnosisOptions>(DEFAULT_G15_OPTIONS);
  const [g41DialogOpen, setG41DialogOpen] = useState(false);
  const [g41Options, setG41Options] = useState<G41DiagnosisOptions>(DEFAULT_G41_OPTIONS);
  const [g22DialogOpen, setG22DialogOpen] = useState(false);
  const [g22Options, setG22Options] = useState<G22DiagnosisOptions>(DEFAULT_G22_OPTIONS);
  const [g72DialogOpen, setG72DialogOpen] = useState(false);
  const [g72Options, setG72Options] = useState<G72DiagnosisOptions>(DEFAULT_G72_OPTIONS);
  const [g71DialogOpen, setG71DialogOpen] = useState(false);
  const [g71Options, setG71Options] = useState<G71DiagnosisOptions>(DEFAULT_G71_OPTIONS);
  const [g73DialogOpen, setG73DialogOpen] = useState(false);
  const [g73Options, setG73Options] = useState<G73DiagnosisOptions>(DEFAULT_G73_OPTIONS);
  const [g74DialogOpen, setG74DialogOpen] = useState(false);
  const [g74Options, setG74Options] = useState<G74DiagnosisOptions>(DEFAULT_G74_OPTIONS);
  const [g32DialogOpen, setG32DialogOpen] = useState(false);
  const [g32Options, setG32Options] = useState<G32DiagnosisOptions>(DEFAULT_G32_OPTIONS);
  const [g35DialogOpen, setG35DialogOpen] = useState(false);
  const [g35Options, setG35Options] = useState<G35DiagnosisOptions>(DEFAULT_G35_OPTIONS);
  const [g36DialogOpen, setG36DialogOpen] = useState(false);
  const [g36Options, setG36Options] = useState<G36DiagnosisOptions>(DEFAULT_G36_OPTIONS);
  const [g52DialogOpen, setG52DialogOpen] = useState(false);
  const [g52Options, setG52Options] = useState<G52DiagnosisOptions>(DEFAULT_G52_OPTIONS);
  const [g61DialogOpen, setG61DialogOpen] = useState(false);
  const [g61Options, setG61Options] = useState<G61DiagnosisOptions>(DEFAULT_G61_OPTIONS);
  const [g62DialogOpen, setG62DialogOpen] = useState(false);
  const [g62Options, setG62Options] = useState<G62DiagnosisOptions>(DEFAULT_G62_OPTIONS);
  const [runningSummary, setRunningSummary] = useState<string | null>(null);
  const [runProgress, setRunProgress] = useState<DiagnosisProgressResponse | null>(null);

  useEffect(() => {
    fetchDiagnosisCatalog()
      .then((res) => {
        const map: Record<string, DiagnosisCatalogModule> = {};
        for (const m of res.modules) map[m.id] = m;
        setCatalog(map);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  const catalogById = useMemo(() => catalog, [catalog]);

  const loadReport = useCallback(async (sectionId: string) => {
    try {
      const report = await fetchDiagnosisReport(sectionId);
      setReports((prev) => ({ ...prev, [sectionId]: report }));
    } catch {
      /* no saved report yet */
    }
  }, []);

  const handleToggle = useCallback(
    (sectionId: string) => {
      setOpenId((prev) => {
        const next = prev === sectionId ? null : sectionId;
        if (next) void loadReport(sectionId);
        return next;
      });
    },
    [loadReport],
  );

  const handleRun = useCallback(
    async (
      sectionId: string,
      options?: G15DiagnosisOptions | G41DiagnosisOptions | G22DiagnosisOptions | G32DiagnosisOptions | G35DiagnosisOptions | G36DiagnosisOptions | G52DiagnosisOptions | G61DiagnosisOptions | G62DiagnosisOptions | G71DiagnosisOptions | G72DiagnosisOptions | G73DiagnosisOptions | G74DiagnosisOptions,
    ) => {
      const mod = catalogById[sectionId];
      if (!mod?.diagnosable || !mod?.implemented) return;

      setError(null);
      setRunningId(sectionId);
      setOpenId(sectionId);
      if (sectionId === "1-5" && options && "corsEnabled" in options) {
        setRunningSummary(g15OptionsSummary(options as G15DiagnosisOptions));
      } else if (sectionId === "4-1" && options && "crossCookieEnabled" in options) {
        setRunningSummary(g41OptionsSummary(options as G41DiagnosisOptions));
      } else if (sectionId === "2-2" && options && "useHttpx" in options) {
        const g22 = options as G22DiagnosisOptions;
        setRunningSummary(
          `${g22.useHttpx ? "httpx" : ""}${g22.useHttpx && g22.useZap ? " + " : ""}${g22.useZap ? "ZAP" : ""}${!g22.useHttpx && !g22.useZap ? "설계 리뷰만" : ""}`,
        );
      } else if (sectionId === "7-1" && options && "strictRisky" in options) {
        setRunningSummary(g71OptionsSummary(options as G71DiagnosisOptions));
      } else if (sectionId === "3-2" && options && "maxAttempts" in options) {
        setRunningSummary(g32OptionsSummary(options as G32DiagnosisOptions));
      } else if (sectionId === "3-5" && options && "probeMode" in options && !("requireRobotsTxt" in options)) {
        setRunningSummary(g35OptionsSummary(options as G35DiagnosisOptions));
      } else if (sectionId === "3-6" && options && "probeMode" in options && !("requireRobotsTxt" in options)) {
        setRunningSummary(g36OptionsSummary(options as G36DiagnosisOptions));
      } else if (sectionId === "7-2" && options && "probeMode" in options) {
        setRunningSummary(g72OptionsSummary(options as G72DiagnosisOptions));
      } else if (sectionId === "7-3" && options && "strict" in options && "includeCdnHeaders" in options) {
        setRunningSummary(g73OptionsSummary(options as G73DiagnosisOptions));
      } else if (sectionId === "5-2" && options && "checkResponseBody" in options) {
        setRunningSummary(g52OptionsSummary(options as G52DiagnosisOptions));
      } else if (sectionId === "6-1" && options && "maxRequests" in options) {
        setRunningSummary(g61OptionsSummary(options as G61DiagnosisOptions));
      } else if (sectionId === "6-2" && options && "probeAccountEmail" in options) {
        setRunningSummary(g62OptionsSummary(options as G62DiagnosisOptions));
      } else if (sectionId === "7-4" && options && "checkCookies" in options) {
        setRunningSummary(g74OptionsSummary(options as G74DiagnosisOptions));
      } else {
        setRunningSummary(null);
      }

      setRunProgress(null);
      const poll = window.setInterval(() => {
        void fetchDiagnosisProgress()
          .then((p) => {
            if (p.section_id === sectionId || p.running) {
              setRunProgress(p);
            }
          })
          .catch(() => {});
      }, 1200);

      try {
        let body;
        if (sectionId === "1-5" && options && "corsEnabled" in options) {
          body = g15OptionsToPayload(options as G15DiagnosisOptions);
        } else if (sectionId === "4-1" && options && "crossCookieEnabled" in options) {
          body = g41OptionsToPayload(options as G41DiagnosisOptions);
        } else if (sectionId === "2-2" && options && "useHttpx" in options) {
          body = g22OptionsToPayload(options as G22DiagnosisOptions);
        } else if (sectionId === "7-1" && options && "strictRisky" in options) {
          body = g71OptionsToPayload(options as G71DiagnosisOptions);
        } else if (sectionId === "3-2" && options && "maxAttempts" in options) {
          body = g32OptionsToPayload(options as G32DiagnosisOptions);
        } else if (sectionId === "3-5" && options && "probeMode" in options && !("requireRobotsTxt" in options)) {
          body = g35OptionsToPayload(options as G35DiagnosisOptions);
        } else if (sectionId === "3-6" && options && "probeMode" in options && !("requireRobotsTxt" in options)) {
          body = g36OptionsToPayload(options as G36DiagnosisOptions);
        } else if (sectionId === "7-2" && options && "probeMode" in options) {
          body = g72OptionsToPayload(options as G72DiagnosisOptions);
        } else if (sectionId === "7-3" && options && "strict" in options && "includeCdnHeaders" in options) {
          body = g73OptionsToPayload(options as G73DiagnosisOptions);
        } else if (sectionId === "5-2" && options && "checkResponseBody" in options) {
          body = g52OptionsToPayload(options as G52DiagnosisOptions);
        } else if (sectionId === "6-1" && options && "maxRequests" in options) {
          body = g61OptionsToPayload(options as G61DiagnosisOptions);
        } else if (sectionId === "6-2" && options && "probeAccountEmail" in options) {
          body = g62OptionsToPayload(options as G62DiagnosisOptions);
        } else if (sectionId === "7-4" && options && "checkCookies" in options) {
          body = g74OptionsToPayload(options as G74DiagnosisOptions);
        }
        const res = await runDiagnosisSection(sectionId, body);
        setReports((prev) => ({ ...prev, [sectionId]: res.report }));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        window.clearInterval(poll);
        setRunningId(null);
        setRunningSummary(null);
        setRunProgress(null);
      }
    },
    [catalogById],
  );

  const handleStartClick = useCallback(
    (sectionId: string) => {
      const mod = catalogById[sectionId];
      if (!mod?.diagnosable || !mod?.implemented || runningId) return;
      if (sectionId === "1-5") {
        setG15DialogOpen(true);
        return;
      }
      if (sectionId === "4-1") {
        setG41DialogOpen(true);
        return;
      }
      if (sectionId === "2-2") {
        setG22DialogOpen(true);
        return;
      }
      if (sectionId === "3-2") {
        setG32DialogOpen(true);
        return;
      }
      if (sectionId === "3-5") {
        setG35DialogOpen(true);
        return;
      }
      if (sectionId === "3-6") {
        setG36DialogOpen(true);
        return;
      }
      if (sectionId === "5-2") {
        setG52DialogOpen(true);
        return;
      }
      if (sectionId === "6-1") {
        setG61DialogOpen(true);
        return;
      }
      if (sectionId === "6-2") {
        setG62DialogOpen(true);
        return;
      }
      if (sectionId === "7-1") {
        setG71DialogOpen(true);
        return;
      }
      if (sectionId === "7-2") {
        setG72DialogOpen(true);
        return;
      }
      if (sectionId === "7-3") {
        setG73DialogOpen(true);
        return;
      }
      if (sectionId === "7-4") {
        setG74DialogOpen(true);
        return;
      }
      void handleRun(sectionId);
    },
    [catalogById, handleRun, runningId],
  );

  const handleG15Start = useCallback(
    (options: G15DiagnosisOptions) => {
      setG15Options(options);
      setG15DialogOpen(false);
      void handleRun("1-5", options);
    },
    [handleRun],
  );

  const handleG41Start = useCallback(
    (options: G41DiagnosisOptions) => {
      setG41Options(options);
      setG41DialogOpen(false);
      void handleRun("4-1", options);
    },
    [handleRun],
  );

  const handleG32Start = useCallback(
    (options: G32DiagnosisOptions) => {
      setG32Options(options);
      setG32DialogOpen(false);
      void handleRun("3-2", options);
    },
    [handleRun],
  );

  const handleG35Start = useCallback(
    (options: G35DiagnosisOptions) => {
      setG35Options(options);
      setG35DialogOpen(false);
      void handleRun("3-5", options);
    },
    [handleRun],
  );

  const handleG36Start = useCallback(
    (options: G36DiagnosisOptions) => {
      setG36Options(options);
      setG36DialogOpen(false);
      void handleRun("3-6", options);
    },
    [handleRun],
  );

  const handleG52Start = useCallback(
    (options: G52DiagnosisOptions) => {
      setG52Options(options);
      setG52DialogOpen(false);
      void handleRun("5-2", options);
    },
    [handleRun],
  );

  const handleG61Start = useCallback(
    (options: G61DiagnosisOptions) => {
      setG61Options(options);
      setG61DialogOpen(false);
      void handleRun("6-1", options);
    },
    [handleRun],
  );

  const handleG62Start = useCallback(
    (options: G62DiagnosisOptions) => {
      setG62Options(options);
      setG62DialogOpen(false);
      void handleRun("6-2", options);
    },
    [handleRun],
  );

  const handleG22Start = useCallback(
    (options: G22DiagnosisOptions) => {
      setG22Options(options);
      setG22DialogOpen(false);
      void handleRun("2-2", options);
    },
    [handleRun],
  );

  const handleG71Start = useCallback(
    (options: G71DiagnosisOptions) => {
      setG71Options(options);
      setG71DialogOpen(false);
      void handleRun("7-1", options);
    },
    [handleRun],
  );

  const handleG72Start = useCallback(
    (options: G72DiagnosisOptions) => {
      setG72Options(options);
      setG72DialogOpen(false);
      void handleRun("7-2", options);
    },
    [handleRun],
  );

  const handleG73Start = useCallback(
    (options: G73DiagnosisOptions) => {
      setG73Options(options);
      setG73DialogOpen(false);
      void handleRun("7-3", options);
    },
    [handleRun],
  );

  const handleG74Start = useCallback(
    (options: G74DiagnosisOptions) => {
      setG74Options(options);
      setG74DialogOpen(false);
      void handleRun("7-4", options);
    },
    [handleRun],
  );

  const chapters = Array.from(new Set(GUIDELINE_SECTIONS.map((s) => s.chapter))).sort(
    (a, b) => a - b,
  );

  return (
    <div className="flex-1 overflow-y-auto p-8">
      <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="font-display text-xl font-semibold text-white">Diagnosis</h2>
        </div>
      </div>

      {error ? (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-rose-400/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      ) : null}

      <div className="space-y-6">
        {chapters.map((chapter) => (
          <section key={chapter}>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-cyber-muted">
              Chapter {chapter}
            </h3>
            <div className="overflow-hidden rounded-lg border border-cyber-border/60">
              {GUIDELINE_SECTIONS.filter((s) => s.chapter === chapter).map((section) => {
                const open = openId === section.id;
                const mod = catalogById[section.id];
                const implemented = mod?.implemented ?? false;
                const diagnosable = mod?.diagnosable ?? true;
                const reviewLater = mod?.review_later ?? false;
                const statusLabel = mod?.status_label ?? null;
                const running = runningId === section.id;
                const report = reports[section.id];
                const badgeLabel = mod
                  ? moduleBadgeLabel({
                      implemented,
                      diagnosable,
                      review_later: reviewLater,
                      status_label: statusLabel,
                      engine: mod.engine,
                    })
                  : null;

                return (
                  <div key={section.id} className="border-b border-cyber-border/40 last:border-b-0">
                    <div className="flex items-center gap-2 px-4 py-3 transition hover:bg-cyber-accent/5">
                      <button
                        type="button"
                        onClick={() => handleToggle(section.id)}
                        className="flex min-w-0 flex-1 items-center gap-3 text-left"
                      >
                        <span className="shrink-0 rounded border border-cyber-border/60 bg-cyber-bg px-2 py-0.5 font-mono text-[11px] text-cyber-accent">
                          {section.id}
                        </span>
                        <span className="flex-1 text-sm text-white">{section.title}</span>
                        {badgeLabel ? (
                          <span
                            className={`shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px] ${
                              implemented
                                ? "bg-cyan-500/15 text-cyan-300"
                                : "bg-cyber-bg text-cyber-muted"
                            }`}
                          >
                            {badgeLabel}
                          </span>
                        ) : null}
                        {report ? <StatusBadge status={report.status} /> : null}
                      </button>
                      {reviewLater || (!diagnosable && !statusLabel) ? (
                        <DiagnosisReviewLaterButton compact />
                      ) : statusLabel ? (
                        <DiagnosisManualCheckButton label={statusLabel} compact />
                      ) : !diagnosable ? (
                        <DiagnosisReviewLaterButton compact />
                      ) : (
                        <DiagnosisStartButton
                          compact
                          implemented={implemented}
                          loading={running}
                          disabled={!implemented || runningId !== null}
                          onClick={() => handleStartClick(section.id)}
                        />
                      )}
                      <button
                        type="button"
                        onClick={() => handleToggle(section.id)}
                        className="shrink-0 rounded p-1 text-cyber-muted transition hover:text-white"
                        aria-label={open ? "접기" : "펼치기"}
                      >
                        <ChevronDown
                          className={`h-4 w-4 transition ${open ? "rotate-180" : ""}`}
                        />
                      </button>
                    </div>
                    {open && report ? <ReportPanel report={report} /> : null}
                    {open && !report && !running && reviewLater ? (
                      <div className="border-t border-amber-400/20 bg-amber-500/5 px-4 py-3 text-xs text-amber-200/90">
                        추후 검토 — 자동 진단 범위에 포함되지 않습니다.
                      </div>
                    ) : null}
                    {open && !report && !running && statusLabel ? (
                      <div className="border-t border-amber-400/20 bg-amber-500/5 px-4 py-3 text-xs text-amber-200/90">
                        {statusLabel} — 회원가입 화면에서 패스워드 정책(길이·복잡도 등)을 직접
                        확인하세요.
                      </div>
                    ) : null}
                    {open && !report && !running && diagnosable ? (
                      <div className="border-t border-cyber-border/40 px-4 py-3 text-xs text-cyber-muted">
                        저장된 리포트 없음 — 「진단 시작」을 눌러 실행하세요.
                      </div>
                    ) : null}
                    {open && running ? (
                      <div className="space-y-2 border-t border-cyber-border/40 px-4 py-3 text-xs text-cyan-300/90">
                        <div className="flex items-center gap-2">
                          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                          <span>
                            진단 실행 중…
                            {runningSummary ? ` (${runningSummary})` : null}
                          </span>
                        </div>
                        {runProgress && runProgress.section_id === section.id ? (
                          <>
                            <div className="h-1.5 overflow-hidden rounded-full bg-cyber-border/40">
                              <div
                                className="h-full rounded-full bg-cyan-400/80 transition-all duration-500"
                                style={{ width: `${Math.max(2, runProgress.percent)}%` }}
                              />
                            </div>
                            <p className="font-mono text-[10px] text-cyber-muted">
                              {runProgress.percent > 0
                                ? `${runProgress.percent}%`
                                : "0%"}
                              {runProgress.endpoints_total > 0
                                ? ` · API ${runProgress.endpoints_done}/${runProgress.endpoints_total}`
                                : null}
                              {runProgress.requests_sent > 0
                                ? ` · 요청 ${runProgress.requests_sent.toLocaleString()}`
                                : null}
                              {runProgress.requests_cap
                                ? ` / ${runProgress.requests_cap.toLocaleString()}`
                                : runProgress.requests_sent > 0
                                  ? " · 무제한"
                                  : null}
                            </p>
                            {runProgress.message ? (
                              <p className="truncate text-[10px] text-white/80">{runProgress.message}</p>
                            ) : null}
                          </>
                        ) : runningSummary?.includes("ZAP") ? (
                          <p className="text-[10px] text-cyber-muted">
                            ZAP은 수십 분 걸릴 수 있습니다
                          </p>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          </section>
        ))}
      </div>

      <G15DiagnosisStartDialog
        open={g15DialogOpen && !runningId}
        initialOptions={g15Options}
        onClose={() => setG15DialogOpen(false)}
        onStart={handleG15Start}
      />
      <G41DiagnosisStartDialog
        open={g41DialogOpen && !runningId}
        initialOptions={g41Options}
        onClose={() => setG41DialogOpen(false)}
        onStart={handleG41Start}
      />
      <G22DiagnosisStartDialog
        open={g22DialogOpen && !runningId}
        initialOptions={g22Options}
        onClose={() => setG22DialogOpen(false)}
        onStart={handleG22Start}
      />
      <G71DiagnosisStartDialog
        open={g71DialogOpen && !runningId}
        initialOptions={g71Options}
        onClose={() => setG71DialogOpen(false)}
        onStart={handleG71Start}
      />
      <G72DiagnosisStartDialog
        open={g72DialogOpen && !runningId}
        initialOptions={g72Options}
        onClose={() => setG72DialogOpen(false)}
        onStart={handleG72Start}
      />
      <G73DiagnosisStartDialog
        open={g73DialogOpen && !runningId}
        initialOptions={g73Options}
        onClose={() => setG73DialogOpen(false)}
        onStart={handleG73Start}
      />
      <G74DiagnosisStartDialog
        open={g74DialogOpen && !runningId}
        initialOptions={g74Options}
        onClose={() => setG74DialogOpen(false)}
        onStart={handleG74Start}
      />
      <G32DiagnosisStartDialog
        open={g32DialogOpen && !runningId}
        initialOptions={g32Options}
        onClose={() => setG32DialogOpen(false)}
        onStart={handleG32Start}
      />
      <G35DiagnosisStartDialog
        open={g35DialogOpen && !runningId}
        initialOptions={g35Options}
        onClose={() => setG35DialogOpen(false)}
        onStart={handleG35Start}
      />
      <G36DiagnosisStartDialog
        open={g36DialogOpen && !runningId}
        initialOptions={g36Options}
        onClose={() => setG36DialogOpen(false)}
        onStart={handleG36Start}
      />
      <G52DiagnosisStartDialog
        open={g52DialogOpen && !runningId}
        initialOptions={g52Options}
        onClose={() => setG52DialogOpen(false)}
        onStart={handleG52Start}
      />
      <G61DiagnosisStartDialog
        open={g61DialogOpen && !runningId}
        initialOptions={g61Options}
        onClose={() => setG61DialogOpen(false)}
        onStart={handleG61Start}
      />
      <G62DiagnosisStartDialog
        open={g62DialogOpen && !runningId}
        initialOptions={g62Options}
        onClose={() => setG62DialogOpen(false)}
        onStart={handleG62Start}
      />
    </div>
  );
}
