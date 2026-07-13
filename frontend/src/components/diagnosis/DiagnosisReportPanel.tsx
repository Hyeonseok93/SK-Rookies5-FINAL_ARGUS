import { useState } from "react";
import { ChevronDown, Terminal, Copy, AlertTriangle, Download } from "lucide-react";
import type { DiagnosisSectionReport } from "../../types";
import { G15FindingsPanel } from "./G15FindingsPanel";
import { G16FindingsPanel } from "./G16FindingsPanel";
import { G22FindingsPanel } from "./G22FindingsPanel";
import { G32FindingsPanel } from "./G32FindingsPanel";
import { G34FindingsPanel } from "./G34FindingsPanel";
import { G35FindingsPanel } from "./G35FindingsPanel";
import { G36FindingsPanel } from "./G36FindingsPanel";
import { G42FindingsPanel } from "./G42FindingsPanel";
import { G45FindingsPanel } from "./G45FindingsPanel";
import { G52FindingsPanel } from "./G52FindingsPanel";
import { G61FindingsPanel } from "./G61FindingsPanel";
import { G62FindingsPanel } from "./G62FindingsPanel";
import { G71FindingsPanel } from "./G71FindingsPanel";
import { G72FindingsPanel } from "./G72FindingsPanel";
import { G73FindingsPanel } from "./G73FindingsPanel";


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

export function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_STYLES[status] ?? STATUS_STYLES.pending;
  return (
    <span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase ${cls}`}>
      {status}
    </span>
  );
}
export function FindingEvidence({
  evidence,
  sectionId,
}: {
  evidence: Record<string, unknown>;
  sectionId: string;
}) {
  const rows: { label: string; value: string }[] = [];
  const blocks: { label: string; value: string }[] = [];

  const add = (label: string, key: string) => {
    const v = evidence[key];
    if (v !== undefined && v !== null && v !== "") {
      rows.push({ label, value: String(v) });
    }
  };

  const addBlock = (label: string, key: string) => {
    const v = evidence[key];
    if (v !== undefined && v !== null && v !== "") {
      blocks.push({ label, value: String(v) });
    }
  };

  add("Login URL", "login_url");
  add("Login label", "login_label");
  add("Probe mode", "probe_mode");
  add("Reason", "reason");
  add("Matched regex", "matched_regex");
  add("Found param", "found_param");
  add("Value prefix", "value_prefix");
  add("Param format", "param_format");
  add("Action URL", "action_url");

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
  add("Assessment", "assessment");
  add("Finding type", "finding_type");
  add("Business role", "business_role");
  add("Feature", "feature_label");
  add("Feature key", "feature_key");
  if (sectionId === "1-2" && evidence.rule_id === "G12_INJECTION") {
    add("Confidence", "confidence");
    add("ARGUS risk", "argus_risk");
    add("Verification", "verification_status");
    add("Reproduction", "reproduction");
  }
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
  add("Attack", "attack");
  add("Affected Parameters", "affected_parameters");
  add("Writer Role", "cross_account_writer_role");
  add("Reader Role", "cross_account_reader_role");

  // Specific blocks for 1-1 from latest.yaml
  addBlock("Vulnerability Description", "vuln_description");
  addBlock("Validation Reason", "validation_reason");
  addBlock("Description", "description");
  addBlock("Remediation Summary", "remediation_summary");
  addBlock("Remediation Cause", "remediation_cause");
  addBlock("Remediation Guide", "remediation_guide");
  addBlock("Remediation Code", "remediation_code");
  addBlock("Evidence Request", "evidence_request");
  addBlock("Evidence Response", "evidence_response");
  addBlock("Evidence", "evidence");

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
  add("Affected methods", "affected_methods");
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
  const affectedExts = evidence.affected_extensions;
  if (Array.isArray(affectedExts) && affectedExts.length > 1) {
    rows.push({
      label: "Affected extensions",
      value: affectedExts.map((e) => `.${e}`).join(", "),
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

  const leak = evidence.payload_leak_markers;
  if (Array.isArray(leak) && leak.length > 0) {
    rows.push({ label: "Payload leak markers", value: leak.map(String).join("; ") });
  }
  const sensitive = evidence.sensitive_markers;
  if (Array.isArray(sensitive) && sensitive.length > 0) {
    rows.push({ label: "Sensitive markers", value: sensitive.map(String).join("; ") });
  }

  const reproductionFlow = Array.isArray(evidence.reproduction_flow)
    ? (evidence.reproduction_flow as { step?: number; label?: string; highlight?: string; rel_path?: string }[])
    : [];
  const shotSteps = reproductionFlow.filter((s) => s.rel_path);
  const fallbackShot =
    shotSteps.length === 0 && typeof evidence.screenshot_rel_path === "string"
      ? (evidence.screenshot_rel_path as string)
      : null;

  if (rows.length === 0 && blocks.length === 0 && shotSteps.length === 0 && !fallbackShot) return null;

  return (
    <div className="mt-2 space-y-2 border-t border-cyber-border/20 pt-2">
      <dl className="space-y-1 text-[10px]">
        {rows.map(({ label, value }) => (
          <div key={label} className="grid grid-cols-[7rem_1fr] gap-2">
            <dt className="text-cyber-muted">{label}</dt>
            <dd className="break-all font-mono text-cyan-300/80">{value}</dd>
          </div>
        ))}
      </dl>
      {shotSteps.length > 0 ? (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {shotSteps.map((s, i) => (
            <figure key={`${s.step}-${i}`} className="overflow-hidden rounded border border-cyber-border/30">
              <img
                src={`/api/diagnosis/modules/${sectionId}/evidence?path=${encodeURIComponent(s.rel_path!)}`}
                alt={s.highlight || s.label || "취약점 재현 스크린샷"}
                className="w-full"
                loading="lazy"
              />
              <figcaption className="bg-cyber-bg/60 px-2 py-1 text-[9px] text-cyber-muted">
                {s.label ?? `Step ${s.step}`}
                {s.highlight ? ` · ${s.highlight}` : ""}
              </figcaption>
            </figure>
          ))}
        </div>
      ) : fallbackShot ? (
        <figure className="overflow-hidden rounded border border-cyber-border/30 sm:max-w-sm">
          <img
            src={`/api/diagnosis/modules/${sectionId}/evidence?path=${encodeURIComponent(fallbackShot)}`}
            alt="취약점 재현 스크린샷"
            className="w-full"
            loading="lazy"
          />
        </figure>
      ) : null}
    </div>
  );
}

function g12EvidenceValue(evidence: Record<string, unknown>, key: string) {
  const direct = evidence[key];
  if (direct !== undefined && direct !== null && direct !== "") return String(direct);
  const detail = evidence.detail as Record<string, unknown> | undefined;
  const nested = detail?.[key];
  return nested !== undefined && nested !== null && nested !== "" ? String(nested) : "";
}

const G12_STRONG_CLASSIFICATIONS = new Set([
  "CONFIRMED_INJECTION_TIME_BASED",
  "CONFIRMED_INJECTION_ERROR_PATTERN",
]);

const G12_WEAK_CLASSIFICATIONS = new Set([
  "CONFIRMED_INJECTION_BOOLEAN_BASED",
  "CONFIRMED_INJECTION_LOW_REPRODUCIBILITY",
]);

function g12Classification(f: { evidence?: Record<string, unknown> }) {
  return f.evidence ? g12EvidenceValue(f.evidence, "classification") : "";
}

function isG12StrongFinding(f: { evidence?: Record<string, unknown> }) {
  return G12_STRONG_CLASSIFICATIONS.has(g12Classification(f));
}

function isG12WeakFinding(f: { evidence?: Record<string, unknown> }) {
  return G12_WEAK_CLASSIFICATIONS.has(g12Classification(f));
}

function G12InjectionSignalBadge({ evidence }: { evidence?: Record<string, unknown> }) {
  if (!evidence || g12EvidenceValue(evidence, "rule_id") !== "G12_INJECTION") return null;

  const classification = g12EvidenceValue(evidence, "classification");
  const confidence = g12EvidenceValue(evidence, "confidence");
  const argusRisk = g12EvidenceValue(evidence, "argus_risk");

  if (G12_STRONG_CLASSIFICATIONS.has(classification)) {
    return (
      <span className="shrink-0 rounded border border-rose-400/50 bg-rose-500/10 px-1.5 py-0.5 font-mono text-[9px] uppercase text-rose-300">
        정탐 · {confidence || argusRisk || "HIGH"}
      </span>
    );
  }

  if (G12_WEAK_CLASSIFICATIONS.has(classification)) {
    return (
      <span className="shrink-0 rounded border border-amber-400/50 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[9px] uppercase text-amber-300">
        약한 정탐 · {confidence || argusRisk || "MEDIUM"}
      </span>
    );
  }

  if (classification.startsWith("SUSPECTED") || classification === "WEAK_SERVER_ERROR_CONFIRMED_LEGACY") {
    return (
      <span className="shrink-0 rounded border border-sky-400/40 bg-sky-500/10 px-1.5 py-0.5 font-mono text-[9px] uppercase text-sky-300">
        의심 · {confidence || argusRisk || "LOW"}
      </span>
    );
  }

  return null;
}

function FindingListItem({
  f,
  sectionId,
}: {
  f: { severity: string; message: string; evidence?: Record<string, unknown> };
  sectionId: string;
}) {
  const findingType = f.evidence?.finding_type as string | undefined;
  const isFpCandidate = findingType === "false_positive_candidate";
  const isTruePositive = findingType === "true_positive";
  return (
    <li
      className={`rounded border px-3 py-2 ${
        isFpCandidate
          ? "border-amber-500/40 bg-amber-500/5"
          : "border-cyber-border/30 bg-cyber-panel/30"
      }`}
    >
      <div className="flex flex-wrap items-start gap-2">
        <span
          className={`shrink-0 font-mono text-[10px] uppercase ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info}`}
        >
          {f.severity}
        </span>
        {isFpCandidate ? (
          <span className="flex items-center gap-1 rounded border border-amber-400/40 bg-amber-500/15 px-1.5 py-0.5 font-mono text-[9px] text-amber-300">
            <AlertTriangle className="h-2.5 w-2.5" />
            오탐 후보
          </span>
        ) : isTruePositive ? (
          <span className="rounded border border-rose-400/40 bg-rose-500/15 px-1.5 py-0.5 font-mono text-[9px] text-rose-300">
            정탐
          </span>
        ) : null}
        {sectionId === "1-2" ? <G12InjectionSignalBadge evidence={f.evidence} /> : null}
        <span className="text-xs text-white/90">{f.message}</span>
      </div>
      {f.evidence && Object.keys(f.evidence).length > 0 ? (
        <FindingEvidence evidence={f.evidence} sectionId={sectionId} />
      ) : null}
    </li>
  );
}

type FindingSummary = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

type G11Artifact = {
  kind: string;
  path: string;
};

type G11CaptureResult = {
  finding_id?: string;
  ok?: boolean;
  artifacts?: G11Artifact[];
  error?: string;
};

function textValue(value: unknown, fallback = "-") {
  if (value === undefined || value === null || value === "") return fallback;
  return String(value);
}

function slugG11Part(value: string) {
  const slug = String(value || "")
    .trim()
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || "x";
}

function g11FindingIdPrefix(finding: FindingSummary) {
  const ev = finding.evidence ?? {};
  const vulnType = textValue(ev.vuln_type, "").trim();
  const method = textValue(ev.method, "GET").toUpperCase();
  const url = textValue(ev.url, "/").replace(/\/+$/, "") || "/";
  let path = "root";
  try {
    path = new URL(url).pathname.replace(/^\/+|\/+$/g, "") || "root";
  } catch {
    path = url.replace(/^https?:\/\/[^/]+/i, "").replace(/^\/+|\/+$/g, "") || "root";
  }
  const param = textValue(ev.param, "").toLowerCase();
  const role = textValue(ev.account_role, "").trim().toUpperCase();
  const parts = [vulnType, method, path, param];
  if (role) parts.push(role);
  return `1-1_${parts.map(slugG11Part).join("_")}_`;
}

function g11EvidenceUrl(path: string) {
  const marker = "/evidence/";
  const idx = path.indexOf(marker);
  const relative = idx >= 0 ? path.slice(idx + marker.length) : path;
  return `/api/diagnosis/modules/1-1/evidence/${relative
    .split("/")
    .map(encodeURIComponent)
    .join("/")}`;
}

function g11CaptureResults(findings: FindingSummary[]) {
  const captureFinding = findings.find((f) => f.evidence?.screenshot_capture);
  const capture = captureFinding?.evidence?.screenshot_capture as Record<string, unknown> | undefined;
  const summary = capture?.capture_summary as Record<string, unknown> | undefined;
  const results = summary?.results;
  return Array.isArray(results) ? (results as G11CaptureResult[]) : [];
}

function g11ArtifactsForFinding(finding: FindingSummary, results: G11CaptureResult[]) {
  const prefix = g11FindingIdPrefix(finding);
  const row = results.find((item) => String(item.finding_id ?? "").startsWith(prefix));
  return {
    result: row,
    images: (row?.artifacts ?? []).filter((item) => /\.(png|jpe?g|webp)$/i.test(item.path)),
  };
}

function g11VulnerabilityTitle(finding: FindingSummary) {
  const ev = finding.evidence ?? {};
  return textValue(ev.vuln_type, finding.message || "취약점");
}

function G11DetailBlock({ title, value }: { title: string; value: unknown }) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <div>
      <div className="mb-1 text-[10px] font-medium text-cyber-muted">{title}</div>
      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words rounded border border-cyber-border/30 bg-black/25 p-2 font-mono text-[10px] leading-relaxed text-cyan-100/80">
        {String(value)}
      </pre>
    </div>
  );
}

function G11FindingCard({
  finding,
  results,
}: {
  finding: FindingSummary;
  results: G11CaptureResult[];
}) {
  const [open, setOpen] = useState(false);
  const ev = finding.evidence ?? {};
  const { result, images } = g11ArtifactsForFinding(finding, results);
  const isCsrf = String(ev.vuln_type ?? "").toLowerCase().includes("csrf");
  const csrf = ev.csrf_defenses as Record<string, unknown> | undefined;

  return (
    <li className="rounded border border-cyber-border/35 bg-cyber-panel/25 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className={`font-mono text-[10px] uppercase ${SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.info}`}>
              {finding.severity}
            </span>
            <span className="text-sm font-semibold text-white">{g11VulnerabilityTitle(finding)}</span>
            {ev.validation_status ? (
              <span className="rounded border border-cyber-border/40 px-1.5 py-0.5 text-[10px] text-cyber-muted">
                {String(ev.validation_status)}
              </span>
            ) : null}
          </div>
          <dl className="grid gap-1 text-[11px] sm:grid-cols-[5rem_1fr]">
            <dt className="text-cyber-muted">URL</dt>
            <dd className="break-all font-mono text-cyan-200/85">{textValue(ev.url)}</dd>
            <dt className="text-cyber-muted">파라미터</dt>
            <dd className="break-all font-mono text-cyan-200/85">{textValue(ev.param)}</dd>
            <dt className="text-cyber-muted">페이로드</dt>
            <dd className="break-all font-mono text-cyan-200/85">{textValue(ev.attack)}</dd>
          </dl>
        </div>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="shrink-0 rounded border border-cyber-border/50 px-2 py-1 text-[11px] text-cyber-muted transition hover:border-cyan-400/50 hover:text-cyan-200"
        >
          상세보기
        </button>
      </div>

      {images.length > 0 ? (
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {images.map((image) => (
            <figure key={`${image.kind}-${image.path}`} className="overflow-hidden rounded border border-cyber-border/30 bg-black/20">
              <img src={g11EvidenceUrl(image.path)} alt={`${g11VulnerabilityTitle(finding)} ${image.kind} evidence`} className="w-full object-contain" loading="lazy" />
              <figcaption className="border-t border-cyber-border/25 px-2 py-1 text-[10px] text-cyber-muted">
                {image.kind === "site" ? "실제 화면 증거" : "요청/응답 증거"}
              </figcaption>
            </figure>
          ))}
        </div>
      ) : null}

      {open ? (
        <div className="mt-3 space-y-3 border-t border-cyber-border/30 pt-3">
          {result && result.ok === false ? (
            <p className="text-[11px] text-amber-200/90">증거 캡처 실패: {textValue(result.error)}</p>
          ) : null}
          {isCsrf && csrf ? (
            <div className="grid gap-1 rounded border border-cyber-border/30 bg-black/15 p-2 text-[11px] sm:grid-cols-2">
              <span className="text-cyber-muted">Origin/Referer 우회: {String(Boolean(csrf.origin_referer_bypass))}</span>
              <span className="text-cyber-muted">CSRF token 부재: {String(Boolean(csrf.csrf_token_absent))}</span>
              <span className="text-cyber-muted">SameSite 미흡: {String(Boolean(csrf.unsafe_samesite))}</span>
              <span className="text-cyber-muted">실패 방어 수: {textValue(csrf.failed_count)}</span>
            </div>
          ) : null}
          <G11DetailBlock title="판정 근거" value={ev.validation_reason ?? ev.description} />
          <G11DetailBlock title="조치 가이드" value={ev.remediation_guide ?? ev.remediation_summary} />
          <G11DetailBlock title="원인" value={ev.remediation_cause} />
          <G11DetailBlock title="예시 코드" value={ev.remediation_code} />
          <G11DetailBlock title="Evidence Request" value={ev.evidence_request} />
          <G11DetailBlock title="Evidence Response" value={ev.evidence_response} />
        </div>
      ) : null}
    </li>
  );
}

function G11FindingsPanel({ findings }: { findings: FindingSummary[] }) {
  const captureResults = g11CaptureResults(findings);
  const visibleFindings = findings.filter((f) => !f.evidence?.screenshot_capture);

  if (visibleFindings.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  return (
    <ul className="space-y-3">
      {visibleFindings.map((finding, index) => (
        <G11FindingCard key={`${finding.message}-${index}`} finding={finding} results={captureResults} />
      ))}
    </ul>
  );
}

function findingBucket(f: {
  severity: string;
  evidence?: Record<string, unknown>;
}):
  | "httpx"
  | "zap"
  | "tls"
  | "version"
  | "port_scan"
  | "cve"
  | "info"
  | "inventory"
  | "other" {
  if (f.severity === "info") return "info";

  const ev = f.evidence;

  if (ev?.rule_id === "2-2-design") return "info";

  const engine = String(ev?.engine ?? ev?.source ?? "").toLowerCase();

  if (engine === "inventory") return "inventory";
  if (engine === "httpx") return "httpx";
  if (engine === "zap") return "zap";

  if (engine === "tls") return "tls";
  if (engine === "version") return "version";
  if (engine === "port_scan") return "port_scan";

  // Dependency / CVE
  if (
    engine === "dependency" ||
    engine === "csv" ||
    engine === "osv" ||
    engine === "dependency_check"
  ) {
    return "cve";
  }

  return "other";
}

function CollapsibleFindingsSection({
  title,
  subtitle,
  count,
  defaultOpen,
  findings,
  sectionId,
  children,
}: {
  title: string;
  subtitle?: string;
  count: number;
  defaultOpen: boolean;
  findings: { severity: string; message: string; evidence?: Record<string, unknown> }[];
  sectionId: string;
  children?: React.ReactNode;
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
        <div className="border-t border-cyber-border/30">
          {children}
          <ul className="space-y-2 px-3 py-2">
            {findings.map((f, i) => (
              <FindingListItem key={`${title}-${f.severity}-${i}`} f={f} sectionId={sectionId} />
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}


/** 오탐 후보(baseline 업로드 거부) 전용 섹션 */
function FpCandidateSection({
  findings,
  sectionId,
}: {
  findings: { severity: string; message: string; evidence?: Record<string, unknown> }[];
  sectionId: string;
}) {
  const [open, setOpen] = useState(true);
  return (
    <div className="mb-3 overflow-hidden rounded-lg border border-amber-500/40 bg-amber-500/5">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition hover:bg-amber-500/10"
      >
        <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
        <span className="text-xs font-semibold text-amber-300">엔드포인트 설정 확인 필요</span>
        <span className="font-mono text-[10px] text-amber-400/80">{findings.length}</span>
        <span className="ml-auto text-[10px] text-amber-500/70">
          baseline(정상 이미지)가 거부됨 — 필드명·인증·extra_fields 검증 후 재진단 권장
        </span>
        <ChevronDown className={`h-4 w-4 shrink-0 text-amber-400/60 transition ${open ? "rotate-180" : ""}`} />
      </button>
      {open ? (
        <ul className="space-y-2 border-t border-amber-500/20 px-3 py-2">
          {findings.map((f, i) => (
            <FindingListItem key={`fpc-${i}`} f={f} sectionId={sectionId} />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function Gradle74Guide() {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState<"unix" | "windows" | null>(null);

  const unixCmd =
    "./gradlew :api-module:dependencies --configuration runtimeClasspath > deps.txt";
  const winCmd =
    "gradlew.bat :api-module:dependencies --configuration runtimeClasspath > deps.txt";

  const handleCopy = async (cmd: string, key: "unix" | "windows") => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(key);
      setTimeout(() => setCopied((v) => (v === key ? null : v)), 1500);
    } catch {
      // 클립보드 접근 실패 시 조용히 무시
    }
  };

  return (
    <div className="mb-3 overflow-hidden rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition hover:bg-cyber-accent/5"
      >
        <ChevronDown
          className={`h-4 w-4 shrink-0 text-cyber-muted transition ${open ? "rotate-180" : ""}`}
        />
        <Terminal className="h-3.5 w-3.5 shrink-0 text-cyan-300/80" />
        <span className="text-xs font-semibold text-white">Gradle 의존성 트리 추출 가이드</span>
        <span className="ml-1 text-[10px] text-cyber-muted">deps.txt 생성 명령어</span>
      </button>
      {open ? (
        <div className="space-y-3 border-t border-cyber-border/30 px-3 py-3">
          <GuideCommandBlock
            label="Linux / macOS"
            command={unixCmd}
            copied={copied === "unix"}
            onCopy={() => handleCopy(unixCmd, "unix")}
          />
          <GuideCommandBlock
            label="Windows (cmd / PowerShell)"
            command={winCmd}
            copied={copied === "windows"}
            onCopy={() => handleCopy(winCmd, "windows")}
          />
          <p className="text-[10px] text-cyber-muted">
            생성된{" "}
            <code className="rounded bg-cyber-bg/60 px-1 font-mono text-cyan-300/90">
              deps.txt
            </code>{" "}
            파일을 업로드하면 자동으로 취약점 진단이 진행됩니다.
          </p>
        </div>

      ) : null}
    </div>
  );
}


const ROLE_LABELS: Record<string, string> = {

  user: "일반사용자",
  seller: "판매자",
  admin: "관리자",
};

function GroupedG21FindingsPanel({
  findings,
  sectionId,
}: {
  findings: { severity: string; message: string; evidence?: Record<string, unknown> }[];
  sectionId: string;
}) {
  if (findings.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  // 오탐 후보(baseline 거부)와 정탐을 분리
  const fpCandidates = findings.filter(
    (f) => f.evidence?.finding_type === "false_positive_candidate",
  );
  const trueFindings = findings.filter(
    (f) => f.evidence?.finding_type !== "false_positive_candidate",
  );

  const roles = ["user", "seller", "admin"];
  const groups = new Map<string, typeof trueFindings>();
  trueFindings.forEach((finding) => {
    const ev = finding.evidence ?? {};
    const role = String(ev.business_role ?? "user");
    const feature = String(ev.feature_key ?? ev.endpoint_id ?? "file_upload");
    const key = `${role}::${feature}`;
    groups.set(key, [...(groups.get(key) ?? []), finding]);
  });

  return (
    <>
      {/* 오탐 후보 섹션 — 엔드포인트 설정을 먼저 검증해야 함을 강조 */}
      {fpCandidates.length > 0 ? (
        <FpCandidateSection findings={fpCandidates} sectionId={sectionId} />
      ) : null}

      {/* 정탐 섹션 — 역할별 그룹 */}
      {roles.map((role) => {
        const roleFindings = Array.from(groups.entries())
          .filter(([key]) => key.startsWith(`${role}::`))
          .flatMap(([, items]) => items);
        if (roleFindings.length === 0) return null;
        return (
          <CollapsibleFindingsSection
            key={role}
            title={ROLE_LABELS[role] ?? role}
            subtitle="2-1 정탐 findings"
            count={roleFindings.length}
            defaultOpen
            findings={roleFindings}
            sectionId={sectionId}
          />
        );
      })}
      {Array.from(groups.entries())
        .filter(([key]) => !roles.some((role) => key.startsWith(`${role}::`)))
        .map(([key, items]) => (
          <CollapsibleFindingsSection
            key={key}
            title={String(items[0]?.evidence?.feature_label ?? key)}
            subtitle="2-1 정탐 findings"
            count={items.length}
            defaultOpen={false}
            findings={items}
            sectionId={sectionId}
          />
        ))}
    </>
  );
}

function GuideCommandBlock({
  label,
  command,
  copied,
  onCopy,
}: {
  label: string;
  command: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div>
      <div className="mb-1 text-[10px] uppercase tracking-wide text-cyber-muted">{label}</div>
      <div className="flex items-center justify-between gap-2 rounded border border-cyber-border/40 bg-black/30 px-2 py-1.5">
        <code className="overflow-x-auto whitespace-nowrap font-mono text-[11px] text-cyan-300/90">
          {command}
        </code>
        <button
          type="button"
          onClick={onCopy}
          className="flex shrink-0 items-center gap-1 rounded border border-cyber-border/50 px-1.5 py-0.5 text-[10px] text-cyber-muted transition hover:bg-cyber-accent/10 hover:text-cyan-300"
        >
          <Copy className="h-3 w-3" />
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
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
  const tls = findings.filter((f) => findingBucket(f) === "tls");
  const version = findings.filter((f) => findingBucket(f) === "version");
  const portScan = findings.filter((f) => findingBucket(f) === "port_scan");
  const cve = findings.filter((f) => findingBucket(f) === "cve");
  const inventory = findings.filter((f) => findingBucket(f) === "inventory");
  const info = findings.filter((f) => findingBucket(f) === "info");
  const other = findings.filter((f) => findingBucket(f) === "other");

  if (findings.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  if (sectionId === "1-1") {
    return <G11FindingsPanel findings={findings} />;
  }

  if (sectionId === "2-1") {
    return <GroupedG21FindingsPanel findings={findings} sectionId={sectionId} />;
  }

  if (sectionId === "1-2") {
    const info = findings.filter((f) => findingBucket(f) === "info");
    const nonInfo = findings.filter((f) => findingBucket(f) !== "info");
    const g12Strong = nonInfo.filter(isG12StrongFinding);
    const g12Weak = nonInfo.filter(isG12WeakFinding);
    const g12Other = nonInfo.filter((f) => !isG12StrongFinding(f) && !isG12WeakFinding(f));

    return (
      <>
        <CollapsibleFindingsSection
          title="info"
          count={info.length}
          defaultOpen={false}
          findings={info}
          sectionId={sectionId}
        />
        <CollapsibleFindingsSection
          title="정탐"
          subtitle="· time / error pattern"
          count={g12Strong.length}
          defaultOpen={g12Strong.length > 0}
          findings={g12Strong}
          sectionId={sectionId}
        />
        <CollapsibleFindingsSection
          title="약한 정탐"
          subtitle="· boolean response difference"
          count={g12Weak.length}
          defaultOpen={g12Strong.length === 0 && g12Weak.length > 0}
          findings={g12Weak}
          sectionId={sectionId}
        />
        <CollapsibleFindingsSection
          title="ARGUS direct"
          subtitle="· error / boolean / time 직접 검증"
          count={g12Other.length}
          defaultOpen={g12Strong.length === 0 && g12Weak.length === 0}
          findings={g12Other}
          sectionId={sectionId}
        />
      </>
    );

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
        sectionId={sectionId}
      />
      <CollapsibleFindingsSection
        title="TLS"
        subtitle="· TLS 검사"
        count={tls.length}
        defaultOpen={false}
        findings={tls}
        sectionId={sectionId}
      />

      <CollapsibleFindingsSection
        title="Version"
        subtitle="· 버전 정보 분석"
        count={version.length}
        defaultOpen={false}
        findings={version}
        sectionId={sectionId}
      />

      <CollapsibleFindingsSection
        title="Port Scan"
        subtitle="· 포트 스캔"
        count={portScan.length}
        defaultOpen={false}
        findings={portScan}
        sectionId={sectionId}
      />

      <CollapsibleFindingsSection
        title="CVE (Dependency/CVE)"
        subtitle="· 라이브러리 취약점 분석"
        count={cve.length}
        defaultOpen={true}
        findings={cve}
        sectionId={sectionId}
      >
        {cve.length > 0 && (
          <div className="mx-3 mt-3 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] leading-relaxed text-amber-200/90">
            <p className="mb-1 font-semibold text-amber-400">안내</p>
            <p>
              CSV 기반 결과는 프로젝트에서 사용하는 라이브러리 버전을 알려진 취약점 데이터베이스(GHSA/CVE)와 비교하여 탐지한 결과입니다.
            </p>
            <p className="mt-1">
              따라서 <strong className="text-amber-300">현재 사용 중인 버전에 알려진 보안 취약점이 존재함을 의미</strong>하지만,{" "}
              <strong className="text-amber-300">해당 취약점이 현재 서비스에서 실제로 악용 가능한 상태임을 의미하는 것은 아닙니다.</strong>
            </p>
            <p className="mt-1">
              실제 영향 여부는 애플리케이션의 사용 방식, 설정 및 배포 환경에 따라 달라질 수 있습니다. 결과는 참고용으로 활용하시기 바랍니다.
            </p>
          </div>
        )}
      </CollapsibleFindingsSection>
      <CollapsibleFindingsSection
        title="ZAP"
        subtitle={zapSubtitle}
        count={zap.length}
        defaultOpen={false}
        findings={zap}
        sectionId={sectionId}
      />
      <CollapsibleFindingsSection
        title="inventory"
        subtitle="· api-tree + login report 분석"
        count={inventory.length}
        defaultOpen={sectionId === "3-4"}
        findings={inventory}
        sectionId={sectionId}
      />
      <CollapsibleFindingsSection
        title="info"
        count={info.length}
        defaultOpen={sectionId === "3-4"}
        findings={info}
        sectionId={sectionId}
      />
      {other.length > 0 ? (
        <CollapsibleFindingsSection
          title="기타"
          count={other.length}
          defaultOpen={false}
          findings={other}
          sectionId={sectionId}
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

export function DiagnosisReportPanel({ report }: { report: DiagnosisSectionReport }) {
  const statsMessages = new Set([
    "1-2 scan statistics",
    "1-5 scan statistics",
    "1-6 scan statistics",
    "2-1 scan statistics",
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
  const isG12Stats = statsFinding?.message === "1-2 scan statistics";
  const isG15Stats = statsFinding?.message === "1-5 scan statistics";
  const isG16Stats = statsFinding?.message === "1-6 scan statistics";
  const isG21Stats = statsFinding?.message === "2-1 scan statistics";
  const isG41Stats = statsFinding?.message === "4-1 scan statistics";
  const isG42Stats = statsFinding?.message === "4-2 scan statistics";
  const isG45Stats = statsFinding?.message === "4-5 scan statistics";
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
      {report.section_id === "1-1" ? (
        <div className="mb-3 flex justify-end">
          <a
            href="/api/diagnosis/modules/1-1/report/download"
            download
            className="inline-flex items-center gap-1.5 rounded border border-cyber-border/50 px-2.5 py-1.5 text-xs text-cyan-200 transition hover:border-cyan-400/60 hover:bg-cyan-400/10"
          >
            <Download className="h-3.5 w-3.5" />
            진단 결과 다운로드
          </a>
        </div>
      ) : null}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <StatusBadge status={report.status} />
        {report.checked_at ? (
          <span className="text-[10px] text-cyber-muted">{report.checked_at}</span>
        ) : null}
        {report.message ? (
          <span className="text-xs text-cyber-muted">{report.message}</span>
        ) : null}
      </div>

      {report.section_id === "7-4" ? <Gradle74Guide /> : null}

      {stats ? (
        <div className="mb-3 rounded border border-cyber-border/40 bg-cyber-panel/40 px-3 py-2 text-[11px] text-cyber-muted">
          {isG12Stats ? (
            <>
              api-tree{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.scan_targets ?? "—")}</span>
              {typeof stats.targets_with_params === "number" ? (
                <span> · params {stats.targets_with_params}</span>
              ) : null}
              {typeof stats.verified_findings === "number" ? (
                <span> · verified {stats.verified_findings}</span>
              ) : null}
              {typeof stats.confirmed_findings === "number" ? (
                <span className={stats.confirmed_findings > 0 ? "text-rose-300/90" : "text-cyber-muted"}>
                  {" "}
                  · 정탐 {stats.confirmed_findings}
                </span>
              ) : null}
              {typeof stats.verified_findings === "number" && typeof stats.confirmed_findings === "number" ? (
                <span className="text-amber-300/90">
                  {" "}
                  · 약한 정탐 {Math.max(0, stats.verified_findings - stats.confirmed_findings)}
                </span>
              ) : null}
              {typeof stats.excluded_server_error_signals === "number" && stats.excluded_server_error_signals > 0 ? (
                <span> · excluded {stats.excluded_server_error_signals}</span>
              ) : null}
              <ZapStatsLine zap={stats.zap} />
            </>
          ) : null}
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
          {isG16Stats ? (
            <>
              payload sources{" "}
              <span className="font-mono text-cyan-300/90">
                {Array.isArray(stats.payload_sources) ? stats.payload_sources.length : "—"}
              </span>
              {typeof stats.raw_findings_count === "number" ? (
                <span> · raw findings {stats.raw_findings_count}</span>
              ) : null}
              {(() => {
                const shots = stats.screenshots as
                  | { enabled?: boolean; status?: string; stats?: { selected?: number; succeeded?: number } }
                  | undefined;
                if (!shots?.enabled) return <span className="text-amber-300/80"> · 스크린샷 비활성</span>;
                if (shots.status === "error") return <span className="text-amber-300/80"> · 스크린샷 실패</span>;
                const sel = shots.stats?.selected ?? 0;
                const ok = shots.stats?.succeeded ?? 0;
                return <span> · 스크린샷 {ok}/{sel}</span>;
              })()}
            </>
          ) : null}
          {isG21Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.source ?? "inventory")}</span>
              {" · 대상 "}
              <span className="font-mono text-cyan-300/90">
                {String(stats.targets_probed ?? stats.targets ?? "—")}
              </span>
              {typeof stats.upload_endpoints_found === "number" ? (
                <span> / api-tree 탐지 {stats.upload_endpoints_found}</span>
              ) : null}
              {stats.truncated_to ? (
                <span className="text-amber-300/80"> · max {String(stats.truncated_to)}로 제한</span>
              ) : null}
              {typeof (stats.httpx as { findings?: number })?.findings === "number" ? (
                <span> · httpx finding {(stats.httpx as { findings?: number }).findings}</span>
              ) : null}
              <ZapStatsLine zap={stats.zap} />
              {typeof stats.collapsed_issues === "number" ? (
                <span className={stats.collapsed_issues > 0 ? "text-rose-300/90" : "text-emerald-300/90"}>
                  {" "}
                  · unique issue {stats.collapsed_issues}
                </span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted"> (raw {stats.raw_issues} → deduped)</span>
              ) : null}
              {stats.auth_configured === false ? (
                <span className="text-amber-300/90"> · auth skip</span>
              ) : typeof stats.auth_sessions === "number" && stats.auth_sessions > 0 ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · {1 + stats.auth_sessions} passes ({stats.auth_sessions} auth)
                </span>
              ) : null}
              {stats.budget_exhausted ? (
                <span className="text-amber-400/90"> · 요청 한도 초과 — 결과 불완전할 수 있음</span>
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
          {isG45Stats ? (
            <>
              API endpoints{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.scanned_endpoints ?? "—")}</span>
              {typeof stats.admin_endpoints === "number" ? (
                <span> · tested endpoints {stats.admin_endpoints}</span>
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

      {report.section_id === "6-1" && report.g61_summary ? (
        <G61FindingsPanel summary={report.g61_summary} status={report.status} />
      ) : report.section_id === "1-6" ? (
        <G16FindingsPanel findings={findings} status={report.status} />
      ) : findings.length === 0 ? (
        <p className="text-xs text-cyber-muted">finding 없음</p>
      ) : report.section_id === "1-5" ? (
        <G15FindingsPanel findings={findings} />
      ) : report.section_id === "2-2" ? (
        <G22FindingsPanel findings={findings} />
      ) : report.section_id === "3-2" ? (
        <G32FindingsPanel findings={findings} stats={stats} />
      ) : report.section_id === "3-4" ? (
        <G34FindingsPanel findings={findings} stats={stats} status={report.status} />
      ) : report.section_id === "3-5" ? (
        <G35FindingsPanel findings={findings} stats={stats} />
      ) : report.section_id === "3-6" ? (
        <G36FindingsPanel findings={findings} stats={stats} status={report.status} />
      ) : report.section_id === "4-2" ? (
        <G42FindingsPanel findings={findings} />
      ) : report.section_id === "4-5" ? (
        <G45FindingsPanel findings={findings} />
      ) : report.section_id === "5-2" ? (
        <G52FindingsPanel findings={findings} stats={stats} />
      ) : report.section_id === "6-2" ? (
        <G62FindingsPanel findings={findings} />
      ) : report.section_id === "7-1" ? (
        <G71FindingsPanel findings={findings} />
      ) : report.section_id === "7-2" ? (
        <G72FindingsPanel findings={findings} />
      ) : report.section_id === "7-3" ? (
        <G73FindingsPanel findings={findings} />
      ) : report.section_id === "7-4" ? (
        <GroupedFindingsPanel findings={findings} sectionId={report.section_id} />
      ) : (
        <GroupedFindingsPanel findings={findings} sectionId={report.section_id} />
      )}
    </div>
  );
}
