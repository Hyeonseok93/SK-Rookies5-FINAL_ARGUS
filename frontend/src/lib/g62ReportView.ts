/** Transform 6-2 diagnosis findings into compact views. */

export type G62Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export type G62Scenario = {
  key: "a" | "b" | "c";
  label: string;
  email: string | null;
  httpStatus: number | string | null;
  message: string | null;
  errorCode: string | null;
};

export type G62DiffKind = "message" | "error_code" | "http_status" | "body" | "other";

export type G62MergedFinding = {
  severity: string;
  loginUrl: string;
  loginPath: string;
  loginLabel: string;
  hostLabel: string;
  probeMode: string | null;
  issueKind: "enumeration" | "zap" | "unreachable" | "other";
  existingMessage: string | null;
  unknownMessage: string | null;
  existingCode: string | null;
  unknownCode: string | null;
  diffKinds: G62DiffKind[];
  codeOnlyDiff: boolean;
  sharedMessage: string | null;
  codeDiffSummary: string | null;
  leakSummary: string;
  scenarios: G62Scenario[];
  remediation: string | null;
  zapAlert: string | null;
  zapOther: string | null;
  sources: ("httpx" | "zap")[];
  rawMessage: string;
};

const SCENARIO_DEFS: { key: G62Scenario["key"]; evKey: string; label: string }[] = [
  { key: "a", evKey: "scenario_a", label: "존재 + 오류 PW" },
  { key: "b", evKey: "scenario_b", label: "없음 + 오류 PW" },
  { key: "c", evKey: "scenario_c", label: "없음 + 유효 PW" },
];

/** Pass (uniform A/B/C) — stats + status already convey this; hide from UI. */
export function isG62UniformPassFinding(f: G62Finding): boolean {
  const ev = f.evidence;
  if (!ev || ev.rule_id !== "6-2-login-enumeration") return false;
  const comparison = ev.comparison as { uniform?: boolean } | undefined;
  if (comparison?.uniform === true) return true;
  return (
    f.severity === "info" &&
    f.message.includes("Uniform login failure") &&
    !f.message.toLowerCase().includes("enumeration")
  );
}

export function filterG62DisplayFindings(findings: G62Finding[]): G62Finding[] {
  return findings.filter((f) => !isG62UniformPassFinding(f));
}

function engineSource(ev: Record<string, unknown>): "httpx" | "zap" | null {
  const engine = String(ev.engine ?? ev.source ?? "");
  if (engine === "httpx") return "httpx";
  if (engine === "zap") return "zap";
  return null;
}

function parseScenario(ev: Record<string, unknown>, def: (typeof SCENARIO_DEFS)[number]): G62Scenario | null {
  const snap = ev[def.evKey] as Record<string, unknown> | undefined;
  if (!snap) return null;
  const msg = snap.primary_message ?? snap.body_preview;
  return {
    key: def.key,
    label: def.label,
    email: snap.email != null ? String(snap.email) : null,
    httpStatus: snap.http_status != null ? (snap.http_status as number | string) : null,
    message: msg != null ? String(msg) : null,
    errorCode: snap.error_code != null ? String(snap.error_code) : null,
  };
}

export function parseG62DiffKinds(ev: Record<string, unknown>): G62DiffKind[] {
  const diffs = ev.differences;
  if (!Array.isArray(diffs) || diffs.length === 0) {
    const comparison = ev.comparison as { differences?: string[] } | undefined;
    const fromComparison = comparison?.differences;
    if (!Array.isArray(fromComparison) || fromComparison.length === 0) {
      return ["message"];
    }
    return diffKindsFromStrings(fromComparison.map(String));
  }
  return diffKindsFromStrings(diffs.map(String));
}

function diffKindsFromStrings(diffs: string[]): G62DiffKind[] {
  const kinds = new Set<G62DiffKind>();
  for (const d of diffs) {
    const s = d.toLowerCase();
    if (s.includes("message")) kinds.add("message");
    else if (s.includes("error code")) kinds.add("error_code");
    else if (s.includes("http status")) kinds.add("http_status");
    else if (s.includes("body")) kinds.add("body");
    else kinds.add("other");
  }
  return kinds.size > 0 ? [...kinds] : ["message"];
}

export function isG62CodeOnlyDiff(
  existingMessage: string | null,
  unknownMessage: string | null,
  existingCode: string | null,
  unknownCode: string | null,
  diffKinds: G62DiffKind[],
): boolean {
  const messagesMatch =
    Boolean(existingMessage && unknownMessage && existingMessage === unknownMessage) ||
    (!existingMessage && !unknownMessage);
  const codesDiffer = Boolean(
    existingCode && unknownCode && existingCode !== unknownCode,
  );
  if (messagesMatch && codesDiffer) return true;
  return diffKinds.includes("error_code") && !diffKinds.includes("message");
}

function inferDiffKinds(
  ev: Record<string, unknown>,
  existingMessage: string | null,
  unknownMessage: string | null,
  existingCode: string | null,
  unknownCode: string | null,
): G62DiffKind[] {
  const parsed = parseG62DiffKinds(ev);
  if (parsed.length > 0 && !(parsed.length === 1 && parsed[0] === "message" && !existingMessage)) {
    return parsed;
  }
  const kinds: G62DiffKind[] = [];
  if (existingMessage !== unknownMessage && (existingMessage || unknownMessage)) {
    kinds.push("message");
  }
  if (existingCode !== unknownCode && (existingCode || unknownCode)) {
    kinds.push("error_code");
  }
  return kinds.length > 0 ? kinds : parsed;
}

export function formatG62DiffKindLabel(kinds: G62DiffKind[], codeOnly = false): string {
  if (codeOnly) return "메시지 동일 · 오류 코드 상이";
  return kinds
    .map((k) => {
      if (k === "message") return "메시지";
      if (k === "error_code") return "오류 코드";
      if (k === "http_status") return "HTTP";
      if (k === "body") return "응답 본문";
      return "기타";
    })
    .join(" · ");
}

function pickUnknownCode(scenarios: G62Scenario[]): string | null {
  const unknownB = scenarios.find((s) => s.key === "b")?.errorCode ?? null;
  const unknownC = scenarios.find((s) => s.key === "c")?.errorCode ?? null;
  if (unknownB && unknownC && unknownB === unknownC) return unknownB;
  return [unknownB, unknownC].filter(Boolean).join(" / ") || null;
}

export function formatG62LoginPath(loginUrl: string): string {
  try {
    const path = new URL(loginUrl).pathname;
    const trimmed = path.replace(/\/$/, "");
    return trimmed || "/";
  } catch {
    return loginUrl.replace(/^https?:\/\/[^/]+/, "") || "/";
  }
}

export function formatG62HostLabel(loginUrl: string): string {
  try {
    const u = new URL(loginUrl);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return loginUrl.replace(/^https?:\/\//, "").split("/")[0] ?? loginUrl;
  }
}

export function truncateMessage(value: string | null, max = 56): string {
  if (!value) return "—";
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

function buildLeakSummary(
  existingMessage: string | null,
  unknownMessage: string | null,
  existingCode: string | null,
  unknownCode: string | null,
): string {
  const msgDiff =
    Boolean(existingMessage && unknownMessage && existingMessage !== unknownMessage) ||
    Boolean((existingMessage || unknownMessage) && existingMessage !== unknownMessage);
  const codeDiff =
    Boolean(existingCode && unknownCode && existingCode !== unknownCode) ||
    Boolean((existingCode || unknownCode) && existingCode !== unknownCode);

  if (msgDiff && existingMessage && unknownMessage) {
    return `${truncateMessage(existingMessage, 32)} ↔ ${truncateMessage(unknownMessage, 32)}`;
  }
  if (codeDiff && existingCode && unknownCode) {
    const msg = existingMessage ?? unknownMessage;
    if (msg) {
      return `${truncateMessage(msg, 28)} · ${existingCode} ↔ ${unknownCode}`;
    }
    return `${existingCode} ↔ ${unknownCode}`;
  }
  if (existingMessage || unknownMessage) {
    return truncateMessage(existingMessage ?? unknownMessage, 80);
  }
  return "응답 불일치";
}

function isG62EnumerationFinding(f: G62Finding): boolean {
  const ev = f.evidence;
  if (!ev || ev.rule_id !== "6-2-login-enumeration") return false;
  const comparison = ev.comparison as { uniform?: boolean } | undefined;
  return comparison?.uniform === false || f.message.toLowerCase().includes("enumeration");
}

function isG62ZapFinding(f: G62Finding): boolean {
  const ev = f.evidence;
  return ev?.rule_id === "6-2-login-enumeration" && engineSource(ev) === "zap";
}

function isG62UnreachableFinding(f: G62Finding): boolean {
  return f.severity === "info" && f.message.includes("Login probe unreachable");
}

function mergeEnumerationFinding(f: G62Finding): G62MergedFinding {
  const ev = f.evidence ?? {};
  const loginUrl = String(ev.login_url ?? "");
  const scenarios = SCENARIO_DEFS.map((d) => parseScenario(ev, d)).filter(
    (s): s is G62Scenario => s != null,
  );
  const existingMessage = scenarios.find((s) => s.key === "a")?.message ?? null;
  const existingCode = scenarios.find((s) => s.key === "a")?.errorCode ?? null;
  const unknownB = scenarios.find((s) => s.key === "b")?.message ?? null;
  const unknownC = scenarios.find((s) => s.key === "c")?.message ?? null;
  const unknownMessage =
    unknownB && unknownC && unknownB === unknownC
      ? unknownB
      : [unknownB, unknownC].filter(Boolean).join(" / ") || null;
  const unknownCode = pickUnknownCode(scenarios);
  const diffKinds = inferDiffKinds(ev, existingMessage, unknownMessage, existingCode, unknownCode);
  const codeOnlyDiff = isG62CodeOnlyDiff(
    existingMessage,
    unknownMessage,
    existingCode,
    unknownCode,
    diffKinds,
  );
  const sharedMessage = codeOnlyDiff ? existingMessage ?? unknownMessage : null;
  const codeDiffSummary =
    existingCode && unknownCode && existingCode !== unknownCode
      ? `${existingCode} ↔ ${unknownCode}`
      : null;

  const src = engineSource(ev);
  return {
    severity: f.severity,
    loginUrl,
    loginPath: formatG62LoginPath(loginUrl),
    loginLabel: String(ev.login_label ?? loginUrl),
    hostLabel: formatG62HostLabel(loginUrl),
    probeMode: ev.probe_mode != null ? String(ev.probe_mode) : null,
    issueKind: "enumeration",
    existingMessage,
    unknownMessage,
    existingCode,
    unknownCode,
    diffKinds,
    codeOnlyDiff,
    sharedMessage,
    codeDiffSummary,
    leakSummary: codeOnlyDiff && codeDiffSummary
      ? codeDiffSummary
      : buildLeakSummary(existingMessage, unknownMessage, existingCode, unknownCode),
    scenarios,
    remediation: ev.remediation != null ? String(ev.remediation) : null,
    zapAlert: null,
    zapOther: null,
    sources: src ? [src] : [],
    rawMessage: f.message,
  };
}

function mergeZapFinding(f: G62Finding): G62MergedFinding {
  const ev = f.evidence ?? {};
  const loginUrl = String(ev.login_url ?? ev.url ?? "");
  const src = engineSource(ev);
  const alert = f.message.replace(/^\[6-2\]\s*/i, "").trim();

  return {
    severity: f.severity,
    loginUrl,
    loginPath: formatG62LoginPath(loginUrl),
    loginLabel: String(ev.login_label ?? loginUrl),
    hostLabel: formatG62HostLabel(loginUrl),
    probeMode: null,
    issueKind: "zap",
    existingMessage: null,
    unknownMessage: null,
    existingCode: null,
    unknownCode: null,
    diffKinds: [],
    codeOnlyDiff: false,
    sharedMessage: null,
    codeDiffSummary: null,
    leakSummary: alert,
    scenarios: [],
    remediation: ev.remediation != null ? String(ev.remediation) : null,
    zapAlert: alert,
    zapOther: ev.other_info != null ? String(ev.other_info) : null,
    sources: src ? [src] : ["zap"],
    rawMessage: f.message,
  };
}

export function mergeG62Findings(findings: G62Finding[]): {
  merged: G62MergedFinding[];
  other: G62Finding[];
} {
  const merged: G62MergedFinding[] = [];
  const other: G62Finding[] = [];

  for (const f of findings) {
    if (isG62EnumerationFinding(f)) {
      merged.push(mergeEnumerationFinding(f));
      continue;
    }
    if (isG62ZapFinding(f)) {
      merged.push(mergeZapFinding(f));
      continue;
    }
    if (isG62UnreachableFinding(f)) {
      const ev = f.evidence ?? {};
      const loginUrl = String(ev.login_url ?? "");
      merged.push({
        severity: f.severity,
        loginUrl,
        loginPath: formatG62LoginPath(loginUrl),
        loginLabel: String(ev.login_label ?? loginUrl),
        hostLabel: formatG62HostLabel(loginUrl),
        probeMode: ev.probe_mode != null ? String(ev.probe_mode) : null,
        issueKind: "unreachable",
        existingMessage: null,
        unknownMessage: null,
        existingCode: null,
        unknownCode: null,
        diffKinds: [],
        codeOnlyDiff: false,
        sharedMessage: null,
        codeDiffSummary: null,
        leakSummary: "프로브 연결 실패",
        scenarios: [],
        remediation: null,
        zapAlert: null,
        zapOther: ev.error != null ? String(ev.error) : null,
        sources: ["httpx"],
        rawMessage: f.message,
      });
      continue;
    }
    other.push(f);
  }

  merged.sort((a, b) => {
    const host = a.hostLabel.localeCompare(b.hostLabel);
    if (host !== 0) return host;
    return a.loginPath.localeCompare(b.loginPath);
  });

  return { merged, other };
}

export function groupG62ByHost(merged: G62MergedFinding[]): {
  hostLabel: string;
  findings: G62MergedFinding[];
}[] {
  const groups = new Map<string, G62MergedFinding[]>();
  for (const f of merged) {
    const list = groups.get(f.hostLabel) ?? [];
    list.push(f);
    groups.set(f.hostLabel, list);
  }
  return [...groups.entries()]
    .map(([hostLabel, findings]) => ({ hostLabel, findings }))
    .sort((a, b) => a.hostLabel.localeCompare(b.hostLabel));
}
