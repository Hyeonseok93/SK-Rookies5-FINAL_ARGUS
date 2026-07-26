/** Transform 7-1 diagnosis findings into compact views. */

export type G71Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export const G71_ISSUE_LABELS: Record<string, string> = {
  trace_echo: "TRACE echo",
  allow_dangerous: "Dangerous Allow",
  allow_risky: "Risky Allow",
};

export type G71MergedFinding = {
  severity: string;
  baseUrl: string;
  issueType: string;
  issueLabel: string;
  reason: string;
  matchedMethods: string[];
  allowHeader: string | null;
  httpMethod: string | null;
  affectedCount: number;
  affectedUrls: string[];
  sampleUrl: string | null;
  sources: ("httpx" | "zap")[];
  httpStatus: string | number | null;
};

export type G71BaseUrlGroup = {
  baseUrl: string;
  displayLabel: string;
  findings: G71MergedFinding[];
};

function isG71MethodFinding(f: G71Finding): boolean {
  const ev = f.evidence;
  if (!ev) return false;
  return ev.rule_id === "7-1-insecure-http-method" && typeof ev.issue_type === "string";
}

function engineSource(ev: Record<string, unknown>): "httpx" | "zap" | null {
  const engine = String(ev.engine ?? ev.source ?? "");
  if (engine === "httpx") return "httpx";
  if (engine === "zap") return "zap";
  return null;
}

export function formatG71BaseLabel(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return baseUrl.replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
}

export function issueTypeLabel(issueType: string): string {
  return G71_ISSUE_LABELS[issueType] ?? issueType;
}

function issueSortKey(issueType: string): number {
  if (issueType === "trace_echo") return 0;
  if (issueType === "allow_dangerous") return 1;
  if (issueType === "allow_risky") return 2;
  return 3;
}

function severityRank(sev: string): number {
  if (sev === "high") return 3;
  if (sev === "medium") return 2;
  if (sev === "low") return 1;
  return 0;
}

function matchedMethodsFromEv(ev: Record<string, unknown>): string[] {
  const raw = ev.matched_methods;
  if (Array.isArray(raw)) return [...raw].map(String).sort();
  if (ev.method) return [String(ev.method)];
  return [];
}

function mergeKey(f: G71Finding): string | null {
  const ev = f.evidence;
  if (!ev?.issue_type) return null;
  const methods = matchedMethodsFromEv(ev).join(",");
  return [String(ev.base_url ?? ""), String(ev.issue_type), methods].join("|");
}

export function mergeG71Findings(findings: G71Finding[]): {
  merged: G71MergedFinding[];
  other: G71Finding[];
} {
  const other: G71Finding[] = [];
  const map = new Map<
    string,
    {
      severity: string;
      ev: Record<string, unknown>;
      urls: Set<string>;
      sources: Set<"httpx" | "zap">;
    }
  >();

  for (const f of findings) {
    if (!isG71MethodFinding(f)) {
      other.push(f);
      continue;
    }
    const key = mergeKey(f);
    if (!key) {
      other.push(f);
      continue;
    }
    const ev = f.evidence ?? {};
    const url = String(ev.url ?? "");
    const affected = ev.affected_urls;
    const urlList = Array.isArray(affected) ? affected.map(String) : url ? [url] : [];

    const existing = map.get(key);
    if (!existing) {
      map.set(key, {
        severity: f.severity,
        ev: { ...ev },
        urls: new Set(urlList.filter(Boolean)),
        sources: new Set(engineSource(ev) ? [engineSource(ev)!] : []),
      });
      continue;
    }
    if (severityRank(f.severity) > severityRank(existing.severity)) {
      existing.severity = f.severity;
    }
    for (const u of urlList) {
      if (u) existing.urls.add(u);
    }
    const src = engineSource(ev);
    if (src) existing.sources.add(src);
    if (ev.allow_header && !existing.ev.allow_header) {
      existing.ev.allow_header = ev.allow_header;
    }
    if (typeof ev.affected_count === "number") {
      const prev = Number(existing.ev.affected_count ?? 0);
      existing.ev.affected_count = Math.max(prev, ev.affected_count);
    }
  }

  const merged: G71MergedFinding[] = [];
  for (const { severity, ev, urls, sources } of map.values()) {
    const urlArr = [...urls].sort();
    const issueType = String(ev.issue_type ?? "unknown");
    const methods = matchedMethodsFromEv(ev);
    const affectedCount =
      urlArr.length > 0 ? urlArr.length : typeof ev.affected_count === "number" ? ev.affected_count : 1;

    merged.push({
      severity,
      baseUrl: String(ev.base_url ?? "—"),
      issueType,
      issueLabel: issueTypeLabel(issueType),
      reason: String(ev.reason ?? issueType),
      matchedMethods: methods,
      allowHeader: ev.allow_header != null ? String(ev.allow_header) : null,
      httpMethod: ev.http_method != null ? String(ev.http_method) : null,
      affectedCount,
      affectedUrls: urlArr,
      sampleUrl: urlArr[0] ?? (ev.url != null ? String(ev.url) : null),
      sources: [...sources].sort() as ("httpx" | "zap")[],
      httpStatus: ev.status != null ? (ev.status as string | number) : null,
    });
  }

  merged.sort((a, b) => {
    const base = a.baseUrl.localeCompare(b.baseUrl);
    if (base !== 0) return base;
    return issueSortKey(a.issueType) - issueSortKey(b.issueType);
  });

  return { merged, other };
}

export function groupG71ByBaseUrl(merged: G71MergedFinding[]): G71BaseUrlGroup[] {
  const groups = new Map<string, G71BaseUrlGroup>();

  for (const f of merged) {
    let g = groups.get(f.baseUrl);
    if (!g) {
      g = {
        baseUrl: f.baseUrl,
        displayLabel: formatG71BaseLabel(f.baseUrl),
        findings: [],
      };
      groups.set(f.baseUrl, g);
    }
    g.findings.push(f);
  }

  return [...groups.values()].sort((a, b) => a.displayLabel.localeCompare(b.displayLabel));
}

export function formatMethodsLabel(methods: string[]): string {
  if (methods.length === 0) return "—";
  return methods.join(", ");
}

export function truncateAllowHeader(value: string | null, max = 48): string {
  if (!value) return "—";
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}
