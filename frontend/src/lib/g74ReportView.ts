/** Transform 7-4 diagnosis findings into matrix + grouped views. */

export type G74Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export type G74MatrixColumn =
  | "csp"
  | "hsts"
  | "xframe"
  | "nosniff"
  | "referrer"
  | "permissions"
  | "cookie";

export const G74_MATRIX_COLUMNS: { id: G74MatrixColumn; label: string }[] = [
  { id: "csp", label: "CSP" },
  { id: "hsts", label: "HSTS" },
  { id: "xframe", label: "X-Frame" },
  { id: "nosniff", label: "nosniff" },
  { id: "referrer", label: "Referrer" },
  { id: "permissions", label: "Permissions" },
  { id: "cookie", label: "Cookie" },
];

const CHECK_TYPE_TO_COLUMN: Record<string, G74MatrixColumn> = {
  missing_csp: "csp",
  missing_hsts: "hsts",
  missing_x_frame_options: "xframe",
  weak_x_frame_options: "xframe",
  missing_nosniff: "nosniff",
  missing_referrer_policy: "referrer",
  missing_permissions_policy: "permissions",
  cookie_missing_secure: "cookie",
  cookie_missing_httponly: "cookie",
  cookie_missing_samesite: "cookie",
  cookie_weak_samesite: "cookie",
};

export type G74MergedFinding = {
  severity: string;
  baseUrl: string;
  checkType: string;
  column: G74MatrixColumn | null;
  header: string | null;
  cookieName: string | null;
  reason: string;
  remediation: string | null;
  affectedCount: number;
  affectedUrls: string[];
  sampleUrl: string | null;
  sources: ("httpx" | "zap")[];
  httpStatus: string | number | null;
  headerValue: string | null;
};

export type G74BaseUrlGroup = {
  baseUrl: string;
  displayLabel: string;
  maxAffectedCount: number;
  findings: G74MergedFinding[];
};

export type G74MatrixRow = {
  baseUrl: string;
  displayLabel: string;
  maxAffectedCount: number;
  cells: Partial<Record<G74MatrixColumn, { severity: string; count: number }>>;
};

function isG74SecurityFinding(f: G74Finding): boolean {
  const ev = f.evidence;
  if (!ev) return false;
  return ev.rule_id === "7-4-weak-security" || typeof ev.check_type === "string";
}

function mergeKey(f: G74Finding): string | null {
  const ev = f.evidence;
  if (!ev?.check_type) return null;
  return [
    f.severity,
    String(ev.base_url ?? ""),
    String(ev.check_type),
    String(ev.header ?? ""),
    String(ev.cookie_name ?? ""),
    String(ev.reason ?? ""),
  ].join("|");
}

function engineSource(ev: Record<string, unknown>): "httpx" | "zap" | null {
  const engine = String(ev.engine ?? ev.source ?? "");
  if (engine === "httpx") return "httpx";
  if (engine === "zap") return "zap";
  return null;
}

export function mergeG74Findings(findings: G74Finding[]): {
  merged: G74MergedFinding[];
  other: G74Finding[];
} {
  const other: G74Finding[] = [];
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
    if (!isG74SecurityFinding(f)) {
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
    for (const u of urlList) {
      if (u) existing.urls.add(u);
    }
    const src = engineSource(ev);
    if (src) existing.sources.add(src);
    if (typeof ev.affected_count === "number") {
      const prev = Number(existing.ev.affected_count ?? 0);
      existing.ev.affected_count = Math.max(prev, ev.affected_count);
    }
  }

  const merged: G74MergedFinding[] = [];
  for (const { severity, ev, urls, sources } of map.values()) {
    const checkType = String(ev.check_type ?? "");
    const urlArr = [...urls].sort();
    const affectedCount =
      urlArr.length > 0 ? urlArr.length : typeof ev.affected_count === "number" ? ev.affected_count : 1;

    merged.push({
      severity,
      baseUrl: String(ev.base_url ?? "—"),
      checkType,
      column: CHECK_TYPE_TO_COLUMN[checkType] ?? null,
      header: ev.header != null ? String(ev.header) : null,
      cookieName: ev.cookie_name != null ? String(ev.cookie_name) : null,
      reason: String(ev.reason ?? checkType),
      remediation: ev.remediation != null ? String(ev.remediation) : null,
      affectedCount,
      affectedUrls: urlArr,
      sampleUrl: urlArr[0] ?? (ev.url != null ? String(ev.url) : null),
      sources: [...sources].sort() as ("httpx" | "zap")[],
      httpStatus: ev.http_status != null ? (ev.http_status as string | number) : null,
      headerValue: ev.header_value != null ? String(ev.header_value) : null,
    });
  }

  merged.sort((a, b) => {
    const base = a.baseUrl.localeCompare(b.baseUrl);
    if (base !== 0) return base;
    const colA = a.column ?? "zzz";
    const colB = b.column ?? "zzz";
    return colA.localeCompare(colB);
  });

  return { merged, other };
}

export function formatG74BaseLabel(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return baseUrl.replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
}

export function buildG74Matrix(merged: G74MergedFinding[]): G74MatrixRow[] {
  const byBase = new Map<string, G74MatrixRow>();

  for (const f of merged) {
    if (!f.column) continue;
    let row = byBase.get(f.baseUrl);
    if (!row) {
      row = {
        baseUrl: f.baseUrl,
        displayLabel: formatG74BaseLabel(f.baseUrl),
        maxAffectedCount: 0,
        cells: {},
      };
      byBase.set(f.baseUrl, row);
    }
    row.maxAffectedCount = Math.max(row.maxAffectedCount, f.affectedCount);
    const prev = row.cells[f.column];
    if (!prev || severityRank(f.severity) > severityRank(prev.severity)) {
      row.cells[f.column] = { severity: f.severity, count: f.affectedCount };
    } else if (prev) {
      prev.count = Math.max(prev.count, f.affectedCount);
    }
  }

  return [...byBase.values()].sort((a, b) => a.displayLabel.localeCompare(b.displayLabel));
}

function severityRank(sev: string): number {
  if (sev === "high") return 3;
  if (sev === "medium") return 2;
  if (sev === "low") return 1;
  return 0;
}

export function groupG74ByBaseUrl(merged: G74MergedFinding[]): G74BaseUrlGroup[] {
  const groups = new Map<string, G74BaseUrlGroup>();

  for (const f of merged) {
    let g = groups.get(f.baseUrl);
    if (!g) {
      g = {
        baseUrl: f.baseUrl,
        displayLabel: formatG74BaseLabel(f.baseUrl),
        maxAffectedCount: 0,
        findings: [],
      };
      groups.set(f.baseUrl, g);
    }
    g.findings.push(f);
    g.maxAffectedCount = Math.max(g.maxAffectedCount, f.affectedCount);
  }

  return [...groups.values()].sort((a, b) => a.displayLabel.localeCompare(b.displayLabel));
}

export function g74IssueLabel(f: G74MergedFinding): string {
  if (f.cookieName) return `cookie \`${f.cookieName}\``;
  if (f.header) return f.header;
  return f.checkType;
}
