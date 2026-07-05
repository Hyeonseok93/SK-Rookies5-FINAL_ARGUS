/** Transform 3-5 search-engine inventory findings into compact report rows. */

export type G35Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export type G35Overview = {
  probeMode: string | null;
  robotsProbed: number | null;
  robotsPresent: number | null;
  robotsMissing: number | null;
  skippedApiBases: number | null;
  pagesProbed: number | null;
  anonNoindex: number | null;
  anonNofollow: number | null;
  anonNoDirective: number | null;
  authNoindex: number | null;
  authNofollow: number | null;
  authNoDirective: number | null;
  authPasses: number | null;
  frontendBases: number | null;
  inventoryFallback: boolean;
};

export type G35RobotsRow = {
  rowKey: string;
  baseUrl: string;
  baseLabel: string;
  status: "present" | "missing" | "unreachable";
  statusLabel: string;
  disallowCount: number;
  allowCount: number;
  sitemapCount: number;
  httpStatus: string | number | null;
  url: string | null;
};

export type G35PageRow = {
  rowKey: string;
  path: string;
  url: string;
  baseLabel: string;
  directiveLabel: string;
  authLabel: string;
  httpStatus: string | number | null;
  metaRobots: string | null;
  xRobotsTag: string | null;
};

export function formatG35BaseLabel(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return baseUrl.replace(/^https?:\/\//i, "").replace(/\/$/, "");
  }
}

export function formatG35AuthLabel(authMode: string): string {
  const mode = authMode.trim();
  if (!mode || mode === "anonymous") return "anonymous";
  if (mode.startsWith("authenticated:")) {
    const parts = mode.split(":");
    if (parts.length >= 3) return parts.slice(1, -1).join(":") || parts[1] || mode;
    return parts[1] ?? mode;
  }
  return mode;
}

function pathFromUrl(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

export function buildG35Overview(stats?: Record<string, unknown> | null): G35Overview {
  const robots = (stats?.robots as Record<string, unknown> | undefined) ?? {};
  const anon = (stats?.pages_anonymous as Record<string, unknown> | undefined) ?? {};
  const auth = (stats?.pages_authenticated as Record<string, unknown> | undefined) ?? {};
  const authSessions = typeof stats?.auth_sessions === "number" ? stats.auth_sessions : null;

  return {
    probeMode: stats?.probe_mode != null ? String(stats.probe_mode) : null,
    robotsProbed: typeof robots.robots_probed === "number" ? robots.robots_probed : null,
    robotsPresent: typeof robots.robots_present === "number" ? robots.robots_present : null,
    robotsMissing: typeof robots.robots_missing === "number" ? robots.robots_missing : null,
    skippedApiBases: typeof robots.skipped_api_bases === "number" ? robots.skipped_api_bases : null,
    pagesProbed: typeof anon.pages_probed === "number" ? anon.pages_probed : null,
    anonNoindex: typeof anon.with_noindex === "number" ? anon.with_noindex : null,
    anonNofollow: typeof anon.with_nofollow === "number" ? anon.with_nofollow : null,
    anonNoDirective: typeof anon.without_robots_directive === "number" ? anon.without_robots_directive : null,
    authNoindex: typeof auth.with_noindex === "number" ? auth.with_noindex : null,
    authNofollow: typeof auth.with_nofollow === "number" ? auth.with_nofollow : null,
    authNoDirective: typeof auth.without_robots_directive === "number" ? auth.without_robots_directive : null,
    authPasses: authSessions != null ? 1 + authSessions : null,
    frontendBases: typeof stats?.frontend_bases === "number" ? stats.frontend_bases : null,
    inventoryFallback: Boolean(stats?.inventory_fallback),
  };
}

export function extractG35RobotsRows(findings: G35Finding[]): G35RobotsRow[] {
  const rows: G35RobotsRow[] = [];
  for (const f of findings) {
    const ev = f.evidence;
    if (!ev || ev.kind !== "robots_txt") continue;
    const baseUrl = String(ev.base_url ?? "");
    const present = ev.present === true;
    const unreachable = Boolean(ev.error);
    const status: G35RobotsRow["status"] = unreachable
      ? "unreachable"
      : present
        ? "present"
        : "missing";
    const statusLabels = {
      present: "있음",
      missing: "없음",
      unreachable: "접근 불가",
    };
    rows.push({
      rowKey: baseUrl || String(ev.url ?? f.message),
      baseUrl,
      baseLabel: formatG35BaseLabel(baseUrl),
      status,
      statusLabel: statusLabels[status],
      disallowCount: Array.isArray(ev.disallow_paths) ? ev.disallow_paths.length : 0,
      allowCount: Array.isArray(ev.allow_paths) ? ev.allow_paths.length : 0,
      sitemapCount: Array.isArray(ev.sitemaps) ? ev.sitemaps.length : 0,
      httpStatus: ev.http_status as string | number | null,
      url: ev.url != null ? String(ev.url) : null,
    });
  }
  return rows.sort((a, b) => a.baseLabel.localeCompare(b.baseLabel));
}

export function extractG35PageRows(findings: G35Finding[]): G35PageRow[] {
  const rows: G35PageRow[] = [];
  for (const f of findings) {
    const ev = f.evidence;
    if (!ev || ev.kind !== "page_robots") continue;
    const url = String(ev.url ?? "");
    const parts: string[] = [];
    if (ev.has_noindex) parts.push("noindex");
    if (ev.has_nofollow) parts.push("nofollow");
    rows.push({
      rowKey: `${ev.auth_mode}|${url}`,
      path: ev.path != null ? String(ev.path) : pathFromUrl(url),
      url,
      baseLabel: formatG35BaseLabel(String(ev.base_url ?? "")),
      directiveLabel: parts.join(", ") || "—",
      authLabel: formatG35AuthLabel(String(ev.auth_mode ?? "anonymous")),
      httpStatus: ev.http_status as string | number | null,
      metaRobots: ev.meta_robots != null ? String(ev.meta_robots) : null,
      xRobotsTag: ev.x_robots_tag != null ? String(ev.x_robots_tag) : null,
    });
  }
  return rows.sort((a, b) => a.path.localeCompare(b.path));
}

export function filterG35DisplayFindings(findings: G35Finding[]): {
  robots: G35Finding[];
  pages: G35Finding[];
  other: G35Finding[];
} {
  const robots: G35Finding[] = [];
  const pages: G35Finding[] = [];
  const other: G35Finding[] = [];
  for (const f of findings) {
    const kind = f.evidence?.kind;
    if (kind === "robots_txt") robots.push(f);
    else if (kind === "page_robots") pages.push(f);
    else if (kind === "page_inventory_summary") continue;
    else other.push(f);
  }
  return { robots, pages, other };
}

export function extractG35InventorySummaryRows(findings: G35Finding[]): {
  rowKey: string;
  authLabel: string;
  pagesProbed: number;
  noindex: number;
  nofollow: number;
  noDirective: number;
  unreachable: number;
  indexableSample: string[];
}[] {
  const rows: {
    rowKey: string;
    authLabel: string;
    pagesProbed: number;
    noindex: number;
    nofollow: number;
    noDirective: number;
    unreachable: number;
    indexableSample: string[];
  }[] = [];
  for (const f of findings) {
    const ev = f.evidence;
    if (!ev || ev.kind !== "page_inventory_summary") continue;
    const authMode = String(ev.auth_mode ?? "anonymous");
    rows.push({
      rowKey: authMode,
      authLabel: formatG35AuthLabel(authMode),
      pagesProbed: typeof ev.pages_probed === "number" ? ev.pages_probed : 0,
      noindex: typeof ev.with_noindex === "number" ? ev.with_noindex : 0,
      nofollow: typeof ev.with_nofollow === "number" ? ev.with_nofollow : 0,
      noDirective:
        typeof ev.without_robots_directive === "number" ? ev.without_robots_directive : 0,
      unreachable: typeof ev.unreachable === "number" ? ev.unreachable : 0,
      indexableSample: Array.isArray(ev.indexable_urls_sample)
        ? ev.indexable_urls_sample.map(String).filter(Boolean)
        : [],
    });
  }
  return rows.sort((a, b) => a.authLabel.localeCompare(b.authLabel));
}

export function pathFromProbeUrl(url: string): string {
  return pathFromUrl(url);
}

export type G35SummaryTone = "ok" | "warn" | "bad" | "info";

export type G35IssueSummaryRow = {
  rowKey: string;
  checkLabel: string;
  issueLabel: string;
  scope: string;
  pathHint: string | null;
  tone: "warn" | "bad";
};

export type G35PassNote = {
  robotsOk: string[];
  pagesOk: string | null;
};

function formatPathHint(paths: string[], max = 3): string | null {
  const unique = [...new Set(paths.filter(Boolean))];
  if (unique.length === 0) return null;
  if (unique.length <= max) return unique.join(", ");
  return `${unique.slice(0, max).join(", ")} 외 ${unique.length - max}`;
}

export function buildG35IssueSummary(
  robotsRows: G35RobotsRow[],
  scopeRows: ReturnType<typeof extractG35InventorySummaryRows>,
): G35IssueSummaryRow[] {
  const rows: G35IssueSummaryRow[] = [];

  for (const r of robotsRows) {
    if (r.status === "present") continue;
    const tone: "warn" | "bad" = r.status === "missing" ? "warn" : "bad";
    rows.push({
      rowKey: `robots-${r.rowKey}`,
      checkLabel: `robots.txt · ${r.baseLabel}`,
      issueLabel: r.status === "missing" ? "파일 없음" : "접근 불가",
      scope: r.httpStatus != null ? `HTTP ${r.httpStatus}` : "—",
      pathHint: null,
      tone,
    });
  }

  const anon = scopeRows.find((r) => r.authLabel === "anonymous");
  if (anon && anon.noDirective > 0) {
    const paths = anon.indexableSample.map(pathFromUrl);
    rows.push({
      rowKey: "pages-anon",
      checkLabel: "페이지 meta · 비로그인",
      issueLabel: "noindex / nofollow 없음",
      scope: `${anon.noDirective}/${anon.pagesProbed} 페이지`,
      pathHint: formatPathHint(paths),
      tone: "warn",
    });
  }

  const authRows = scopeRows.filter((r) => r.authLabel !== "anonymous");
  const authNoDirective = authRows.reduce((s, r) => s + r.noDirective, 0);
  if (authNoDirective > 0) {
    rows.push({
      rowKey: "pages-auth",
      checkLabel: `페이지 meta · 로그인 ${authRows.length}계정`,
      issueLabel: "noindex / nofollow 없음",
      scope: `${authNoDirective}건`,
      pathHint: null,
      tone: "warn",
    });
  }

  const toneOrder = { bad: 0, warn: 1 };
  rows.sort((a, b) => toneOrder[a.tone] - toneOrder[b.tone]);
  return rows;
}

export function buildG35PassNotes(
  robotsRows: G35RobotsRow[],
  scopeRows: ReturnType<typeof extractG35InventorySummaryRows>,
): G35PassNote {
  const robotsOk = robotsRows
    .filter((r) => r.status === "present")
    .map((r) => `${r.baseLabel} robots.txt 있음`);

  const authRows = scopeRows.filter((r) => r.authLabel !== "anonymous");
  const authNoDirective = authRows.reduce((s, r) => s + r.noDirective, 0);
  let pagesOk: string | null = null;
  if (authRows.length > 0 && authNoDirective === 0) {
    pagesOk = `로그인 ${authRows.length}계정 — 지침 없음 0`;
  }

  return { robotsOk, pagesOk };
}

/** @deprecated use buildG35IssueSummary — kept for tests if any */
export function buildG35FindingsSummary(
  robotsRows: G35RobotsRow[],
  scopeRows: ReturnType<typeof extractG35InventorySummaryRows>,
  _overview: G35Overview,
  _pageRows: G35PageRow[],
): G35IssueSummaryRow[] {
  return buildG35IssueSummary(robotsRows, scopeRows);
}

export function overviewSummaryLines(o: G35Overview): string[] {
  const lines: string[] = [];
  if (o.robotsProbed != null) {
    lines.push(`robots ${o.robotsPresent ?? 0}/${o.robotsProbed}`);
  }
  if (o.pagesProbed != null) lines.push(`pages ${o.pagesProbed}`);
  if (o.anonNoindex != null || o.authNoindex != null) {
    lines.push(`noindex anon ${o.anonNoindex ?? 0} · auth ${o.authNoindex ?? 0}`);
  }
  if (o.probeMode) lines.push(o.probeMode);
  if (o.authPasses != null) lines.push(`${o.authPasses} passes`);
  return lines;
}
