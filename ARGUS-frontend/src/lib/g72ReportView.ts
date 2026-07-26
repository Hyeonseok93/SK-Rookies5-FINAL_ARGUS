/** Transform 7-2 diagnosis findings into URL-centric views. */

export type G72Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export const G72_LISTING_TYPE_LABELS: Record<string, string> = {
  nginx_autoindex: "nginx autoindex",
  apache_indexes: "Apache Index",
  iis: "IIS",
  tomcat_listings: "Tomcat",
  heuristic_links: "Heuristic",
  zap_directory_browsing: "Directory browsing",
  zap_passive_directory_browsing: "Directory browsing",
  unknown: "기타",
};

export type G72MergedFinding = {
  severity: string;
  baseUrl: string;
  listingType: string;
  listingLabel: string;
  reason: string;
  remediation: string | null;
  affectedCount: number;
  affectedUrls: string[];
  sampleUrl: string | null;
  sampleLabel: string | null;
  sources: ("httpx" | "zap")[];
  httpStatus: string | number | null;
  matchedPatterns: string[];
  fileLinkCount: number | null;
};

export type G72BaseUrlGroup = {
  baseUrl: string;
  displayLabel: string;
  maxAffectedCount: number;
  findings: G72MergedFinding[];
};

function isG72ListingFinding(f: G72Finding): boolean {
  const ev = f.evidence;
  if (!ev) return false;
  return ev.rule_id === "7-2-directory-listing" && typeof ev.listing_type === "string";
}

function isZapListingType(listingType: string): boolean {
  return listingType.startsWith("zap_");
}

function engineSource(ev: Record<string, unknown>): "httpx" | "zap" | null {
  const engine = String(ev.engine ?? ev.source ?? "");
  if (engine === "httpx") return "httpx";
  if (engine === "zap") return "zap";
  return null;
}

function primaryUrlFromEv(ev: Record<string, unknown>): string {
  const affected = ev.affected_urls;
  if (Array.isArray(affected) && affected.length > 0) {
    return String(affected[0]);
  }
  return String(ev.url ?? "");
}

function urlPathKey(url: string): string {
  try {
    const path = new URL(url).pathname;
    const trimmed = path.replace(/\/$/, "");
    return trimmed || "/";
  } catch {
    return url;
  }
}

function severityRank(sev: string): number {
  if (sev === "high") return 3;
  if (sev === "medium") return 2;
  if (sev === "low") return 1;
  return 0;
}

function pickListingType(current: string | undefined, next: string): string {
  if (!current) return next;
  if (isZapListingType(current) && !isZapListingType(next)) return next;
  if (!isZapListingType(current) && isZapListingType(next)) return current;
  return current;
}

export function formatG72BaseLabel(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return baseUrl.replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
}

export function listingTypeLabel(listingType: string): string {
  return G72_LISTING_TYPE_LABELS[listingType] ?? listingType;
}

export function formatG72Path(url: string | null): string {
  if (!url) return "—";
  try {
    const path = new URL(url).pathname;
    return path || "/";
  } catch {
    return url;
  }
}

function mergeKey(f: G72Finding): string | null {
  const ev = f.evidence;
  if (!ev?.listing_type) return null;
  const pathKey = urlPathKey(primaryUrlFromEv(ev));
  return `${String(ev.base_url ?? "")}|${pathKey}`;
}

export function mergeG72Findings(findings: G72Finding[]): {
  merged: G72MergedFinding[];
  other: G72Finding[];
} {
  const other: G72Finding[] = [];
  const map = new Map<
    string,
    {
      severity: string;
      ev: Record<string, unknown>;
      listingType: string;
      urls: Set<string>;
      labels: Set<string>;
      sources: Set<"httpx" | "zap">;
      patterns: Set<string>;
    }
  >();

  for (const f of findings) {
    if (!isG72ListingFinding(f)) {
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
    const label = String(ev.label ?? url);
    const affected = ev.affected_urls;
    const urlList = Array.isArray(affected) ? affected.map(String) : url ? [url] : [];
    const patterns = Array.isArray(ev.matched_patterns) ? ev.matched_patterns.map(String) : [];
    const listingType = String(ev.listing_type ?? "unknown");

    const existing = map.get(key);
    if (!existing) {
      map.set(key, {
        severity: f.severity,
        ev: { ...ev },
        listingType,
        urls: new Set(urlList.filter(Boolean)),
        labels: new Set(label ? [label] : []),
        sources: new Set(engineSource(ev) ? [engineSource(ev)!] : []),
        patterns: new Set(patterns),
      });
      continue;
    }
    if (severityRank(f.severity) > severityRank(existing.severity)) {
      existing.severity = f.severity;
    }
    existing.listingType = pickListingType(existing.listingType, listingType);
    for (const u of urlList) {
      if (u) existing.urls.add(u);
    }
    if (label) existing.labels.add(label);
    for (const p of patterns) existing.patterns.add(p);
    const src = engineSource(ev);
    if (src) existing.sources.add(src);
    if (ev.remediation && !existing.ev.remediation) {
      existing.ev.remediation = ev.remediation;
    }
    if (typeof ev.affected_count === "number") {
      const prev = Number(existing.ev.affected_count ?? 0);
      existing.ev.affected_count = Math.max(prev, ev.affected_count);
    }
    if (typeof ev.file_link_count === "number") {
      const prev = Number(existing.ev.file_link_count ?? 0);
      existing.ev.file_link_count = Math.max(prev, ev.file_link_count);
    }
  }

  const merged: G72MergedFinding[] = [];
  for (const { severity, ev, listingType, urls, labels, sources, patterns } of map.values()) {
    const urlArr = [...urls].sort();
    const labelArr = [...labels].sort();
    const affectedCount =
      urlArr.length > 0 ? urlArr.length : typeof ev.affected_count === "number" ? ev.affected_count : 1;

    merged.push({
      severity,
      baseUrl: String(ev.base_url ?? "—"),
      listingType,
      listingLabel: listingTypeLabel(listingType),
      reason: String(ev.reason ?? listingType),
      remediation: ev.remediation != null ? String(ev.remediation) : null,
      affectedCount,
      affectedUrls: urlArr,
      sampleUrl: urlArr[0] ?? (ev.url != null ? String(ev.url) : null),
      sampleLabel: labelArr[0] ?? null,
      sources: [...sources].sort() as ("httpx" | "zap")[],
      httpStatus: ev.http_status != null ? (ev.http_status as string | number) : null,
      matchedPatterns: [...patterns].sort(),
      fileLinkCount: typeof ev.file_link_count === "number" ? ev.file_link_count : null,
    });
  }

  merged.sort((a, b) => {
    const base = a.baseUrl.localeCompare(b.baseUrl);
    if (base !== 0) return base;
    return formatG72Path(a.sampleUrl).localeCompare(formatG72Path(b.sampleUrl));
  });

  return { merged, other };
}

export function groupG72ByBaseUrl(merged: G72MergedFinding[]): G72BaseUrlGroup[] {
  const groups = new Map<string, G72BaseUrlGroup>();

  for (const f of merged) {
    let g = groups.get(f.baseUrl);
    if (!g) {
      g = {
        baseUrl: f.baseUrl,
        displayLabel: formatG72BaseLabel(f.baseUrl),
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
