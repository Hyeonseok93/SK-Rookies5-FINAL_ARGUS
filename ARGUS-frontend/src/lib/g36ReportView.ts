/** Transform 3-6 backup/test file findings into compact report rows. */

export type G36Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export const G36_FILE_TYPE_LABELS: Record<string, string> = {
  backup_archive: "백업 아카이브",
  backup_sql: "SQL 덤프",
  env_secrets: "환경·비밀 파일",
  test_debug: "테스트·디버그",
  vcs_artifact: "VCS (.git 등)",
  log_file: "로그 파일",
  config_backup: "설정 백업",
  sensitive_file: "민감 파일",
};

function severityRank(sev: string): number {
  if (sev === "high") return 3;
  if (sev === "medium") return 2;
  if (sev === "low") return 1;
  return 0;
}

function maxSeverity(a: string, b: string): string {
  return severityRank(a) >= severityRank(b) ? a : b;
}

export function fileTypeLabel(fileType: string): string {
  return G36_FILE_TYPE_LABELS[fileType] ?? fileType.replace(/_/g, " ");
}

export function formatG36AuthLabel(authMode: string): string {
  const mode = authMode.trim();
  if (!mode || mode === "anonymous") return "anonymous";
  if (mode.startsWith("authenticated:")) {
    const parts = mode.split(":");
    if (parts.length >= 3) return parts.slice(1, -1).join(":") || parts[1] || mode;
    return parts[1] ?? mode;
  }
  return mode;
}

export function formatG36BaseLabel(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return baseUrl.replace(/^https?:\/\//i, "").replace(/\/$/, "");
  }
}

function pathFromUrl(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

export type G36MergedFinding = {
  severity: string;
  fileType: string;
  fileTypeLabel: string;
  pathSummary: string;
  paths: string[];
  urls: string[];
  affectedCount: number;
  reason: string | null;
  authMode: string;
  authLabel: string;
  baseUrl: string;
  baseLabel: string;
  httpStatus: string | number | null;
  remediation: string | null;
  rowKey: string;
};

export type G36PassSummary = {
  probed: number | null;
  probeMode: string | null;
  wordlistTotal: number | null;
  authPasses: number | null;
  inventoryFallback: boolean;
};

export function buildG36PassSummary(stats?: Record<string, unknown> | null): G36PassSummary {
  const authSessions =
    typeof stats?.auth_sessions === "number" ? stats.auth_sessions : null;
  return {
    probed: typeof stats?.probed === "number" ? stats.probed : null,
    probeMode: stats?.probe_mode != null ? String(stats.probe_mode) : null,
    wordlistTotal: typeof stats?.wordlist_total === "number" ? stats.wordlist_total : null,
    authPasses: authSessions != null ? 1 + authSessions : null,
    inventoryFallback: Boolean(stats?.inventory_fallback),
  };
}

function isActionableFinding(f: G36Finding): boolean {
  const ev = f.evidence;
  if (!ev?.file_type) return false;
  if (f.severity === "info" && ev.error) return false;
  return f.severity === "high" || f.severity === "medium" || f.severity === "low";
}

function mergeKey(ev: Record<string, unknown>): string {
  return [
    String(ev.file_type ?? ""),
    String(ev.auth_mode ?? "anonymous"),
    String(ev.base_url ?? ""),
    String(ev.reason ?? ""),
    String(ev.trigger ?? ""),
  ].join("|");
}

export function mergeG36Findings(findings: G36Finding[]): {
  merged: G36MergedFinding[];
  other: G36Finding[];
} {
  const groups = new Map<string, G36MergedFinding>();
  const other: G36Finding[] = [];

  for (const f of findings) {
    const ev = f.evidence;
    if (!ev || !isActionableFinding(f)) {
      other.push(f);
      continue;
    }

    const key = mergeKey(ev);
    const path = ev.path != null ? String(ev.path) : "";
    const url = ev.url != null ? String(ev.url) : "";
    const affected = ev.affected_urls;
    const urls = Array.isArray(affected)
      ? [...new Set(affected.map(String).filter(Boolean))]
      : url
        ? [url]
        : [];
    const paths = [...new Set(urls.map(pathFromUrl).filter(Boolean))];
    if (path && !paths.includes(path)) paths.unshift(path);

    const existing = groups.get(key);
    if (!existing) {
      const count = typeof ev.affected_count === "number" ? ev.affected_count : paths.length || 1;
      groups.set(key, {
        severity: f.severity,
        fileType: String(ev.file_type),
        fileTypeLabel: fileTypeLabel(String(ev.file_type)),
        pathSummary: paths[0] ?? path ?? "—",
        paths,
        urls,
        affectedCount: count,
        reason: ev.reason != null ? String(ev.reason) : null,
        authMode: String(ev.auth_mode ?? "anonymous"),
        authLabel: formatG36AuthLabel(String(ev.auth_mode ?? "anonymous")),
        baseUrl: String(ev.base_url ?? ""),
        baseLabel: formatG36BaseLabel(String(ev.base_url ?? "")),
        httpStatus: ev.http_status as string | number | null,
        remediation: ev.remediation != null ? String(ev.remediation) : null,
        rowKey: key,
      });
      continue;
    }

    existing.severity = maxSeverity(existing.severity, f.severity);
    for (const p of paths) {
      if (!existing.paths.includes(p)) existing.paths.push(p);
    }
    for (const u of urls) {
      if (!existing.urls.includes(u)) existing.urls.push(u);
    }
    existing.affectedCount = Math.max(existing.affectedCount, existing.paths.length);
    if (!existing.remediation && ev.remediation) {
      existing.remediation = String(ev.remediation);
    }
  }

  const merged = [...groups.values()]
    .map((row) => ({
      ...row,
      pathSummary:
        row.paths.length > 1
          ? `${row.paths[0]} 외 ${row.paths.length - 1}건`
          : row.paths[0] ?? row.pathSummary,
      affectedCount: row.paths.length || row.affectedCount,
    }))
    .sort((a, b) => {
      const sev = severityRank(b.severity) - severityRank(a.severity);
      if (sev !== 0) return sev;
      return a.pathSummary.localeCompare(b.pathSummary);
    });

  return { merged, other };
}
