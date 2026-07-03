/** Transform 3-4 admin separation findings into compact report rows. */

export type G34Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export type G34RowKind = "issue" | "positive" | "info";

export const G34_RULE_LABELS: Record<string, string> = {
  "3-4-same-login-url": "동일 로그인 URL",
  "3-4-login-same-host": "로그인 동일 서버",
  "3-4-ui-same-server": "Admin UI 동일 base",
  "3-4-api-same-server": "Admin API 동일 origin",
  "3-4-guessable-path": "추측 가능 admin 경로",
  "3-4-host-separated": "서브도메인 분리",
};

const G34_RULE_COPY: Record<string, { category: string; problem: string }> = {
  "3-4-same-login-url": {
    category: "로그인",
    problem: "user·admin이 같은 로그인 URL을 공유",
  },
  "3-4-login-same-host": {
    category: "로그인",
    problem: "user·admin 로그인 API가 같은 host:port (경로만 분리)",
  },
  "3-4-ui-same-server": {
    category: "Admin UI",
    problem: "관리자 화면이 사용자 웹과 같은 base URL",
  },
  "3-4-api-same-server": {
    category: "Admin API",
    problem: "관리자 API가 사용자 API와 같은 origin",
  },
  "3-4-guessable-path": {
    category: "경로명",
    problem: "admin 등 추측하기 쉬운 URL 패턴 존재",
  },
  "3-4-host-separated": {
    category: "분리",
    problem: "admin 전용 서브도메인으로 분리됨",
  },
};

const G34_RULE_KIND: Record<string, G34RowKind> = {
  "3-4-same-login-url": "issue",
  "3-4-login-same-host": "issue",
  "3-4-ui-same-server": "issue",
  "3-4-api-same-server": "issue",
  "3-4-guessable-path": "info",
  "3-4-host-separated": "positive",
};

export type G34Overview = {
  userLogins: number | null;
  adminLogins: number | null;
  adminUiPaths: number | null;
  adminApiPaths: number | null;
  mediumCount: number | null;
  highCount: number | null;
  guessablePaths: number | null;
  hasSubdomainSeparation: boolean;
  inventoryScope: string | null;
};

export type G34SampleRow = {
  label: string;
  value: string;
};

export type G34Row = {
  rowKey: string;
  ruleId: string;
  ruleLabel: string;
  categoryLabel: string;
  problemSummary: string;
  scaleSummary: string;
  sampleHint: string | null;
  kind: G34RowKind;
  severity: string;
  impact: string;
  trigger: string | null;
  count: number | null;
  samples: G34SampleRow[];
  message: string;
};

function formatOriginCompact(raw: string): string {
  try {
    const u = new URL(raw);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return raw.replace(/^https?:\/\//i, "").replace(/\/$/, "");
  }
}

function formatOriginsCompact(origins: string[]): string {
  const labels = [...new Set(origins.map(formatOriginCompact).filter(Boolean))];
  if (labels.length === 0) return "—";
  if (labels.length <= 4) return labels.join(", ");
  return `${labels.slice(0, 3).join(", ")} 외 ${labels.length - 3}`;
}

function pathFromValue(raw: string): string {
  try {
    return new URL(raw).pathname || "/";
  } catch {
    return raw;
  }
}

function buildSampleHint(samples: G34SampleRow[], max = 3): string | null {
  const paths = [
    ...new Set(
      samples
        .map((s) => {
          if (s.label.startsWith("GET ") || s.label.startsWith("POST ")) return s.label.split(" ").slice(1).join(" ");
          if (s.label === "tokens") return null;
          if (s.label.includes("/")) return s.label;
          return pathFromValue(s.value);
        })
        .filter(Boolean),
    ),
  ];
  if (paths.length === 0) return null;
  if (paths.length <= max) return paths.join(", ");
  return `${paths.slice(0, max).join(", ")} 외 ${paths.length - max}`;
}

function severityRank(sev: string): number {
  if (sev === "high") return 3;
  if (sev === "medium") return 2;
  if (sev === "low") return 1;
  return 0;
}

const KIND_ORDER: Record<G34RowKind, number> = { issue: 0, info: 1, positive: 2 };

export function buildG34Overview(stats?: Record<string, unknown> | null): G34Overview {
  const bySev = (stats?.by_severity as Record<string, number> | undefined) ?? {};
  const pairs = stats?.admin_subdomain_pairs;
  return {
    userLogins: typeof stats?.user_login_entries === "number" ? stats.user_login_entries : null,
    adminLogins: typeof stats?.admin_login_entries === "number" ? stats.admin_login_entries : null,
    adminUiPaths: typeof stats?.admin_frontend_paths === "number" ? stats.admin_frontend_paths : null,
    adminApiPaths: typeof stats?.admin_api_paths === "number" ? stats.admin_api_paths : null,
    mediumCount: typeof bySev.medium === "number" ? bySev.medium : null,
    highCount: typeof bySev.high === "number" ? bySev.high : null,
    guessablePaths: typeof stats?.guessable_paths === "number" ? stats.guessable_paths : null,
    hasSubdomainSeparation: Array.isArray(pairs) && pairs.length > 0,
    inventoryScope: stats?.inventory_scope != null ? String(stats.inventory_scope) : null,
  };
}

export function overviewSummaryLines(o: G34Overview): string[] {
  const lines: string[] = [];
  if (o.userLogins != null || o.adminLogins != null) {
    lines.push(`login user ${o.userLogins ?? 0} / admin ${o.adminLogins ?? 0}`);
  }
  if (o.adminUiPaths != null) lines.push(`admin UI ${o.adminUiPaths}`);
  if (o.adminApiPaths != null) lines.push(`admin API ${o.adminApiPaths}`);
  if (o.highCount != null && o.highCount > 0) lines.push(`high ${o.highCount}`);
  if (o.mediumCount != null && o.mediumCount > 0) lines.push(`medium ${o.mediumCount}`);
  if (o.guessablePaths != null && o.guessablePaths > 0) lines.push(`guessable ${o.guessablePaths}`);
  return lines;
}

function asStringList(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map(String).filter(Boolean);
}

function asSampleRows(v: unknown): G34SampleRow[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((x) => x && typeof x === "object")
    .map((raw) => {
      const row = raw as Record<string, unknown>;
      const path = row.path != null ? String(row.path) : "";
      const base = row.base_url != null ? String(row.base_url) : "";
      const method = row.method != null ? String(row.method) : "";
      const tokens = row.tokens != null ? String(row.tokens) : "";
      if (path && base) {
        return {
          label: method ? `${method} ${path}` : path,
          value: base,
        };
      }
      if (path) return { label: path, value: tokens || base || "—" };
      return null;
    })
    .filter((x): x is G34SampleRow => x != null);
}

export function parseG34Row(f: G34Finding): G34Row | null {
  const ev = f.evidence;
  if (!ev?.rule_id) return null;
  const ruleId = String(ev.rule_id);
  const kind = G34_RULE_KIND[ruleId] ?? "info";
  const total = typeof ev.total === "number" ? ev.total : null;
  const trigger = ev.trigger != null ? String(ev.trigger) : null;

  let impact = "—";
  let scaleSummary = "—";
  const samples: G34SampleRow[] = [];
  const copy = G34_RULE_COPY[ruleId] ?? { category: "기타", problem: f.message };

  switch (ruleId) {
    case "3-4-same-login-url": {
      const urls = asStringList(ev.urls);
      scaleSummary = urls.length > 0 ? `URL ${urls.length}개` : "공유";
      impact = scaleSummary;
      for (const url of urls) samples.push({ label: "login", value: url });
      break;
    }
    case "3-4-login-same-host": {
      const origins = asStringList(ev.origins);
      scaleSummary =
        origins.length > 0 ? `origin ${origins.length}개 · ${formatOriginsCompact(origins)}` : "path-only";
      impact = scaleSummary;
      for (const o of origins) samples.push({ label: "origin", value: o });
      for (const url of asStringList(ev.user_login_urls)) {
        samples.push({ label: "user login", value: url });
      }
      for (const url of asStringList(ev.admin_login_urls)) {
        samples.push({ label: "admin login", value: url });
      }
      break;
    }
    case "3-4-ui-same-server": {
      scaleSummary = total != null ? `UI ${total}건` : "—";
      impact = scaleSummary;
      samples.push(...asSampleRows(ev.samples));
      break;
    }
    case "3-4-api-same-server": {
      scaleSummary = total != null ? `API ${total}건` : "—";
      impact = scaleSummary;
      samples.push(...asSampleRows(ev.samples));
      break;
    }
    case "3-4-guessable-path": {
      scaleSummary = total != null ? `경로 ${total}건` : "—";
      impact = scaleSummary;
      samples.push(...asSampleRows(ev.samples));
      const tokens = asStringList(ev.tokens);
      if (tokens.length > 0) {
        samples.unshift({ label: "tokens", value: tokens.join(", ") });
      }
      break;
    }
    case "3-4-host-separated": {
      const adminHost = ev.admin_host != null ? String(ev.admin_host) : "";
      const userHost = ev.user_host != null ? String(ev.user_host) : "";
      scaleSummary = adminHost && userHost ? `${adminHost} / ${userHost}` : "분리됨";
      impact = scaleSummary;
      if (userHost) samples.push({ label: "user", value: userHost });
      if (adminHost) samples.push({ label: "admin", value: adminHost });
      break;
    }
    default:
      scaleSummary = total != null ? `${total}건` : "—";
      impact = scaleSummary;
  }

  const sampleHint = buildSampleHint(samples);

  return {
    rowKey: `${ruleId}|${scaleSummary}|${samples.map((s) => s.value).join("|")}`,
    ruleId,
    ruleLabel: G34_RULE_LABELS[ruleId] ?? ruleId.replace(/^3-4-/, ""),
    categoryLabel: copy.category,
    problemSummary: copy.problem,
    scaleSummary,
    sampleHint,
    kind,
    severity: f.severity,
    impact,
    trigger,
    count: total,
    samples,
    message: f.message,
  };
}

export function parseG34Findings(findings: G34Finding[]): {
  rows: G34Row[];
  other: G34Finding[];
} {
  const rows: G34Row[] = [];
  const other: G34Finding[] = [];
  for (const f of findings) {
    const row = parseG34Row(f);
    if (row) rows.push(row);
    else other.push(f);
  }
  rows.sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    const kind = KIND_ORDER[a.kind] - KIND_ORDER[b.kind];
    if (kind !== 0) return kind;
    return a.ruleLabel.localeCompare(b.ruleLabel);
  });
  return { rows, other };
}

export function groupG34ByKind(rows: G34Row[]): { kind: G34RowKind; label: string; rows: G34Row[] }[] {
  const labels: Record<G34RowKind, string> = {
    issue: "분리 이슈",
    info: "참고",
    positive: "양호",
  };
  const order: G34RowKind[] = ["issue", "info", "positive"];
  const map = new Map<G34RowKind, G34Row[]>();
  for (const row of rows) {
    const list = map.get(row.kind) ?? [];
    list.push(row);
    map.set(row.kind, list);
  }
  return order
    .filter((k) => map.has(k))
    .map((k) => ({ kind: k, label: labels[k], rows: map.get(k)! }));
}
