/** Transform 5-2 PII findings into compact report rows. */

export type G52Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export const G52_RULE_LABELS: Record<string, string> = {
  email_plain: "이메일 평문",
  phone_plain: "전화번호 평문",
  rrn_plain: "주민등록번호 평문",
  passport_plain: "여권번호 평문",
  card_plain: "카드번호 평문",
  account_plain: "계좌번호 평문",
  korean_name_plain: "이름 평문",
  bank_name_plain: "은행명 평문",
  path_structure: "경로 구조 노출",
  http_plain_sensitive: "HTTP 평문 전송",
};

export const G52_DIRECTION_LABELS: Record<string, string> = {
  response_body: "응답 본문",
  request_body: "요청 본문",
  request_url: "요청 URL",
  transport: "전송 계층",
};

export type G52MergedFinding = {
  severity: string;
  ruleId: string;
  ruleLabel: string;
  category: string;
  direction: string;
  directionLabel: string;
  method: string;
  apiPath: string;
  fieldPath: string | null;
  samples: string[];
  sampleUrl: string | null;
  authModes: string[];
  authSummary: string;
  remediation: string | null;
  sources: ("httpx")[];
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

function engineSource(ev: Record<string, unknown>): "httpx" | null {
  const engine = String(ev.engine ?? ev.source ?? "");
  return engine === "httpx" ? "httpx" : null;
}

export function formatG52ApiPath(url: string): string {
  try {
    const u = new URL(url);
    return `${u.pathname}${u.search}`;
  } catch {
    return url.replace(/^https?:\/\/[^/]+/i, "") || url;
  }
}

function authModesFromEvidence(ev: Record<string, unknown>): string[] {
  const modes = ev.auth_modes;
  if (Array.isArray(modes) && modes.length > 0) {
    return [...new Set(modes.map(String))].sort();
  }
  const single = ev.auth_mode;
  return single != null ? [String(single)] : [];
}

export function formatG52AuthSummary(modes: string[]): string {
  const emails = modes
    .filter((m) => m.startsWith("authenticated:"))
    .map((m) => m.split(":")[1])
    .filter(Boolean);
  const hasAnon = modes.includes("anonymous");
  if (emails.length === 0) return hasAnon ? "anonymous" : "—";
  if (emails.length === 1 && !hasAnon) return emails[0]!;
  if (hasAnon && emails.length > 0) return `anon + ${emails.length}계정`;
  return `${emails.length}계정`;
}

export function ruleLabel(ruleId: string): string {
  return G52_RULE_LABELS[ruleId] ?? ruleId;
}

export function directionLabel(direction: string): string {
  return G52_DIRECTION_LABELS[direction] ?? direction;
}

/** Collapse JSON array indices for summary merge (``members[0].email`` → ``members[*].email``). */
export function normalizeG52FieldPathForMerge(fieldPath: string | null | undefined): string {
  if (!fieldPath) return "";
  return fieldPath.replace(/\[\d+\]/g, "[*]");
}

function mergeKey(ev: Record<string, unknown>): string | null {
  const ruleId = ev.rule_id;
  if (!ruleId) return null;
  const url = String(ev.url ?? "");
  const apiPath = url ? formatG52ApiPath(url) : String(ev.endpoint_id ?? "");
  const fieldPath = normalizeG52FieldPathForMerge(
    ev.field_path != null ? String(ev.field_path) : null,
  );
  return [
    String(ruleId),
    String(ev.method ?? "").toUpperCase(),
    apiPath,
    String(ev.direction ?? ""),
    fieldPath,
  ].join("|");
}

export function formatG52SampleCount(samples: string[]): string {
  if (samples.length === 0) return "—";
  return `${samples.length}건`;
}

/** Display label for a single probe auth pass (raw ``auth_mode``). */
export function formatG52AuthLabel(authMode: string): string {
  const mode = authMode.trim();
  if (!mode || mode === "anonymous") return "anonymous";
  if (mode === "multiple") return "multiple";
  if (mode.startsWith("authenticated:")) {
    const parts = mode.split(":");
    if (parts.length >= 3) {
      return parts.slice(1, -1).join(":") || parts[1] || mode;
    }
    return parts[1] ?? mode;
  }
  return mode;
}

export function authColumnKey(authMode: string): string {
  return authMode.trim() || "anonymous";
}

function authColumnSortKey(label: string): string {
  if (label === "anonymous") return "0";
  return `1:${label.toLowerCase()}`;
}

export type G52RawHit = {
  severity: string;
  ruleId: string;
  ruleLabel: string;
  category: string;
  direction: string;
  directionLabel: string;
  method: string;
  apiPath: string;
  sampleUrl: string | null;
  fieldPath: string | null;
  authMode: string;
  authLabel: string;
  sample: string | null;
  statusCode: number | null;
};

export type G52AuthColumn = {
  key: string;
  label: string;
};

export type G52DetailCell = {
  samples: string[];
  statusCode: number | null;
  severity: string;
};

export type G52DetailRow = {
  rowKey: string;
  ruleId: string;
  ruleLabel: string;
  direction: string;
  directionLabel: string;
  fieldPath: string | null;
  severity: string;
  byAuth: Record<string, G52DetailCell>;
};

export type G52ApiDetailGroup = {
  groupKey: string;
  method: string;
  apiPath: string;
  sampleUrl: string | null;
  authColumns: G52AuthColumn[];
  rows: G52DetailRow[];
  hitCount: number;
};

function normalizeRawHit(raw: G52Finding): G52RawHit | null {
  const ev = raw.evidence;
  if (!ev?.rule_id) return null;
  const url = ev.url != null ? String(ev.url) : "";
  const authMode = String(ev.auth_mode ?? "anonymous");
  const status = ev.status_code;
  return {
    severity: raw.severity,
    ruleId: String(ev.rule_id),
    ruleLabel: ruleLabel(String(ev.rule_id)),
    category: String(ev.category ?? ""),
    direction: String(ev.direction ?? ""),
    directionLabel: directionLabel(String(ev.direction ?? "")),
    method: String(ev.method ?? "").toUpperCase(),
    apiPath: url ? formatG52ApiPath(url) : String(ev.endpoint_id ?? ""),
    sampleUrl: url || null,
    fieldPath: ev.field_path != null ? String(ev.field_path) : null,
    authMode,
    authLabel: formatG52AuthLabel(authMode),
    sample: ev.sample != null ? String(ev.sample) : null,
    statusCode: typeof status === "number" ? status : status != null ? Number(status) : null,
  };
}

/** Read pre-collapse hits from scan stats (new reports) or infer from findings (legacy). */
export function parseG52RawFindings(
  findings: G52Finding[],
  stats?: Record<string, unknown> | null,
): G52RawHit[] {
  const fromStats = stats?.raw_findings;
  if (Array.isArray(fromStats) && fromStats.length > 0) {
    const hits: G52RawHit[] = [];
    for (const row of fromStats) {
      if (!row || typeof row !== "object") continue;
      const rec = row as { severity?: string; evidence?: Record<string, unknown> };
      const evidence = rec.evidence;
      if (!evidence?.rule_id) continue;
      const hit = normalizeRawHit({
        severity: String(rec.severity ?? "info"),
        message: "",
        evidence,
      });
      if (hit) hits.push(hit);
    }
    return hits;
  }

  const hits: G52RawHit[] = [];
  for (const f of findings) {
    const hit = normalizeRawHit(f);
    if (!hit) continue;
    const modes = f.evidence?.auth_modes;
    if (Array.isArray(modes) && modes.length > 1) {
      for (const mode of modes) {
        hits.push({ ...hit, authMode: String(mode), authLabel: formatG52AuthLabel(String(mode)) });
      }
      continue;
    }
    hits.push(hit);
  }
  return hits;
}

function detailRowKey(hit: Pick<G52RawHit, "ruleId" | "direction" | "fieldPath">): string {
  return [
    hit.ruleId,
    hit.direction,
    normalizeG52FieldPathForMerge(hit.fieldPath),
  ].join("|");
}

function pushUniqueSample(samples: string[], sample: string | null) {
  if (sample && !samples.includes(sample)) samples.push(sample);
}

function apiGroupKey(hit: Pick<G52RawHit, "method" | "apiPath">): string {
  return `${hit.method}:${hit.apiPath}`;
}

/** Group raw hits by API, pivot auth passes into table columns (audit / replay). */
export function buildG52ApiDetailGroups(rawHits: G52RawHit[]): G52ApiDetailGroup[] {
  const groups = new Map<
    string,
    {
      method: string;
      apiPath: string;
      sampleUrl: string | null;
      authKeys: Set<string>;
      authLabels: Map<string, string>;
      rows: Map<string, G52DetailRow>;
      hitCount: number;
    }
  >();

  for (const hit of rawHits) {
    const gKey = apiGroupKey(hit);
    let group = groups.get(gKey);
    if (!group) {
      group = {
        method: hit.method,
        apiPath: hit.apiPath,
        sampleUrl: hit.sampleUrl,
        authKeys: new Set(),
        authLabels: new Map(),
        rows: new Map(),
        hitCount: 0,
      };
      groups.set(gKey, group);
    }
    group.hitCount += 1;
    if (!group.sampleUrl && hit.sampleUrl) group.sampleUrl = hit.sampleUrl;

    const authKey = authColumnKey(hit.authMode);
    group.authKeys.add(authKey);
    group.authLabels.set(authKey, hit.authLabel);

    const rKey = detailRowKey(hit);
    const fieldPattern = hit.fieldPath ? normalizeG52FieldPathForMerge(hit.fieldPath) : null;
    let row = group.rows.get(rKey);
    if (!row) {
      row = {
        rowKey: rKey,
        ruleId: hit.ruleId,
        ruleLabel: hit.ruleLabel,
        direction: hit.direction,
        directionLabel: hit.directionLabel,
        fieldPath: fieldPattern,
        severity: hit.severity,
        byAuth: {},
      };
      group.rows.set(rKey, row);
    }
    row.severity = maxSeverity(row.severity, hit.severity);
    const cell = row.byAuth[authKey];
    if (!cell) {
      row.byAuth[authKey] = {
        samples: hit.sample ? [hit.sample] : [],
        statusCode: hit.statusCode,
        severity: hit.severity,
      };
    } else {
      pushUniqueSample(cell.samples, hit.sample);
      cell.severity = maxSeverity(cell.severity, hit.severity);
      if (cell.statusCode == null && hit.statusCode != null) cell.statusCode = hit.statusCode;
    }
  }

  return [...groups.values()]
    .map((group) => {
      const authColumns: G52AuthColumn[] = [...group.authKeys]
        .map((key) => ({ key, label: group.authLabels.get(key) ?? key }))
        .sort((a, b) => authColumnSortKey(a.label).localeCompare(authColumnSortKey(b.label)));

      const rows = [...group.rows.values()].sort((a, b) => {
        const sev = severityRank(b.severity) - severityRank(a.severity);
        if (sev !== 0) return sev;
        const rule = a.ruleLabel.localeCompare(b.ruleLabel);
        if (rule !== 0) return rule;
        return (a.fieldPath ?? "").localeCompare(b.fieldPath ?? "");
      });

      return {
        groupKey: apiGroupKey(group),
        method: group.method,
        apiPath: group.apiPath,
        sampleUrl: group.sampleUrl,
        authColumns,
        rows,
        hitCount: group.hitCount,
      };
    })
    .sort((a, b) => {
      const path = a.apiPath.localeCompare(b.apiPath);
      if (path !== 0) return path;
      return a.method.localeCompare(b.method);
    });
}

export function mergeG52Findings(findings: G52Finding[]): {
  merged: G52MergedFinding[];
  other: G52Finding[];
} {
  const groups = new Map<string, G52MergedFinding>();
  const other: G52Finding[] = [];

  for (const f of findings) {
    const ev = f.evidence;
    if (!ev) {
      other.push(f);
      continue;
    }
    const key = mergeKey(ev);
    if (!key) {
      other.push(f);
      continue;
    }

    const ruleId = String(ev.rule_id);
    const direction = String(ev.direction ?? "");
    const sample = ev.sample != null ? String(ev.sample) : null;
    const authModes = authModesFromEvidence(ev);
    const src = engineSource(ev);

    const existing = groups.get(key);
    if (!existing) {
      const samples = sample ? [sample] : [];
      const rawFieldPath = ev.field_path != null ? String(ev.field_path) : null;
      groups.set(key, {
        severity: f.severity,
        ruleId,
        ruleLabel: ruleLabel(ruleId),
        category: String(ev.category ?? ""),
        direction,
        directionLabel: directionLabel(direction),
        method: String(ev.method ?? "").toUpperCase(),
        apiPath: formatG52ApiPath(String(ev.url ?? "")),
        fieldPath: rawFieldPath ? normalizeG52FieldPathForMerge(rawFieldPath) : null,
        samples,
        sampleUrl: ev.url != null ? String(ev.url) : null,
        authModes,
        authSummary: formatG52AuthSummary(authModes),
        remediation: ev.remediation != null ? String(ev.remediation) : null,
        sources: src ? [src] : [],
      });
      continue;
    }

    existing.severity = maxSeverity(existing.severity, f.severity);
    if (sample && !existing.samples.includes(sample)) {
      existing.samples.push(sample);
    }
    for (const mode of authModes) {
      if (!existing.authModes.includes(mode)) existing.authModes.push(mode);
    }
    existing.authModes.sort();
    existing.authSummary = formatG52AuthSummary(existing.authModes);
    if (src && !existing.sources.includes(src)) existing.sources.push(src);
    if (!existing.remediation && ev.remediation) {
      existing.remediation = String(ev.remediation);
    }
  }

  const merged = [...groups.values()].sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    const path = a.apiPath.localeCompare(b.apiPath);
    if (path !== 0) return path;
    return a.ruleId.localeCompare(b.ruleId);
  });

  return { merged, other };
}
