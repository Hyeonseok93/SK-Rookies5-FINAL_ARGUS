/** Transform 6-1 diagnosis summary groups into compact report views (SK Shielders 6-1 buckets). */

export type G61SkClass = "http" | "exception" | "dbms";

export type G61SummaryGroup = {
  group_key: string;
  severity: string;
  sk_class: G61SkClass;
  sk_label: string;
  category: string;
  rule_id: string;
  category_label: string;
  rule_label: string;
  explanation: string;
  origin: string;
  engine: string;
  engines?: string[];
  count: number;
  sample_urls: string[];
  sample_methods: string[];
  sample_snippets: string[];
  remediation: string | null;
  trigger_families: { family: string; count: number }[];
  top_status_codes: string[];
};

export type G61ReportSummary = {
  total_issues: number;
  by_severity: Record<string, number>;
  by_sk: Record<string, number>;
  by_category: Record<string, number>;
  by_trigger_family: Record<string, number>;
  by_origin: {
    origin: string;
    count: number;
    sk: Record<string, number>;
    categories: Record<string, number>;
  }[];
  groups: G61SummaryGroup[];
  stats?: Record<string, unknown> | null;
};

export const G61_SK_COLUMNS: { id: G61SkClass; label: string }[] = [
  { id: "dbms", label: "DBMS" },
  { id: "exception", label: "익셉션" },
  { id: "http", label: "HTTP/서버" },
];

export const SK_CLASS_LABELS: Record<G61SkClass, string> = {
  dbms: "DBMS 오류",
  exception: "익셉션 오류",
  http: "HTTP/서버 오류",
};

const SEVERITY_RANK: Record<string, number> = { high: 3, medium: 2, low: 1, info: 0 };

export function formatG61OriginLabel(raw: string): string {
  const text = (raw || "").trim();
  if (!text) return "—";
  return text
    .replace(/^host\.docker\.internal/i, "localhost")
    .replace(/^https?:\/\//i, "")
    .replace(/\/$/, "");
}

export function severityLabelKo(sev: string): string {
  if (sev === "high") return "높음";
  if (sev === "medium") return "중간";
  if (sev === "low") return "낮음";
  return sev;
}

export function formatG61Engine(engine: string, engines?: string[]): string {
  if (engines && engines.length > 1) return "httpx+ZAP";
  if (engine === "httpx+zap") return "httpx+ZAP";
  if (engine === "httpx") return "httpx";
  if (engine.startsWith("zap")) return "ZAP";
  return engine;
}

export type G61MatrixRow = {
  origin: string;
  displayLabel: string;
  total: number;
  cells: Partial<Record<G61SkClass, { severity: string; count: number }>>;
};

export function buildG61Matrix(summary: G61ReportSummary): G61MatrixRow[] {
  const rows = new Map<string, G61MatrixRow>();
  for (const slot of summary.by_origin) {
    const displayLabel = formatG61OriginLabel(slot.origin);
    const cells: G61MatrixRow["cells"] = {};
    for (const [sk, count] of Object.entries(slot.sk ?? {})) {
      const col = sk as G61SkClass;
      if (!G61_SK_COLUMNS.some((c) => c.id === col)) continue;
      const group = summary.groups.find((g) => g.origin === slot.origin && g.sk_class === col);
      const severity = group?.severity ?? "low";
      const prev = cells[col];
      if (!prev || count > prev.count) {
        cells[col] = { severity, count };
      }
    }
    rows.set(slot.origin, {
      origin: slot.origin,
      displayLabel,
      total: slot.count,
      cells,
    });
  }
  return [...rows.values()].sort((a, b) => b.total - a.total);
}

export function sortG61Groups(groups: G61SummaryGroup[]): G61SummaryGroup[] {
  const skRank: Record<string, number> = { dbms: 3, exception: 2, http: 1 };
  return [...groups].sort((a, b) => {
    const kr = (skRank[b.sk_class] ?? 0) - (skRank[a.sk_class] ?? 0);
    if (kr !== 0) return kr;
    const sr = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (sr !== 0) return sr;
    return b.count - a.count;
  });
}

export function g61Headline(summary: G61ReportSummary, status: string): string {
  const dbms = summary.by_sk?.dbms ?? 0;
  const exc = summary.by_sk?.exception ?? 0;
  const http = summary.by_sk?.http ?? 0;
  const high = summary.by_severity.high ?? 0;
  const medium = summary.by_severity.medium ?? 0;
  if (status === "pass") return "오류페이지 정보 노출 — 이상 없음";
  if (dbms > 0 || high > 0) return "오류페이지 정보 노출 — DBMS/고위험 검토 필요";
  if (exc + medium > 0) return "오류페이지 정보 노출 — 익셉션/HTTP 검토 필요";
  if (http > 0) return "오류페이지 정보 노출 — 서버 오류 응답 검토 필요";
  return "오류페이지 정보 노출 — 참고";
}

export function pathFromUrl(raw: string): string {
  try {
    return new URL(raw).pathname || raw;
  } catch {
    return raw;
  }
}

export function triggerFamilyLabel(family: string): string {
  const map: Record<string, string> = {
    param: "query/body param",
    body: "body",
    path: "path",
    method: "HTTP method",
    header: "header",
  };
  return map[family] ?? family;
}
