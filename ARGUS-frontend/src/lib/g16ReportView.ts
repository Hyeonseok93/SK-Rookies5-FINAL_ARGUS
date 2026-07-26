/** Client-side case grouping for 1-6 diagnosis findings (입력 값 크기 및 무결성 검증 오류). */

export type G16Finding = {
  severity: string;
  message: string;
  evidence: Record<string, unknown>;
};

export type G16CaseGroup = {
  group_key: string;
  severity: string;
  exception_type: string;
  vuln_type: string;
  origin: string;
  count: number;
  sample_urls: string[];
  sample_payload_names: string[];
  sample_status_codes: string[];
  sample_findings: G16Finding[];
};

const SEVERITY_RANK: Record<string, number> = { high: 3, medium: 2, low: 1, info: 0 };

const MAX_SAMPLES = 5;
const MAX_SAMPLE_FINDINGS = 3;

export function severityLabelKo(sev: string): string {
  if (sev === "high") return "높음";
  if (sev === "medium") return "중간";
  if (sev === "low") return "낮음";
  if (sev === "info") return "참고";
  return sev;
}

function originFromUrl(raw: string | undefined): string {
  const text = (raw || "").trim();
  if (!text) return "—";
  try {
    const u = new URL(text.includes("://") ? text : `http://${text}`);
    const host = u.hostname.replace(/^host\.docker\.internal$/i, "localhost");
    return u.port ? `${host}:${u.port}` : host;
  } catch {
    return text.replace(/^https?:\/\//i, "").split("/")[0] || text;
  }
}

export function exceptionLabel(evidence: Record<string, unknown>): string {
  const resp = evidence.response_analysis as Record<string, unknown> | undefined;
  const cls = evidence.classification as Record<string, unknown> | undefined;
  const exceptionType = typeof resp?.exception_type === "string" ? resp.exception_type : "";
  if (exceptionType) return exceptionType;
  const vulnType = typeof cls?.vuln_type === "string" ? cls.vuln_type : "";
  return vulnType || "서버 예외 (유형 미상)";
}

export function buildG16Groups(findings: G16Finding[]): G16CaseGroup[] {
  const groups = new Map<string, G16CaseGroup>();
  for (const f of findings) {
    const ev = f.evidence ?? {};
    const label = exceptionLabel(ev);
    const url = (ev.normalized_url as string) || (ev.url as string) || "";
    const origin = originFromUrl(url);
    const key = `${f.severity}|${label}|${origin}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        group_key: key,
        severity: f.severity,
        exception_type: label,
        vuln_type: String((ev.classification as Record<string, unknown> | undefined)?.vuln_type ?? ""),
        origin,
        count: 0,
        sample_urls: [],
        sample_payload_names: [],
        sample_status_codes: [],
        sample_findings: [],
      };
      groups.set(key, g);
    }
    g.count += 1;
    if (url && !g.sample_urls.includes(url) && g.sample_urls.length < MAX_SAMPLES) {
      g.sample_urls.push(url);
    }
    const payloadName = ev.payload_name as string | undefined;
    if (payloadName && !g.sample_payload_names.includes(payloadName) && g.sample_payload_names.length < MAX_SAMPLES) {
      g.sample_payload_names.push(payloadName);
    }
    const statusCode = ev.status_code != null ? String(ev.status_code) : "";
    if (statusCode && !g.sample_status_codes.includes(statusCode) && g.sample_status_codes.length < 4) {
      g.sample_status_codes.push(statusCode);
    }
    if (g.sample_findings.length < MAX_SAMPLE_FINDINGS) g.sample_findings.push(f);
  }
  return [...groups.values()];
}

export function sortG16Groups(groups: G16CaseGroup[]): G16CaseGroup[] {
  return [...groups].sort((a, b) => {
    const sr = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (sr !== 0) return sr;
    return b.count - a.count;
  });
}
