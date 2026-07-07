/** Transform 2-2 download / traversal findings into compact report rows. */

export type G22Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export type G22DetailField = { label: string; value: string };

export type G22Row = {
  rowKey: string;
  ruleId: string;
  typeLabel: string;
  method: string;
  path: string;
  endpointLabel: string;
  serverLabel: string;
  param: string | null;
  paramIn: string | null;
  payload: string | null;
  issueLabel: string;
  headline: string;
  scaleSummary: string;
  plainExplanation: string;
  classification: "A" | "B" | null;
  severity: string;
  severityLabel: string;
  engines: string[];
  detailFields: G22DetailField[];
};

export type G22SummaryRow = G22Row & {
  groupedCount: number;
  endpointHint: string;
  members: G22Row[];
};

const RULE_COPY: Record<string, { typeLabel: string; defaultIssue: string; explanation: string }> = {
  "2-2-path-traversal": {
    typeLabel: "경로 조작 · 파일 노출",
    defaultIssue: "민감 파일 내용이 응답에 포함",
    explanation: "path traversal payload로 시스템·설정 파일 내용을 읽어올 수 있습니다.",
  },
  "2-2-input-validation": {
    typeLabel: "입력값 검증 미흡",
    defaultIssue: "악성 path payload를 그대로 수용",
    explanation: "../ 등 path 조작 문자열을 거부·정규화하지 않고 API가 수용했습니다.",
  },
  "2-2-unauth-download": {
    typeLabel: "비로그인 다운로드",
    defaultIssue: "로그인 없이 파일 다운로드 가능",
    explanation: "인증 없이도 다운로드·첨부 형태 응답을 받을 수 있습니다.",
  },
  "2-2-forced-browse": {
    typeLabel: "강제 파일 탐색",
    defaultIssue: "숨겨진 경로·파일 노출",
    explanation: "추측 경로로 비공개 파일에 접근할 수 있습니다.",
  },
};

const TRIGGER_COPY: Record<string, { issue: string; headline?: string }> = {
  payload_target_leak_confirmed: {
    issue: "요청한 파일 내용이 응답에 노출",
    headline: "path 조작으로 요청한 파일(/etc/passwd 등) 내용이 응답에 포함됨",
  },
  different_response_no_payload_leak: {
    issue: "악성 payload 수용 · 응답만 변경",
  },
  identical_response_to_baseline: {
    issue: "악성 payload 수용 · baseline과 동일 응답",
  },
  unauth_download_no_account: {
    issue: "로그인 없이 다운로드 가능",
    headline: "테스트 계정 없이도 다운로드 형태 응답(HTTP 200)",
  },
  unauth_download_anonymous: {
    issue: "비로그인·로그인 동일하게 다운로드",
  },
  sensitive_body_in_response: {
    issue: "응답에 민감 문자열 포함",
  },
};

function severityLabelKo(sev: string): string {
  if (sev === "high") return "높음";
  if (sev === "medium") return "중간";
  if (sev === "low") return "낮음";
  return sev;
}

function severityRank(sev: string): number {
  if (sev === "high") return 3;
  if (sev === "medium") return 2;
  if (sev === "low") return 1;
  return 0;
}

export function formatG22ServerLabel(raw: string): string {
  try {
    const u = new URL(raw);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return raw.replace(/^https?:\/\//i, "").replace(/\/$/, "");
  }
}

function pathOnly(raw: string): string {
  try {
    return new URL(raw).pathname || "/";
  } catch {
    return raw;
  }
}

function addField(fields: G22DetailField[], label: string, value: unknown) {
  if (value !== undefined && value !== null && value !== "") {
    fields.push({ label, value: String(value) });
  }
}

function truncate(value: string, max = 240): string {
  const t = value.replace(/\s+/g, " ").trim();
  if (t.length <= max) return t;
  return `${t.slice(0, max)}…`;
}

function logicKey(ev: Record<string, unknown>): string {
  const ruleId = String(ev.rule_id ?? "");
  const method = String(ev.method ?? "").toUpperCase();
  const path = String(ev.path ?? pathOnly(String(ev.url ?? "")));
  const param = String(ev.param ?? "");
  const paramIn = String(ev.param_in ?? "");
  const server = formatG22ServerLabel(String(ev.base_url ?? ev.url ?? ""));
  const trigger = String(ev.trigger ?? "");
  return `${ruleId}|${method}|${path}|${param}|${paramIn}|${server}|${trigger}`;
}

function groupKey(row: G22Row): string {
  return `${row.ruleId}|${row.param ?? ""}|${row.paramIn ?? ""}|${row.serverLabel}|${row.classification ?? ""}|${row.issueLabel}|${row.severity}`;
}

function endpointHintFromRows(rows: G22Row[]): string {
  const labels = [...new Set(rows.map((r) => r.endpointLabel))];
  if (labels.length === 0) return "—";
  if (labels.length === 1) return labels[0]!;
  if (labels.length <= 3) return labels.join(", ");
  return `${labels.slice(0, 2).join(", ")} 외 ${labels.length - 2}건`;
}

function buildHeadline(row: {
  ruleId: string;
  method: string;
  path: string;
  param: string | null;
  payload: string | null;
  trigger: string;
  classification: "A" | "B" | null;
}): string {
  const triggerCopy = TRIGGER_COPY[row.trigger];
  if (triggerCopy?.headline) return triggerCopy.headline;
  const where = row.param ? `\`${row.param}\`(${row.method} ${row.path})` : `${row.method} ${row.path}`;
  if (row.ruleId === "2-2-path-traversal") {
    const sample = row.payload ? ` · 예: ${row.payload}` : "";
    return `${where} — path 조작 시 파일·민감 내용 노출${sample}`;
  }
  if (row.ruleId === "2-2-unauth-download") {
    return `${row.method} ${row.path} — 로그인 없이 다운로드 가능`;
  }
  if (row.ruleId === "2-2-input-validation") {
    return `${where} — ../ 등 악성 path 문자열 수용`;
  }
  if (row.classification === "B") return `${row.method} ${row.path} — 민감 내용 노출 신호`;
  return `${row.method} ${row.path} — 입력값 검증 이슈`;
}

export function isG22DisplayFinding(f: G22Finding): boolean {
  if (f.message === "2-2 scan statistics") return false;
  if (f.severity === "info") return false;
  const ruleId = String(f.evidence?.rule_id ?? "");
  if (ruleId === "2-2-design") return false;
  return Boolean(ruleId);
}

export function filterG22DisplayFindings(findings: G22Finding[]): G22Finding[] {
  return findings.filter(isG22DisplayFinding);
}

export function parseG22Row(f: G22Finding): G22Row | null {
  const ev = f.evidence;
  if (!ev?.rule_id) return null;
  const ruleId = String(ev.rule_id);
  if (ruleId === "2-2-design") return null;

  const copy = RULE_COPY[ruleId] ?? {
    typeLabel: "2-2",
    defaultIssue: "검토 필요",
    explanation: "중요 파일 다운로드·path 조작 가능성을 확인하세요.",
  };

  const method = String(ev.method ?? "GET").toUpperCase();
  const path = String(ev.path ?? pathOnly(String(ev.url ?? "")));
  const serverLabel = formatG22ServerLabel(String(ev.base_url ?? ev.url ?? ""));
  const param = ev.param != null ? String(ev.param) : null;
  const paramIn = ev.param_in != null ? String(ev.param_in) : null;
  const payload = ev.payload != null ? String(ev.payload) : null;
  const trigger = ev.trigger != null ? String(ev.trigger) : "";
  const classification =
    ev.classification === "A" || ev.classification === "B"
      ? ev.classification
      : ruleId === "2-2-path-traversal"
        ? "B"
        : ruleId === "2-2-input-validation"
          ? "A"
          : null;

  const triggerCopy = TRIGGER_COPY[trigger];
  const issueLabel = triggerCopy?.issue ?? copy.defaultIssue;
  const payloadsTried =
    typeof ev.payloads_tried_count === "number"
      ? ev.payloads_tried_count
      : Array.isArray(ev.payloads_tried)
        ? ev.payloads_tried.length
        : null;

  const scaleParts: string[] = [];
  if (payloadsTried != null && payloadsTried > 0) scaleParts.push(`payload ${payloadsTried}종`);
  if (ev.http_status != null) scaleParts.push(`HTTP ${ev.http_status}`);
  if (ev.payload_leak_confirmed === true) scaleParts.push("파일 내용 유출 확인");
  else if (classification === "A") scaleParts.push("유출 미확인");

  const detailFields: G22DetailField[] = [];
  addField(detailFields, "요청 URL", ev.url);
  addField(detailFields, "서버", ev.base_url ?? serverLabel);
  addField(detailFields, "파라미터", param);
  addField(detailFields, "위치", paramIn);
  addField(detailFields, "Payload 예시", payload);
  addField(detailFields, "HTTP", ev.http_status);
  addField(detailFields, "Baseline HTTP", ev.baseline_http_status);
  addField(detailFields, "분류", classification);
  addField(detailFields, "판정", ev.trigger_label ?? trigger);
  if (ev.payload_leak_confirmed === true) addField(detailFields, "파일 유출", "confirmed");
  if (ev.extracted_text_preview) {
    addField(detailFields, "추출 텍스트", truncate(String(ev.extracted_text_preview), 320));
  }
  if (ev.content_type) addField(detailFields, "Content-Type", ev.content_type);
  if (ev.content_disposition) addField(detailFields, "Content-Disposition", ev.content_disposition);
  if (Array.isArray(ev.payload_leak_markers) && ev.payload_leak_markers.length > 0) {
    addField(detailFields, "유출 marker", (ev.payload_leak_markers as string[]).slice(0, 8).join(", "));
  }
  const engine = String(ev.engine ?? ev.source ?? "httpx");
  addField(detailFields, "엔진", engine);

  return {
    rowKey: logicKey(ev),
    ruleId,
    typeLabel: copy.typeLabel,
    method,
    path,
    endpointLabel: `${method} ${path}`,
    serverLabel,
    param,
    paramIn,
    payload,
    issueLabel,
    headline: buildHeadline({ ruleId, method, path, param, payload, trigger, classification }),
    scaleSummary: scaleParts.join(" · ") || "—",
    plainExplanation: copy.explanation,
    classification,
    severity: f.severity,
    severityLabel: severityLabelKo(f.severity),
    engines: [engine],
    detailFields,
  };
}

export function parseG22Findings(findings: G22Finding[]): {
  rows: G22Row[];
  other: G22Finding[];
} {
  const merged = new Map<string, G22Row>();
  const other: G22Finding[] = [];

  for (const f of filterG22DisplayFindings(findings)) {
    const row = parseG22Row(f);
    if (!row) {
      other.push(f);
      continue;
    }
    const prev = merged.get(row.rowKey);
    if (!prev) {
      merged.set(row.rowKey, row);
      continue;
    }
    const engines = [...new Set([...prev.engines, ...row.engines])];
    merged.set(row.rowKey, { ...prev, engines });
  }

  const rows = [...merged.values()];
  rows.sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    if (a.typeLabel !== b.typeLabel) return a.typeLabel.localeCompare(b.typeLabel);
    return a.endpointLabel.localeCompare(b.endpointLabel);
  });
  return { rows, other };
}

export function buildG22SummaryRows(rows: G22Row[]): G22SummaryRow[] {
  const groups = new Map<string, G22Row[]>();
  for (const row of rows) {
    const key =
      row.ruleId === "2-2-input-validation"
        ? groupKey(row)
        : `${row.rowKey}|${row.severity}`;
    const list = groups.get(key) ?? [];
    list.push(row);
    groups.set(key, list);
  }

  const out: G22SummaryRow[] = [];
  for (const members of groups.values()) {
    members.sort((a, b) => a.endpointLabel.localeCompare(b.endpointLabel));
    const primary = members[0]!;
    const groupedCount = members.length;
    out.push({
      ...primary,
      groupedCount,
      endpointHint: groupedCount > 1 ? endpointHintFromRows(members) : primary.endpointLabel,
      members,
      scaleSummary:
        groupedCount > 1
          ? `${groupedCount}개 API · ${primary.scaleSummary}`
          : primary.scaleSummary,
    });
  }

  out.sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    return a.endpointHint.localeCompare(b.endpointHint);
  });
  return out;
}

export function isG22IssueRow(row: G22SummaryRow): boolean {
  return row.severity === "high" || row.severity === "medium" || row.severity === "low";
}
