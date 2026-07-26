/** Transform 3-2 auth failure limit findings into compact report rows. */

export type G32Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export type G32RowKind = "issue" | "ok" | "error";

export type G32AttemptRow = {
  attempt: number;
  httpStatus: string | number | null;
  errorCode: string | null;
  primaryMessage: string | null;
  error: string | null;
};

export type G32Row = {
  rowKey: string;
  loginLabel: string;
  loginUrl: string;
  accountEmail: string;
  kind: G32RowKind;
  resultLabel: string;
  scaleSummary: string;
  reason: string | null;
  limitType: string | null;
  limitTypeLabel: string | null;
  severity: string;
  maxAttempts: number;
  detectedAtAttempt: number | null;
  attempts: G32AttemptRow[];
  trigger: string | null;
  message: string;
};

const LIMIT_TYPE_LABELS: Record<string, string> = {
  rate_limit: "속도 제한 (429)",
  account_lockout: "계정 잠금",
  response_message: "잠금·제한 메시지",
  response_change: "응답 변경",
};

function parseAttempts(raw: unknown): G32AttemptRow[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((x) => x && typeof x === "object")
    .map((item) => {
      const row = item as Record<string, unknown>;
      return {
        attempt: typeof row.attempt === "number" ? row.attempt : 0,
        httpStatus: row.http_status as string | number | null,
        errorCode: row.error_code != null ? String(row.error_code) : null,
        primaryMessage: row.primary_message != null ? String(row.primary_message) : null,
        error: row.error != null ? String(row.error) : null,
      };
    })
    .filter((r) => r.attempt > 0)
    .sort((a, b) => a.attempt - b.attempt);
}

function pathFromLoginUrl(url: string): string {
  try {
    return new URL(url).pathname || "/";
  } catch {
    return url;
  }
}

export function parseG32Row(f: G32Finding): G32Row | null {
  const ev = f.evidence;
  if (!ev?.rule_id || ev.rule_id !== "3-2-auth-failure-limit") return null;

  const trigger = ev.trigger != null ? String(ev.trigger) : null;
  const loginUrl = ev.login_url != null ? String(ev.login_url) : "";
  const loginLabel =
    ev.login_label != null ? String(ev.login_label) : pathFromLoginUrl(loginUrl) || loginUrl;
  const accountEmail = ev.account_email != null ? String(ev.account_email) : "—";
  const maxAttempts = typeof ev.max_attempts === "number" ? ev.max_attempts : 0;
  const detectedAt =
    typeof ev.detected_at_attempt === "number"
      ? ev.detected_at_attempt
      : typeof (ev.analysis as Record<string, unknown> | undefined)?.detected_at_attempt ===
          "number"
        ? ((ev.analysis as Record<string, unknown>).detected_at_attempt as number)
        : null;
  const limitType = ev.limit_type != null ? String(ev.limit_type) : null;
  const analysis = ev.analysis as Record<string, unknown> | undefined;
  const reason =
    ev.reason != null
      ? String(ev.reason)
      : analysis?.reason != null
        ? String(analysis.reason)
        : null;

  let kind: G32RowKind = "issue";
  let resultLabel = "제한 없음";
  let scaleSummary = maxAttempts > 0 ? `${maxAttempts}회 동일 응답` : "—";

  if (trigger === "lockout_detected") {
    kind = "ok";
    resultLabel = "제한 감지";
    scaleSummary =
      detectedAt != null && maxAttempts > 0
        ? `${detectedAt}/${maxAttempts}회차`
        : maxAttempts > 0
          ? `${maxAttempts}회 이내`
          : "감지됨";
  } else if (trigger === "probe_unreachable") {
    kind = "error";
    resultLabel = "접근 불가";
    scaleSummary = ev.error != null ? String(ev.error).slice(0, 80) : "probe 실패";
  }

  const limitTypeLabel = limitType ? (LIMIT_TYPE_LABELS[limitType] ?? limitType) : null;

  return {
    rowKey: `${loginUrl}|${accountEmail}|${trigger ?? ""}`,
    loginLabel,
    loginUrl,
    accountEmail,
    kind,
    resultLabel,
    scaleSummary,
    reason,
    limitType,
    limitTypeLabel,
    severity: f.severity,
    maxAttempts,
    detectedAtAttempt: detectedAt,
    attempts: parseAttempts(ev.attempts),
    trigger,
    message: f.message,
  };
}

export function parseG32Findings(findings: G32Finding[]): {
  rows: G32Row[];
  other: G32Finding[];
} {
  const rows: G32Row[] = [];
  const other: G32Finding[] = [];
  for (const f of findings) {
    const row = parseG32Row(f);
    if (row) rows.push(row);
    else other.push(f);
  }
  const kindOrder: Record<G32RowKind, number> = { issue: 0, error: 1, ok: 2 };
  rows.sort((a, b) => {
    const k = kindOrder[a.kind] - kindOrder[b.kind];
    if (k !== 0) return k;
    return a.loginLabel.localeCompare(b.loginLabel);
  });
  return { rows, other };
}

export function buildG32PassNote(rows: G32Row[]): string | null {
  const ok = rows.filter((r) => r.kind === "ok");
  if (ok.length === 0) return null;
  return `${ok.length}개 login — 실패 횟수 제한 확인`;
}
