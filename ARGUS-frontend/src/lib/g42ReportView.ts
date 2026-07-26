/** Transform 4-2 auth token safety findings into compact report rows. */

export type G42Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export type G42Category = "jwt" | "session" | "logout";

export const G42_CATEGORY_LABELS: Record<G42Category, string> = {
  jwt: "JWT·토큰",
  session: "세션·재로그인",
  logout: "로그아웃",
};

export const G42_RULE_LABELS: Record<string, string> = {
  "4-2-jwt-long-lived": "JWT access token 수명 과다",
  "4-2-jwt-no-exp": "JWT exp 미설정",
  "4-2-jwt-weak-alg": "JWT 서명 알고리즘 취약",
  "4-2-jwt-structure": "JWT 구조 오류",
  "4-2-token-complexity": "토큰 엔트로피·길이 부족",
  "4-2-token-reuse": "재로그인 시 동일 토큰 재발급",
  "4-2-duplicate-login": "중복 로그인·동시 세션 허용",
  "4-2-duplicate-login-cross-ip": "IP 변경 후에도 기존 세션 유효",
  "4-2-no-ip-session-binding": "세션·IP 미바인딩",
  "4-2-no-server-logout-api": "서버 로그아웃 API 없음",
  "4-2-token-valid-after-client-logout": "클라이언트 로그아웃 후 access token 유효",
  "4-2-refresh-valid-after-client-logout": "클라이언트 로그아웃 후 refresh token 유효",
  "4-2-logout-not-invalidating": "서버 로그아웃 후 세션 미폐기",
  "4-2-logout-skipped": "로그아웃 검사 스킵",
};

const G42_RULE_CATEGORY: Record<string, G42Category> = {
  "4-2-jwt-long-lived": "jwt",
  "4-2-jwt-no-exp": "jwt",
  "4-2-jwt-weak-alg": "jwt",
  "4-2-jwt-structure": "jwt",
  "4-2-token-complexity": "jwt",
  "4-2-token-reuse": "session",
  "4-2-duplicate-login": "session",
  "4-2-duplicate-login-cross-ip": "session",
  "4-2-no-ip-session-binding": "session",
  "4-2-no-server-logout-api": "logout",
  "4-2-token-valid-after-client-logout": "logout",
  "4-2-refresh-valid-after-client-logout": "logout",
  "4-2-logout-not-invalidating": "logout",
  "4-2-logout-skipped": "logout",
};

export type G42AccountHit = {
  email: string | null;
  loginUrl: string | null;
  loginPath: string | null;
  reason: string | null;
  remediation: string | null;
  severity: string;
  message: string;
  evidence: Record<string, unknown>;
};

export type G42MergedFinding = {
  ruleId: string;
  ruleLabel: string;
  category: G42Category;
  categoryLabel: string;
  severity: string;
  reason: string | null;
  remediation: string | null;
  emailSummary: string;
  loginPathSummary: string;
  accounts: G42AccountHit[];
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

export function formatG42LoginPath(url: string | null | undefined): string {
  if (!url) return "—";
  try {
    return new URL(url).pathname;
  } catch {
    return url.replace(/^https?:\/\/[^/]+/i, "") || url;
  }
}

export function ruleLabel(ruleId: string): string {
  return G42_RULE_LABELS[ruleId] ?? ruleId.replace(/^4-2-/, "");
}

export function ruleCategory(ruleId: string): G42Category {
  return G42_RULE_CATEGORY[ruleId] ?? "jwt";
}

function strOrNull(v: unknown): string | null {
  if (v === undefined || v === null || v === "") return null;
  return String(v);
}

export function formatG42EmailSummary(emails: string[]): string {
  const sorted = [...new Set(emails.filter(Boolean))].sort();
  if (sorted.length === 0) return "전역";
  if (sorted.length === 1) return sorted[0]!;
  if (sorted.length <= 3) return sorted.join(", ");
  return `${sorted.length}계정`;
}

export function truncateG42Text(value: string | null | undefined, max = 52): string {
  const text = (value ?? "").trim();
  if (!text) return "—";
  if (text.length <= max) return text;
  return `${text.slice(0, Math.max(1, max - 1))}…`;
}

export function formatG42LoginPathSummary(paths: string[]): string {
  const sorted = [...new Set(paths.filter((p) => p && p !== "—"))].sort();
  if (sorted.length === 0) return "—";
  if (sorted.length === 1) return sorted[0]!;
  return `${sorted.length}개 login`;
}

function accountFromFinding(f: G42Finding): G42AccountHit {
  const ev = f.evidence ?? {};
  const loginUrl = strOrNull(ev.login_url);
  return {
    email: strOrNull(ev.email),
    loginUrl,
    loginPath: loginUrl ? formatG42LoginPath(loginUrl) : null,
    reason: strOrNull(ev.reason),
    remediation: strOrNull(ev.remediation),
    severity: f.severity,
    message: f.message,
    evidence: ev,
  };
}

function pickCommonReason(accounts: G42AccountHit[]): string | null {
  const reasons = [...new Set(accounts.map((a) => a.reason).filter(Boolean) as string[])];
  if (reasons.length === 1) return reasons[0]!;
  if (reasons.length === 0) return null;
  return reasons[0]!;
}

function pickRemediation(accounts: G42AccountHit[]): string | null {
  for (const a of accounts) {
    if (a.remediation) return a.remediation;
  }
  return null;
}

/** Merge per-account hits into one row per rule (e.g. JWT lifetime across all test accounts). */
export function mergeG42Findings(findings: G42Finding[]): {
  merged: G42MergedFinding[];
  other: G42Finding[];
} {
  const groups = new Map<string, G42MergedFinding>();
  const other: G42Finding[] = [];

  for (const f of findings) {
    const ruleId = strOrNull(f.evidence?.rule_id);
    if (!ruleId) {
      other.push(f);
      continue;
    }

    const account = accountFromFinding(f);
    const existing = groups.get(ruleId);
    if (!existing) {
      const category = ruleCategory(ruleId);
      groups.set(ruleId, {
        ruleId,
        ruleLabel: ruleLabel(ruleId),
        category,
        categoryLabel: G42_CATEGORY_LABELS[category],
        severity: f.severity,
        reason: account.reason,
        remediation: account.remediation,
        emailSummary: formatG42EmailSummary(account.email ? [account.email] : []),
        loginPathSummary: formatG42LoginPathSummary(account.loginPath ? [account.loginPath] : []),
        accounts: [account],
      });
      continue;
    }

    existing.severity = maxSeverity(existing.severity, f.severity);
    existing.accounts.push(account);
    existing.emailSummary = formatG42EmailSummary(
      existing.accounts.map((a) => a.email ?? "").filter(Boolean),
    );
    existing.loginPathSummary = formatG42LoginPathSummary(
      existing.accounts.map((a) => a.loginPath ?? "").filter(Boolean),
    );
    existing.reason = pickCommonReason(existing.accounts);
    existing.remediation = pickRemediation(existing.accounts) ?? existing.remediation;
  }

  const categoryOrder: Record<G42Category, number> = { jwt: 0, session: 1, logout: 2 };
  const merged = [...groups.values()].sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    const cat = categoryOrder[a.category] - categoryOrder[b.category];
    if (cat !== 0) return cat;
    return a.ruleLabel.localeCompare(b.ruleLabel);
  });

  return { merged, other };
}

export function groupG42ByCategory(merged: G42MergedFinding[]): {
  category: G42Category;
  categoryLabel: string;
  findings: G42MergedFinding[];
}[] {
  const map = new Map<G42Category, G42MergedFinding[]>();
  for (const row of merged) {
    const list = map.get(row.category) ?? [];
    list.push(row);
    map.set(row.category, list);
  }
  const order: G42Category[] = ["jwt", "session", "logout"];
  return order
    .filter((c) => map.has(c))
    .map((c) => ({
      category: c,
      categoryLabel: G42_CATEGORY_LABELS[c],
      findings: map.get(c)!,
    }));
}
