/** Transform 1-5 redirect/CORS findings into compact report rows. */

export type G15Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export type G15Category = "redirect" | "cors" | "crossdomain" | "reflected" | "xss";

export type G15DetailField = { label: string; value: string };

export type G15Row = {
  rowKey: string;
  category: G15Category;
  categoryLabel: string;
  checkLabel: string;
  issueLabel: string;
  headline: string;
  scaleSummary: string;
  plainExplanation: string;
  targetHint: string | null;
  severity: string;
  severityLabel: string;
  engine: string;
  message: string;
  detailFields: G15DetailField[];
};

const CATEGORY_LABELS: Record<G15Category, string> = {
  redirect: "외부 리다이렉트",
  cors: "CORS",
  crossdomain: "crossdomain.xml",
  reflected: "반사(Reflected) 확인",
  xss: "반사형 XSS 확인",
};

type ReasonCopy = { label: string; summary: string; headline: string; detail: string };

const CORS_REASON_COPY: Record<string, ReasonCopy> = {
  cors_wildcard_with_credentials: {
    label: "모든 출처 + 쿠키 허용",
    summary: "모든 웹사이트에서 쿠키 포함 요청 가능",
    headline: "모든 웹사이트에서 로그인 쿠키를 넣어 접근할 수 있는 CORS 설정",
    detail:
      "어느 Origin이든 허용(*)하면서 쿠키(credentials)도 허용하는 조합입니다. 브라우저는 보통 막지만, 서버 설정 자체가 위험한 형태입니다.",
  },
  cors_wildcard_origin: {
    label: "모든 출처 허용",
    summary: "모든 웹사이트에서 cross-origin 요청 가능",
    headline: "모든 웹사이트에서 이 서버로 cross-origin 요청이 가능한 CORS 설정",
    detail: "Access-Control-Allow-Origin이 * 로 열려 있습니다. 필요한 도메인만 허용하는지 확인하세요.",
  },
  cors_reflect_origin_with_credentials: {
    label: "다른 사이트 Origin + 쿠키 허용",
    summary: "Origin reflect · credentials true",
    headline: "요청 Origin을 그대로 허용하고 쿠키도 허용",
    detail:
      "테스트 Origin이 Access-Control-Allow-Origin에 그대로 반환되고 credentials=true 입니다. 악성 사이트가 로그인된 사용자 브라우저로 API를 호출할 수 있는 설정입니다.",
  },
  cors_reflect_origin: {
    label: "요청 출처 그대로 허용",
    summary: "요청 Origin을 Allow-Origin에 그대로 반환",
    headline: "요청한 웹사이트 Origin을 그대로 허용하는 CORS 설정",
    detail:
      "고정된 허용 목록이 아니라, 요청 Origin을 그대로 반환(reflect)합니다. cross-origin 접근 범위가 넓어질 수 있습니다.",
  },
};

const CROSSDOMAIN_REASON_COPY: Record<string, ReasonCopy> = {
  crossdomain_wildcard: {
    label: "모든 도메인 허용",
    summary: 'crossdomain.xml domain="*"',
    headline: "crossdomain.xml에서 모든 도메인 접근을 허용",
    detail: "Flash crossdomain 정책에서 모든 도메인 접근을 허용합니다.",
  },
  crossdomain_allow_from: {
    label: "특정 도메인 허용",
    summary: "allow-access-from 규칙 존재",
    headline: "crossdomain.xml에 외부 도메인 허용 규칙이 있음",
    detail: "crossdomain.xml에 allow-access-from 규칙이 있습니다. 필요 최소 범위인지 확인하세요.",
  },
};

const REFLECTED_DETECTION_COPY: Record<string, ReasonCopy> = {
  meta_refresh: {
    label: "meta refresh 리다이렉트",
    summary: "meta refresh 태그로 외부 이동",
    headline: "meta refresh 태그에 외부 주소가 그대로 반영됨",
    detail:
      "응답 본문의 <meta http-equiv=\"refresh\"> 태그에 주입한 외부 주소가 그대로 반영되어, 브라우저가 자동으로 외부 사이트로 이동할 수 있습니다.",
  },
  js_redirect: {
    label: "JS location 리다이렉트",
    summary: "JS location 대입으로 외부 이동",
    headline: "JavaScript location 대입 코드에 외부 주소가 그대로 반영됨",
    detail:
      "응답에 포함된 JavaScript의 location 대입 코드(location.href/.replace()/.assign())에 주입한 외부 주소가 그대로 반영되어, 페이지 로드 시 브라우저가 외부 사이트로 이동될 수 있습니다.",
  },
  reflected_value: {
    label: "값 반사만 확인됨 (참고)",
    summary: "리다이렉트 실행 증거 없이 값만 반사",
    headline: "입력값이 검증 없이 응답에 그대로 반사됨 (리다이렉트 실행 증거 없음)",
    detail:
      "주입한 값이 응답 본문에 그대로 나타나지만, 실제 리다이렉트 실행(Location 헤더/meta refresh/JS location 대입) 증거는 없습니다. 타입 검증 실패 에러 메시지 등에서도 흔히 발생하는 패턴이라 1-5 확정 취약점은 아니며, 참고용 정보 노출 신호로만 취급해야 합니다.",
  },
};

const XSS_CONFIRMED_COPY: ReasonCopy = {
  label: "반사형 XSS (확정)",
  summary: "스크립트가 이스케이프 없이 HTML 응답에 반사됨",
  headline: "스크립트/HTML 인젝션이 이스케이프 없이 그대로 반사됨 (확정)",
  detail:
    "주입한 스크립트/HTML 인젝션 페이로드가 응답 Content-Type이 text/html인 응답에 이스케이프 없이 그대로 반사되어, 브라우저가 그대로 파싱해 스크립트가 실행될 수 있습니다.",
};

const XSS_CANDIDATE_COPY: ReasonCopy = {
  label: "반사형 XSS 후보 (참고)",
  summary: "JSON 등 비-HTML 응답에 이스케이프 없이 반사됨",
  headline: "입력값이 이스케이프 없이 응답에 그대로 반사됨 (프런트엔드 렌더링 확인 필요)",
  detail:
    "주입한 스크립트/HTML 인젝션 페이로드가 이스케이프 없이 응답에 그대로 반사되지만, 응답 Content-Type이 HTML이 아니라(JSON 등) 즉시 실행되지는 않습니다. 프런트엔드가 이 값을 innerHTML/dangerouslySetInnerHTML 등으로 안전하지 않게 렌더링하는 지점이 있는지 확인이 필요합니다.",
};

function pathFromUrl(url: string): string {
  try {
    return new URL(url).pathname || "/";
  } catch {
    return url;
  }
}

export function formatG15BaseLabel(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return baseUrl.replace(/^https?:\/\//i, "").replace(/\/$/, "");
  }
}

function severityLabelKo(sev: string): string {
  if (sev === "high") return "높음";
  if (sev === "medium") return "중간";
  if (sev === "low") return "낮음";
  return sev;
}

function addField(fields: G15DetailField[], label: string, value: unknown) {
  if (value !== undefined && value !== null && value !== "") {
    fields.push({ label, value: String(value) });
  }
}

function severityRank(sev: string): number {
  if (sev === "high") return 3;
  if (sev === "medium") return 2;
  if (sev === "low") return 1;
  return 0;
}

export function parseG15Row(f: G15Finding): G15Row | null {
  const ev = f.evidence;
  if (!ev?.rule_id) return null;
  const ruleId = String(ev.rule_id);
  if (!ruleId.startsWith("1-5-")) return null;

  const engine = String(ev.engine ?? ev.source ?? "httpx");
  const detailFields: G15DetailField[] = [];
  const sevLabel = severityLabelKo(f.severity);

  if (ruleId === "1-5-open-redirect") {
    const phase = ev.phase != null ? String(ev.phase) : "";
    const param = ev.param_name != null ? String(ev.param_name) : null;
    const path = ev.path != null ? String(ev.path) : pathFromUrl(String(ev.test_url ?? ev.url ?? ""));
    const location = ev.location != null ? String(ev.location) : null;
    const testStatus = ev.test_status;

    const phaseCopy =
      phase === "A"
        ? {
            label: "파라미터 조작 → 외부 이동",
            headline: "리다이렉트 파라미터에 외부 URL을 넣으면 공격자 사이트로 보냄",
            detail: "리다이렉트 파라미터에 외부 URL을 넣으면 Location이 공격자 sink로 향했습니다.",
          }
        : phase === "B"
          ? {
              label: "경로 조작 → 외부 이동",
              headline: "URL 경로 조작으로 외부 사이트로 리다이렉트됨",
              detail: "경로에 redirect 페이로드를 넣으면 외부 Location으로 응답했습니다.",
            }
          : {
              label: "외부 open redirect",
              headline: "잘못된 redirect로 사용자를 외부 사이트로 보낼 수 있음",
              detail: "잘못된 redirect 응답으로 사용자를 외부 사이트로 보낼 수 있습니다.",
            };

    addField(detailFields, "요청 URL (baseline)", ev.baseline_url);
    addField(detailFields, "요청 URL (test)", ev.test_url ?? ev.url);
    addField(detailFields, "Location (test)", location);
    addField(detailFields, "Location (baseline)", ev.baseline_location);
    addField(detailFields, "HTTP (test)", testStatus);
    addField(detailFields, "파라미터", param);
    addField(detailFields, "파라미터 위치", ev.param_in);
    if (ev.trigger_label) addField(detailFields, "ZAP 규칙", ev.trigger_label);
    if (ev.plugin_id) addField(detailFields, "plugin", ev.plugin_id);

    return {
      rowKey: `${engine}|${ev.test_url ?? ev.url}|${param ?? ""}|${location ?? ""}`,
      category: "redirect",
      categoryLabel: CATEGORY_LABELS.redirect,
      checkLabel: param ? `${path} · ${param}` : path,
      issueLabel: engine === "zap" ? "ZAP — open redirect" : phaseCopy.label,
      headline: phaseCopy.headline,
      scaleSummary: location
        ? `HTTP ${testStatus ?? "—"} · 외부 Location으로 이동`
        : `HTTP ${testStatus ?? "—"}`,
      plainExplanation: phaseCopy.detail,
      targetHint: null,
      severity: f.severity,
      severityLabel: sevLabel,
      engine,
      message: f.message,
      detailFields,
    };
  }

  if (ruleId === "1-5-cors-misconfig") {
    const reason = ev.reason != null ? String(ev.reason) : "";
    const url = String(ev.url ?? "");
    const base = ev.base_url != null ? String(ev.base_url) : url;
    const server = formatG15BaseLabel(base);
    const copy = CORS_REASON_COPY[reason] ?? {
      label: "CORS 설정 이상",
      summary: "안전하지 않을 수 있는 CORS 응답",
      headline: `${server} — CORS 설정이 안전하지 않을 수 있음`,
      detail: "CORS 응답 헤더가 안전하지 않을 수 있습니다.",
    };
    const httpStatus = ev.http_status;

    addField(detailFields, "요청 URL", url);
    addField(detailFields, "Access-Control-Allow-Origin", ev.acao);
    addField(detailFields, "Access-Control-Allow-Credentials", ev.acac);
    addField(detailFields, "보낸 Origin (테스트)", ev.probe_origin);
    addField(detailFields, "HTTP", httpStatus);

    const scaleParts = [copy.summary];
    if (httpStatus != null && httpStatus !== "") scaleParts.push(`응답 HTTP ${httpStatus}`);

    return {
      rowKey: `${url}|${reason}`,
      category: "cors",
      categoryLabel: CATEGORY_LABELS.cors,
      checkLabel: server,
      issueLabel: copy.label,
      headline: `${server} — ${copy.headline}`,
      scaleSummary: scaleParts.join(" · "),
      plainExplanation: copy.detail,
      targetHint: pathFromUrl(url),
      severity: f.severity,
      severityLabel: sevLabel,
      engine,
      message: f.message,
      detailFields,
    };
  }

  if (ruleId === "1-5-crossdomain-permissive") {
    const reason = ev.reason != null ? String(ev.reason) : "";
    const url = String(ev.url ?? "");
    const copy = CROSSDOMAIN_REASON_COPY[reason] ?? {
      label: "crossdomain.xml",
      summary: "정책 확인 필요",
      headline: "crossdomain.xml 정책이 너무 넓을 수 있음",
      detail: "crossdomain.xml 정책을 확인하세요.",
    };

    addField(detailFields, "요청 URL", url);
    addField(detailFields, "domain", ev.domain);
    addField(detailFields, "HTTP", ev.http_status);

    return {
      rowKey: `${url}|${reason}|${ev.domain ?? ""}`,
      category: "crossdomain",
      categoryLabel: CATEGORY_LABELS.crossdomain,
      checkLabel: formatG15BaseLabel(String(ev.base_url ?? url)),
      issueLabel: copy.label,
      headline: copy.headline,
      scaleSummary: ev.domain != null ? String(ev.domain) : copy.summary,
      plainExplanation: copy.detail,
      targetHint: pathFromUrl(url),
      severity: f.severity,
      severityLabel: sevLabel,
      engine,
      message: f.message,
      detailFields,
    };
  }

  if (ruleId === "1-5-reflected-probe") {
    const trigger = ev.trigger != null ? String(ev.trigger) : "";
    const url = String(ev.url ?? "");
    const param = ev.param_name != null ? String(ev.param_name) : null;
    const path = pathFromUrl(url);
    const confirmed = ev.confirmed_redirect === true;
    const testStatus = ev.test_status;
    const copy = REFLECTED_DETECTION_COPY[trigger] ?? {
      label: "반사(Reflected) 확인",
      summary: "값이 응답에 그대로 반사됨",
      headline: "주입한 값이 응답에 그대로 반사됨",
      detail: "주입한 값이 응답에 그대로 반사되는지만 결정적 규칙으로 확인한 결과입니다.",
    };

    addField(detailFields, "요청 URL", url);
    addField(detailFields, "메서드", ev.method);
    addField(detailFields, "파라미터", param);
    addField(detailFields, "주입 payload", ev.payload_used);
    addField(detailFields, "우회 기법", ev.payload_description);
    addField(detailFields, "HTTP (baseline)", ev.baseline_status);
    addField(detailFields, "HTTP (test)", testStatus);
    addField(detailFields, "반사된 응답 스니펫", ev.evidence_snippet);
    addField(detailFields, "조치 방안", ev.recommendation);
    addField(detailFields, "요청 바디/쿼리", ev.request_body);

    return {
      rowKey: `${engine}|${url}|${param ?? ""}|${trigger}|${ev.payload_used ?? ""}`,
      category: "reflected",
      categoryLabel: CATEGORY_LABELS.reflected,
      checkLabel: param ? `${path} · ${param}` : path,
      issueLabel: confirmed ? copy.label : `${copy.label} — 미확정`,
      headline: copy.headline,
      scaleSummary: confirmed
        ? `HTTP ${testStatus ?? "—"} · 리다이렉트 실행 증거 있음`
        : `HTTP ${testStatus ?? "—"} · 반사만 확인, 리다이렉트 실행 증거 없음`,
      plainExplanation: ev.description != null ? String(ev.description) : copy.detail,
      targetHint: null,
      severity: f.severity,
      severityLabel: sevLabel,
      engine,
      message: f.message,
      detailFields,
    };
  }

  if (ruleId === "1-5-reflected-xss-probe") {
    const url = String(ev.url ?? "");
    const param = ev.param_name != null ? String(ev.param_name) : null;
    const path = pathFromUrl(url);
    const confirmed = ev.confirmed_redirect === true;
    const testStatus = ev.test_status;
    const stored = ev.stored === true;
    const copy = confirmed ? XSS_CONFIRMED_COPY : XSS_CANDIDATE_COPY;

    addField(detailFields, "요청 URL", url);
    addField(detailFields, "메서드 (페이로드 주입)", ev.method);
    addField(detailFields, "파라미터", param);
    addField(detailFields, "주입 payload", ev.payload_used);
    addField(detailFields, "Content-Type", ev.content_type);
    addField(detailFields, "HTTP (baseline)", ev.baseline_status);
    addField(detailFields, "HTTP (test)", testStatus);
    // stored=true면 이 스니펫은 쓰기(method) 요청 자체의 응답이 아니라, 그 직후 값이
    // 실제로 저장됐는지 확인하려고 별도로 보낸 GET 재조회 응답이다 — 라벨로 구분해 주지
    // 않으면 "PATCH를 했는데 왜 조회 성공 메시지가 나오냐"는 혼란을 준다.
    addField(
      detailFields,
      stored ? "반사된 응답 스니펫 (재조회 GET — 쓰기 응답 아님)" : "반사된 응답 스니펫",
      ev.evidence_snippet,
    );
    addField(detailFields, "조치 방안", ev.recommendation);
    addField(detailFields, "요청 바디/쿼리", ev.request_body);

    return {
      rowKey: `${engine}|${url}|${param ?? ""}|xss|${ev.payload_used ?? ""}`,
      category: "xss",
      categoryLabel: CATEGORY_LABELS.xss,
      checkLabel: param ? `${path} · ${param}` : path,
      issueLabel: copy.label,
      headline: copy.headline,
      scaleSummary: confirmed
        ? `HTTP ${testStatus ?? "—"} · text/html 응답에 확정 반사`
        : `HTTP ${testStatus ?? "—"} · ${String(ev.content_type ?? "비-HTML")} 응답에 반사 (후보)`,
      plainExplanation: ev.description != null ? String(ev.description) : copy.detail,
      targetHint: null,
      severity: f.severity,
      severityLabel: sevLabel,
      engine,
      message: f.message,
      detailFields,
    };
  }

  return null;
}

export function parseG15Findings(findings: G15Finding[]): {
  rows: G15Row[];
  other: G15Finding[];
} {
  const rows: G15Row[] = [];
  const other: G15Finding[] = [];
  for (const f of findings) {
    const row = parseG15Row(f);
    if (row) rows.push(row);
    else if (f.message !== "1-5 scan statistics") other.push(f);
  }
  const catOrder: Record<G15Category, number> = { redirect: 0, reflected: 1, xss: 2, cors: 3, crossdomain: 4 };
  rows.sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    const cat = catOrder[a.category] - catOrder[b.category];
    if (cat !== 0) return cat;
    return a.checkLabel.localeCompare(b.checkLabel);
  });
  return { rows, other };
}

export function formatG15TargetDisplay(
  row: Pick<G15Row, "checkLabel" | "targetHint" | "category">,
): string {
  if (row.category === "redirect") return row.checkLabel;
  if (!row.targetHint || row.targetHint === "/") return row.checkLabel;
  return `${row.checkLabel} · ${row.targetHint}`;
}

export function isG15SummaryRow(row: G15Row): boolean {
  return row.severity === "high" || row.severity === "medium" || row.severity === "low";
}
