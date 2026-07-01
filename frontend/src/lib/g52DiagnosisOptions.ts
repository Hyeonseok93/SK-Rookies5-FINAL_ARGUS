/** Per-run options for guideline 5-2 diagnosis (POST /diagnosis/modules/5-2/run). */

export type G52ProbeMode = "sample" | "full";

export type G52OptionsTab = "smoke" | "exhaustive" | "custom";

export interface G52DiagnosisOptions {
  probeMode: G52ProbeMode;
  sampleSize: number;
  maxEndpoints: number;
  timeout: number;
  intervalSec: number;
  checkRequestUrl: boolean;
  checkRequestBody: boolean;
  checkResponseBody: boolean;
  checkHttpPlain: boolean;
  enableAuthModes: boolean;
}

export const G52_SMOKE_PRESET: G52DiagnosisOptions = {
  probeMode: "sample",
  sampleSize: 40,
  maxEndpoints: 80,
  timeout: 12,
  intervalSec: 0.02,
  checkRequestUrl: true,
  checkRequestBody: true,
  checkResponseBody: true,
  checkHttpPlain: true,
  enableAuthModes: true,
};

/** api-tree 전체 API · 요청/응답 PII 전수 검사 */
export const G52_EXHAUSTIVE_PRESET: G52DiagnosisOptions = {
  probeMode: "full",
  sampleSize: 500,
  maxEndpoints: 0,
  timeout: 12,
  intervalSec: 0.02,
  checkRequestUrl: true,
  checkRequestBody: true,
  checkResponseBody: true,
  checkHttpPlain: true,
  enableAuthModes: true,
};

export const DEFAULT_G52_OPTIONS = G52_SMOKE_PRESET;

export function g52DetectTab(options: G52DiagnosisOptions): G52OptionsTab {
  if (
    options.probeMode === "full" &&
    options.maxEndpoints === 0 &&
    options.checkRequestUrl &&
    options.checkRequestBody &&
    options.checkResponseBody &&
    options.checkHttpPlain
  ) {
    return "exhaustive";
  }
  if (
    options.probeMode === "sample" &&
    options.sampleSize === 40 &&
    options.maxEndpoints === 80
  ) {
    return "smoke";
  }
  return "custom";
}

export const G52_TAB_LABELS: Record<G52OptionsTab, string> = {
  smoke: "스모크",
  exhaustive: "전체 전수",
  custom: "직접 설정",
};

export const G52_TAB_HINTS: Record<G52OptionsTab, string> = {
  smoke: "api-tree 40개 API · 요청 URL/body + 응답 body PII 검사",
  exhaustive: "api-tree API 전체 · 주민번호·전화·이메일·계좌·여권 등 마스킹 없으면 탐지",
  custom: "아래 값을 직접 수정",
};

export function g52OptionsToPayload(options: G52DiagnosisOptions) {
  return {
    g52: {
      probe_mode: options.probeMode,
      sample_size: options.sampleSize,
      max_endpoints: options.maxEndpoints,
      timeout: options.timeout,
      interval_sec: options.intervalSec,
      check_request_url: options.checkRequestUrl,
      check_request_body: options.checkRequestBody,
      check_response_body: options.checkResponseBody,
      check_http_plain: options.checkHttpPlain,
      enable_auth_modes: options.enableAuthModes,
    },
  };
}

export function g52ScopeLabel(options: G52DiagnosisOptions): string {
  if (options.probeMode === "full") {
    return options.maxEndpoints > 0
      ? `Full ≤${options.maxEndpoints} API`
      : "Full · api-tree 전체 API";
  }
  return `Sample · ${options.sampleSize} API`;
}

export function g52OptionsSummary(options: G52DiagnosisOptions): string {
  const checks = [
    options.checkRequestUrl ? "req URL" : null,
    options.checkRequestBody ? "req body" : null,
    options.checkResponseBody ? "resp" : null,
    options.checkHttpPlain ? "HTTP" : null,
  ]
    .filter(Boolean)
    .join("+");
  return `httpx · ${g52ScopeLabel(options)} · ${checks || "checks off"} · ${options.enableAuthModes ? "multi-auth" : "anon"}`;
}
