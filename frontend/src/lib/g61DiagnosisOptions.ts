/** Per-run options for guideline 6-1 diagnosis (POST /diagnosis/modules/6-1/run). */



export type G61ProbeMode = "sample" | "full";



/** UI preset tab — not sent to the API. */

export type G61OptionsTab = "smoke" | "exhaustive" | "custom";



export interface G61DiagnosisOptions {

  probeMode: G61ProbeMode;

  sampleSize: number;

  maxEndpoints: number;

  /** 0 = unlimited (no request cap). */

  maxRequests: number;

  timeout: number;

  intervalSec: number;

  useHttpx: boolean;

  useZap: boolean;

  zapUnified: boolean;

  zapSupplemental: boolean;

  /** 0 = unlimited. */

  zapMaxRequests: number;

  zapMaxMinutes: number;

  /** 0 = seed every probe URL for ZAP supplemental. */

  zapSeedCap: number;

}



/** 빠른 스모크 — api-tree 샘플 40개, 요청 상한 8k. */

export const G61_SMOKE_PRESET: G61DiagnosisOptions = {

  probeMode: "sample",

  sampleSize: 40,

  maxEndpoints: 80,

  maxRequests: 8000,

  timeout: 10,

  intervalSec: 0.02,

  useHttpx: true,

  useZap: true,

  zapUnified: true,

  zapSupplemental: true,

  zapMaxRequests: 8000,

  zapMaxMinutes: 15,

  zapSeedCap: 200,

};



/** 전체 전수 — Full, 엔드포인트·요청·ZAP seed 상한 없음. */

export const G61_EXHAUSTIVE_PRESET: G61DiagnosisOptions = {

  probeMode: "full",

  sampleSize: 500,

  maxEndpoints: 0,

  maxRequests: 0,

  timeout: 12,

  intervalSec: 0.02,

  useHttpx: true,

  useZap: true,

  zapUnified: true,

  zapSupplemental: true,

  zapMaxRequests: 0,

  zapMaxMinutes: 120,

  zapSeedCap: 0,

};



/** @deprecated use G61_SMOKE_PRESET */

export const DEFAULT_G61_OPTIONS = G61_SMOKE_PRESET;



export function g61RequestCapLabel(cap: number): string {

  return cap <= 0 ? "무제한" : cap.toLocaleString();

}



export function g61PresetForTab(tab: G61OptionsTab): G61DiagnosisOptions {

  if (tab === "exhaustive") return { ...G61_EXHAUSTIVE_PRESET };

  if (tab === "smoke") return { ...G61_SMOKE_PRESET };

  return { ...G61_SMOKE_PRESET };

}



export function g61DetectTab(options: G61DiagnosisOptions): G61OptionsTab {

  if (

    options.probeMode === "full" &&

    options.maxEndpoints === 0 &&

    options.maxRequests <= 0 &&

    options.zapMaxRequests <= 0 &&

    options.zapSeedCap <= 0

  ) {

    return "exhaustive";

  }

  if (

    options.probeMode === "sample" &&

    options.sampleSize === 40 &&

    options.maxEndpoints === 80 &&

    options.maxRequests === 8000 &&

    options.zapMaxRequests === 8000

  ) {

    return "smoke";

  }

  return "custom";

}



export const G61_TAB_LABELS: Record<G61OptionsTab, string> = {

  smoke: "스모크",

  exhaustive: "전체 전수",

  custom: "직접 설정",

};



export const G61_TAB_HINTS: Record<G61OptionsTab, string> = {

  smoke: "api-tree에서 40개 API만 · 요청 각 8,000건 상한",

  exhaustive:

    "api-tree API 전부 · param/body/path/method/header 전수 · httpx+ZAP 요청 상한 없음",

  custom: "아래 값을 직접 수정 (max_requests=0 이면 무제한)",

};



export function g61OptionsToPayload(options: G61DiagnosisOptions) {

  return {

    g61: {

      probe_mode: options.probeMode,

      sample_size: options.sampleSize,

      max_endpoints: options.maxEndpoints,

      max_requests: options.maxRequests,

      timeout: options.timeout,

      interval_sec: options.intervalSec,

      httpx_enabled: options.useHttpx,

      zap_enabled: options.useZap,

      zap_unified_enabled: options.zapUnified,

      zap_supplemental_enabled: options.zapSupplemental,

      zap_max_requests: options.zapMaxRequests,

      zap_max_minutes: options.zapMaxMinutes,

      zap_seed_cap: options.zapSeedCap,

    },

  };

}



export function g61ScopeLabel(options: G61DiagnosisOptions): string {

  if (options.probeMode === "full") {

    return options.maxEndpoints > 0

      ? `Full ≤${options.maxEndpoints} API`

      : "Full · api-tree 전체 API";

  }

  return `Sample · ${options.sampleSize} API`;

}



export function g61OptionsSummary(options: G61DiagnosisOptions): string {

  const parts: string[] = [

    options.useHttpx ? "httpx" : "no httpx",

    g61ScopeLabel(options),

    `httpx ${g61RequestCapLabel(options.maxRequests)}`,

    `timeout ${options.timeout}s`,

  ];

  if (options.useZap) {

    const zapParts: string[] = [];

    if (options.zapUnified) zapParts.push("unified");

    if (options.zapSupplemental) zapParts.push("90022/10023");

    parts.push(

      `ZAP ${zapParts.join("+") || "on"} · ${g61RequestCapLabel(options.zapMaxRequests)} · ${options.zapMaxMinutes}m`,

    );

  } else {

    parts.push("ZAP off");

  }

  return parts.join(" · ");

}


