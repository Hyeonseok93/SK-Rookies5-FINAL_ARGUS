/** Per-run options for guideline 4-1 diagnosis (POST /diagnosis/modules/4-1/run). */

export type G41ProbeMode = "base_only" | "sample" | "full";

export type G41DiagnosisPreset = "minimal" | "full" | "manual";

export interface G41DiagnosisOptions {
  probeMode: G41ProbeMode;
  sampleSize: number;
  maxEndpoints: number;
  timeout: number;
  maxPairsPerEndpoint: number;
  crossCookieEnabled: boolean;
  tamperEnabled: boolean;
  tamperMaxEndpoints: number;
  cookieAttrEnabled: boolean;
  cookieAttrStrict: boolean;
}

/** 동작 확인 — login matrix + cookie flags만 (httpx cross/tamper 없음). */
export const MINIMAL_G41_OPTIONS: G41DiagnosisOptions = {
  probeMode: "base_only",
  sampleSize: 20,
  maxEndpoints: 40,
  timeout: 8,
  maxPairsPerEndpoint: 6,
  crossCookieEnabled: false,
  tamperEnabled: false,
  tamperMaxEndpoints: 15,
  cookieAttrEnabled: true,
  cookieAttrStrict: true,
};

/** 전수 — api-tree full + cross-cookie + tamper 전체. */
export const FULL_G41_OPTIONS: G41DiagnosisOptions = {
  probeMode: "full",
  sampleSize: 500,
  maxEndpoints: 500,
  timeout: 10,
  maxPairsPerEndpoint: 20,
  crossCookieEnabled: true,
  tamperEnabled: true,
  tamperMaxEndpoints: 200,
  cookieAttrEnabled: true,
  cookieAttrStrict: true,
};

export const DEFAULT_G41_OPTIONS = MINIMAL_G41_OPTIONS;

/** @deprecated use MINIMAL_G41_OPTIONS */
export const QUICK_G41_OPTIONS = MINIMAL_G41_OPTIONS;

export function g41OptionsForPreset(preset: G41DiagnosisPreset): G41DiagnosisOptions {
  if (preset === "full") return { ...FULL_G41_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G41_OPTIONS };
  return { ...MINIMAL_G41_OPTIONS };
}

export const G41_PRESET_LABELS: Record<G41DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g41OptionsToPayload(options: G41DiagnosisOptions) {
  return {
    g41: {
      probe_mode: options.probeMode,
      sample_size: options.sampleSize,
      max_endpoints: options.maxEndpoints,
      timeout: options.timeout,
      max_pairs_per_endpoint: options.maxPairsPerEndpoint,
      cross_cookie_enabled: options.crossCookieEnabled,
      tamper_enabled: options.tamperEnabled,
      tamper_max_endpoints: options.tamperMaxEndpoints,
      cookie_attr_enabled: options.cookieAttrEnabled,
      cookie_attr_strict: options.cookieAttrStrict,
    },
  };
}

const PROBE_MODE_LABELS: Record<G41ProbeMode, string> = {
  base_only: "login matrix + cookie flags",
  sample: "sample cross/tamper",
  full: "api-tree 전체",
};

export function g41OptionsSummary(options: G41DiagnosisOptions): string {
  const parts: string[] = ["httpx", PROBE_MODE_LABELS[options.probeMode]];
  if (options.cookieAttrEnabled) parts.push("HttpOnly/Secure/SameSite");
  if (options.probeMode === "sample") {
    parts.push(`${options.sampleSize} ep · max ${options.maxEndpoints}`);
  }
  if (options.crossCookieEnabled) parts.push("cross-cookie");
  if (options.tamperEnabled) parts.push("tamper");
  if (options.crossCookieEnabled || options.tamperEnabled) {
    parts.push("bearer+cookie+dual+browser");
  }
  parts.push(`${options.timeout}s`);
  return parts.join(" · ");
}
