/** Per-run options for guideline 4-1 diagnosis (POST /diagnosis/modules/4-1/run). */

export type G41ProbeMode = "base_only" | "sample" | "full";

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

export const DEFAULT_G41_OPTIONS: G41DiagnosisOptions = {
  probeMode: "sample",
  sampleSize: 40,
  maxEndpoints: 80,
  timeout: 8,
  maxPairsPerEndpoint: 12,
  crossCookieEnabled: true,
  tamperEnabled: true,
  tamperMaxEndpoints: 30,
  cookieAttrEnabled: true,
  cookieAttrStrict: true,
};

export const QUICK_G41_OPTIONS: G41DiagnosisOptions = {
  ...DEFAULT_G41_OPTIONS,
  probeMode: "sample",
  sampleSize: 20,
  maxEndpoints: 40,
  maxPairsPerEndpoint: 6,
  tamperMaxEndpoints: 15,
};

export const FULL_G41_OPTIONS: G41DiagnosisOptions = {
  ...DEFAULT_G41_OPTIONS,
  probeMode: "full",
  sampleSize: 120,
  maxEndpoints: 200,
  maxPairsPerEndpoint: 20,
  tamperMaxEndpoints: 60,
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
