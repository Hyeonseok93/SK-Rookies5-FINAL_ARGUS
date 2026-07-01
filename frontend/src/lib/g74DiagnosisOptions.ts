/** Per-run options for guideline 7-4 diagnosis (POST /diagnosis/modules/7-4/run). */

export type G74ProbeMode = "base_only" | "sample" | "full";

export interface G74DiagnosisOptions {
  strict: boolean;
  checkCookies: boolean;
  timeout: number;
  extraProbePaths: string;
  probeMode: G74ProbeMode;
  sampleSize: number;
  useZap: boolean;
  zapMaxMinutes: number;
}

export const DEFAULT_G74_OPTIONS: G74DiagnosisOptions = {
  strict: true,
  checkCookies: true,
  timeout: 8,
  extraProbePaths: "",
  probeMode: "base_only",
  sampleSize: 20,
  useZap: false,
  zapMaxMinutes: 10,
};

export const RELAXED_G74_OPTIONS: G74DiagnosisOptions = {
  strict: false,
  checkCookies: true,
  timeout: 8,
  extraProbePaths: "",
  probeMode: "base_only",
  sampleSize: 20,
  useZap: false,
  zapMaxMinutes: 10,
};

export const FULL_G74_OPTIONS: G74DiagnosisOptions = {
  ...DEFAULT_G74_OPTIONS,
  probeMode: "full",
  timeout: 10,
};

export function g74OptionsToPayload(options: G74DiagnosisOptions) {
  const paths = options.extraProbePaths
    .split(/[\n,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const g74: Record<string, boolean | number | string | string[]> = {
    strict: options.strict,
    check_cookies: options.checkCookies,
    timeout: options.timeout,
    probe_mode: options.probeMode,
    sample_size: options.sampleSize,
    zap_enabled: options.useZap,
    zap_max_minutes: options.zapMaxMinutes,
  };
  if (paths.length > 0) {
    g74.extra_probe_paths = paths;
  }
  return { g74 };
}

const PROBE_MODE_LABELS: Record<G74ProbeMode, string> = {
  base_only: "Base URL만",
  sample: "api-tree 샘플",
  full: "api-tree 전체",
};

export function g74OptionsSummary(options: G74DiagnosisOptions): string {
  const parts: string[] = ["httpx GET", PROBE_MODE_LABELS[options.probeMode]];
  if (options.probeMode === "sample") {
    parts.push(`${options.sampleSize}/base`);
  }
  parts.push(options.strict ? "strict" : "standard");
  if (options.checkCookies) parts.push("cookies");
  const paths = options.extraProbePaths
    .split(/[\n,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  if (paths.length > 0) parts.push(`추가 경로 ${paths.length}개`);
  parts.push(`timeout ${options.timeout}s`);
  if (options.useZap) {
    parts.push(`ZAP passive HSTS/CSP/XFO/nosniff/cookie · ${options.zapMaxMinutes}m max`);
  }
  return parts.join(" · ");
}
