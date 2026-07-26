/** Per-run options for guideline 7-4 diagnosis (POST /diagnosis/modules/7-4/run). */

export type G74ProbeMode = "base_only" | "sample" | "full";

export type G74DiagnosisPreset = "minimal" | "full" | "manual";

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

/** Smoke test — Base URL only, httpx only. */
export const MINIMAL_G74_OPTIONS: G74DiagnosisOptions = {
  strict: true,
  checkCookies: true,
  timeout: 8,
  extraProbePaths: "",
  probeMode: "base_only",
  sampleSize: 20,
  useZap: false,
  zapMaxMinutes: 10,
};

export const DEFAULT_G74_OPTIONS: G74DiagnosisOptions = {
  ...MINIMAL_G74_OPTIONS,
};

/** Full inventory + httpx + ZAP passive. */
export const FULL_G74_OPTIONS: G74DiagnosisOptions = {
  strict: true,
  checkCookies: true,
  timeout: 10,
  extraProbePaths: "",
  probeMode: "full",
  sampleSize: 20,
  useZap: true,
  zapMaxMinutes: 15,
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

export function g74OptionsForPreset(preset: G74DiagnosisPreset): G74DiagnosisOptions {
  if (preset === "full") return { ...FULL_G74_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G74_OPTIONS };
  return { ...DEFAULT_G74_OPTIONS };
}

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

export const G74_PRESET_LABELS: Record<G74DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};
