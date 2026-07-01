/** Per-run options for guideline 7-3 diagnosis (POST /diagnosis/modules/7-3/run). */

export type G73ProbeMode = "base_only" | "sample" | "full";

export interface G73DiagnosisOptions {
  strict: boolean;
  includeCdnHeaders: boolean;
  timeout: number;
  extraProbePaths: string;
  probeMode: G73ProbeMode;
  sampleSize: number;
  useZap: boolean;
  zapMaxMinutes: number;
}

export const DEFAULT_G73_OPTIONS: G73DiagnosisOptions = {
  strict: true,
  includeCdnHeaders: false,
  timeout: 8,
  extraProbePaths: "",
  probeMode: "base_only",
  sampleSize: 20,
  useZap: false,
  zapMaxMinutes: 10,
};

export const RELAXED_G73_OPTIONS: G73DiagnosisOptions = {
  strict: false,
  includeCdnHeaders: false,
  timeout: 8,
  extraProbePaths: "",
  probeMode: "base_only",
  sampleSize: 20,
  useZap: false,
  zapMaxMinutes: 10,
};

export const FULL_G73_OPTIONS: G73DiagnosisOptions = {
  ...DEFAULT_G73_OPTIONS,
  probeMode: "full",
  timeout: 10,
};

export function g73OptionsToPayload(options: G73DiagnosisOptions) {
  const paths = options.extraProbePaths
    .split(/[\n,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const g73: Record<string, boolean | number | string | string[]> = {
    strict: options.strict,
    include_cdn_headers: options.includeCdnHeaders,
    timeout: options.timeout,
    probe_mode: options.probeMode,
    sample_size: options.sampleSize,
    zap_enabled: options.useZap,
    zap_max_minutes: options.zapMaxMinutes,
  };
  if (paths.length > 0) {
    g73.extra_probe_paths = paths;
  }
  return { g73 };
}

const PROBE_MODE_LABELS: Record<G73ProbeMode, string> = {
  base_only: "Base URL만",
  sample: "api-tree 샘플",
  full: "api-tree 전체",
};

export function g73OptionsSummary(options: G73DiagnosisOptions): string {
  const parts: string[] = ["httpx HEAD/GET", PROBE_MODE_LABELS[options.probeMode]];
  if (options.probeMode === "sample") {
    parts.push(`${options.sampleSize}/base`);
  }
  parts.push(options.strict ? "strict" : "standard");
  if (options.includeCdnHeaders) parts.push("CDN 헤더 포함");
  const paths = options.extraProbePaths
    .split(/[\n,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  if (paths.length > 0) parts.push(`추가 경로 ${paths.length}개`);
  parts.push(`timeout ${options.timeout}s`);
  if (options.useZap) parts.push(`ZAP passive 10036/10037 · ${options.zapMaxMinutes}m max`);
  return parts.join(" · ");
}
