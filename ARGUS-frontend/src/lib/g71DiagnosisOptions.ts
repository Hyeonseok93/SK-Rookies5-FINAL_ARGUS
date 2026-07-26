/** Per-run options for guideline 7-1 diagnosis (POST /diagnosis/modules/7-1/run). */

export type G71ProbeMode = "base_only" | "sample" | "full";

export type G71DiagnosisPreset = "minimal" | "full" | "manual";

export interface G71DiagnosisOptions {
  strictRisky: boolean;
  timeout: number;
  extraProbePaths: string;
  probeMode: G71ProbeMode;
  sampleSize: number;
  useZap: boolean;
  zapMaxMinutes: number;
}

export const MINIMAL_G71_OPTIONS: G71DiagnosisOptions = {
  strictRisky: true,
  timeout: 8,
  extraProbePaths: "",
  probeMode: "base_only",
  sampleSize: 20,
  useZap: false,
  zapMaxMinutes: 10,
};

export const FULL_G71_OPTIONS: G71DiagnosisOptions = {
  strictRisky: true,
  timeout: 10,
  extraProbePaths: "",
  probeMode: "full",
  sampleSize: 20,
  useZap: true,
  zapMaxMinutes: 15,
};

export const DEFAULT_G71_OPTIONS = MINIMAL_G71_OPTIONS;

export const RELAXED_G71_OPTIONS: G71DiagnosisOptions = {
  strictRisky: false,
  timeout: 8,
  extraProbePaths: "",
  probeMode: "base_only",
  sampleSize: 20,
  useZap: false,
  zapMaxMinutes: 10,
};

export function g71OptionsForPreset(preset: G71DiagnosisPreset): G71DiagnosisOptions {
  if (preset === "full") return { ...FULL_G71_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G71_OPTIONS };
  return { ...MINIMAL_G71_OPTIONS };
}

export const G71_PRESET_LABELS: Record<G71DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g71OptionsToPayload(options: G71DiagnosisOptions) {
  const paths = options.extraProbePaths
    .split(/[\n,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const g71: Record<string, boolean | number | string | string[]> = {
    strict_risky: options.strictRisky,
    timeout: options.timeout,
    probe_mode: options.probeMode,
    sample_size: options.sampleSize,
    zap_enabled: options.useZap,
    zap_max_minutes: options.zapMaxMinutes,
  };
  if (paths.length > 0) {
    g71.extra_probe_paths = paths;
  }
  return { g71 };
}

const PROBE_MODE_LABELS: Record<G71ProbeMode, string> = {
  base_only: "Base URL만",
  sample: "api-tree 샘플",
  full: "api-tree 전체",
};

export function g71OptionsSummary(options: G71DiagnosisOptions): string {
  const parts: string[] = ["httpx TRACE/OPTIONS", PROBE_MODE_LABELS[options.probeMode]];
  if (options.probeMode === "sample") {
    parts.push(`${options.sampleSize}/base`);
  }
  parts.push(options.strictRisky ? "strict risky" : "TRACE/TRACK only");
  const paths = options.extraProbePaths
    .split(/[\n,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  if (paths.length > 0) parts.push(`추가 경로 ${paths.length}개`);
  parts.push(`timeout ${options.timeout}s`);
  if (options.useZap) parts.push(`ZAP active 90028 · ${options.zapMaxMinutes}m max`);
  return parts.join(" · ");
}
