/** Per-run options for guideline 7-2 diagnosis. */

export type G72ProbeMode = "base_only" | "sample" | "full";

export type G72DiagnosisPreset = "minimal" | "full" | "manual";

export interface G72DiagnosisOptions {
  probeMode: G72ProbeMode;
  sampleSize: number;
  timeout: number;
  useZap: boolean;
  zapMaxMinutes: number;
}

export const MINIMAL_G72_OPTIONS: G72DiagnosisOptions = {
  probeMode: "base_only",
  sampleSize: 20,
  timeout: 8,
  useZap: false,
  zapMaxMinutes: 15,
};

export const FULL_G72_OPTIONS: G72DiagnosisOptions = {
  probeMode: "full",
  sampleSize: 20,
  timeout: 12,
  useZap: true,
  zapMaxMinutes: 20,
};

export const DEFAULT_G72_OPTIONS = MINIMAL_G72_OPTIONS;

export function g72OptionsForPreset(preset: G72DiagnosisPreset): G72DiagnosisOptions {
  if (preset === "full") return { ...FULL_G72_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G72_OPTIONS };
  return { ...MINIMAL_G72_OPTIONS };
}

export const G72_PRESET_LABELS: Record<G72DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g72OptionsToPayload(options: G72DiagnosisOptions) {
  return {
    g72: {
      probe_mode: options.probeMode,
      sample_size: options.sampleSize,
      timeout: options.timeout,
      use_extended_wordlist: true,
      zap_enabled: options.useZap,
      zap_max_minutes: options.zapMaxMinutes,
    },
  };
}

const PROBE_MODE_LABELS: Record<G72ProbeMode, string> = {
  base_only: "내장 wordlist 전체",
  sample: "wordlist+api-tree 샘플",
  full: "wordlist+api-tree 전체",
};

export function g72OptionsSummary(options: G72DiagnosisOptions): string {
  const parts: string[] = [
    "httpx GET",
    "builtin wordlist",
    PROBE_MODE_LABELS[options.probeMode],
  ];
  if (options.probeMode === "sample") parts.push(`${options.sampleSize}/base`);
  parts.push(`timeout ${options.timeout}s`);
  if (options.useZap) parts.push(`ZAP Rule 0/10033 · ${options.zapMaxMinutes}m max`);
  return parts.join(" · ");
}
