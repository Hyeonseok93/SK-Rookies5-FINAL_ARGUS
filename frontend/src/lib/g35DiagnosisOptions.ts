/** Per-run options for guideline 3-5 diagnosis (inventory mode). */

export type G35ProbeMode = "base_only" | "sample" | "full";

export type G35DiagnosisPreset = "minimal" | "full" | "manual";

export interface G35DiagnosisOptions {
  probeMode: G35ProbeMode;
  sampleSize: number;
  timeout: number;
}

/** 동작 확인 — Base `/` + robots.txt만. */
export const MINIMAL_G35_OPTIONS: G35DiagnosisOptions = {
  probeMode: "base_only",
  sampleSize: 50,
  timeout: 8,
};

/** 전수 — api-tree GET path 전체. */
export const FULL_G35_OPTIONS: G35DiagnosisOptions = {
  probeMode: "full",
  sampleSize: 500,
  timeout: 10,
};

export const DEFAULT_G35_OPTIONS = MINIMAL_G35_OPTIONS;

export function g35OptionsForPreset(preset: G35DiagnosisPreset): G35DiagnosisOptions {
  if (preset === "full") return { ...FULL_G35_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G35_OPTIONS };
  return { ...MINIMAL_G35_OPTIONS };
}

export const G35_PRESET_LABELS: Record<G35DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g35OptionsToPayload(options: G35DiagnosisOptions) {
  return {
    g35: {
      probe_mode: options.probeMode,
      sample_size: options.sampleSize,
      timeout: options.timeout,
    },
  };
}

const PROBE_MODE_LABELS: Record<G35ProbeMode, string> = {
  base_only: "Base `/`만",
  sample: "api-tree 샘플",
  full: "api-tree 전체",
};

export function g35OptionsSummary(options: G35DiagnosisOptions): string {
  const parts: string[] = [
    "httpx inventory",
    "robots.txt + noindex",
    PROBE_MODE_LABELS[options.probeMode],
  ];
  if (options.probeMode === "sample") parts.push(`${options.sampleSize}/base`);
  parts.push(`timeout ${options.timeout}s`);
  return parts.join(" · ");
}
