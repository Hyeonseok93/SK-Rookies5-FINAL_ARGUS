/** Per-run options for guideline 3-6 diagnosis. */

export type G36ProbeMode = "base_only" | "sample" | "full";

export type G36DiagnosisPreset = "minimal" | "full" | "manual";

export interface G36DiagnosisOptions {
  probeMode: G36ProbeMode;
  sampleSize: number;
  timeout: number;
}

/** 동작 확인 — 내장 wordlist만. */
export const MINIMAL_G36_OPTIONS: G36DiagnosisOptions = {
  probeMode: "base_only",
  sampleSize: 20,
  timeout: 8,
};

/** 전수 — wordlist + api-tree 파일형 path 전체. */
export const FULL_G36_OPTIONS: G36DiagnosisOptions = {
  probeMode: "full",
  sampleSize: 500,
  timeout: 10,
};

export const DEFAULT_G36_OPTIONS = MINIMAL_G36_OPTIONS;

export function g36OptionsForPreset(preset: G36DiagnosisPreset): G36DiagnosisOptions {
  if (preset === "full") return { ...FULL_G36_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G36_OPTIONS };
  return { ...MINIMAL_G36_OPTIONS };
}

export const G36_PRESET_LABELS: Record<G36DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g36OptionsToPayload(options: G36DiagnosisOptions) {
  return {
    g36: {
      probe_mode: options.probeMode,
      sample_size: options.sampleSize,
      timeout: options.timeout,
    },
  };
}

const PROBE_MODE_LABELS: Record<G36ProbeMode, string> = {
  base_only: "내장 wordlist",
  sample: "wordlist+api-tree 샘플",
  full: "wordlist+api-tree 전체",
};

export function g36OptionsSummary(options: G36DiagnosisOptions): string {
  const parts: string[] = [
    "httpx GET",
    "backup/test wordlist",
    PROBE_MODE_LABELS[options.probeMode],
  ];
  if (options.probeMode === "sample") parts.push(`${options.sampleSize}/base`);
  parts.push(`timeout ${options.timeout}s`);
  return parts.join(" · ");
}
