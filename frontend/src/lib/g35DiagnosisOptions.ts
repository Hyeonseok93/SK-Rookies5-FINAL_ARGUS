/** Per-run options for guideline 3-5 diagnosis (inventory mode). */

export type G35ProbeMode = "base_only" | "sample" | "full";

export interface G35DiagnosisOptions {
  probeMode: G35ProbeMode;
  sampleSize: number;
  timeout: number;
}

export const DEFAULT_G35_OPTIONS: G35DiagnosisOptions = {
  probeMode: "sample",
  sampleSize: 50,
  timeout: 8,
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
