/** Per-run options for guideline 3-6 diagnosis. */



export type G36ProbeMode = "base_only" | "sample" | "full";



export interface G36DiagnosisOptions {

  probeMode: G36ProbeMode;

  sampleSize: number;

  timeout: number;

}



export const DEFAULT_G36_OPTIONS: G36DiagnosisOptions = {

  probeMode: "base_only",

  sampleSize: 20,

  timeout: 8,

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

