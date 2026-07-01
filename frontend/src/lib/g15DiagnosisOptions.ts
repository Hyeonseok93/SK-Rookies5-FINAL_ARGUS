/** Per-run options for guideline 1-5 diagnosis (POST /diagnosis/modules/1-5/run). */

export type G15ProbeMode = "base_only" | "sample" | "full";

export type G15DiagnosisPreset = "minimal" | "full" | "manual";

export interface G15DiagnosisOptions {
  probeMode: G15ProbeMode;
  sampleSize: number;
  timeout: number;
  useZap: boolean;
  zapMaxMinutes: number;
  corsEnabled: boolean;
  crossdomainEnabled: boolean;
  /** Empty = use config default (ARGUS redirect sink) */
  redirectSinkBase: string;
}

/** 동작 확인 — CORS/crossdomain만, httpx, ZAP OFF. */
export const MINIMAL_G15_OPTIONS: G15DiagnosisOptions = {
  probeMode: "base_only",
  sampleSize: 60,
  timeout: 8,
  useZap: false,
  zapMaxMinutes: 10,
  corsEnabled: true,
  crossdomainEnabled: true,
  redirectSinkBase: "",
};

/** 전수 — api-tree full + httpx + ZAP. */
export const FULL_G15_OPTIONS: G15DiagnosisOptions = {
  probeMode: "full",
  sampleSize: 120,
  timeout: 10,
  useZap: true,
  zapMaxMinutes: 15,
  corsEnabled: true,
  crossdomainEnabled: true,
  redirectSinkBase: "",
};

export const DEFAULT_G15_OPTIONS = MINIMAL_G15_OPTIONS;

/** @deprecated use MINIMAL_G15_OPTIONS */
export const QUICK_G15_OPTIONS = MINIMAL_G15_OPTIONS;

/** @deprecated use FULL_G15_OPTIONS (without zap) */
export const ZAP_G15_OPTIONS: G15DiagnosisOptions = {
  probeMode: "sample",
  sampleSize: 60,
  timeout: 8,
  useZap: true,
  zapMaxMinutes: 15,
  corsEnabled: true,
  crossdomainEnabled: true,
  redirectSinkBase: "",
};

export function g15OptionsForPreset(preset: G15DiagnosisPreset): G15DiagnosisOptions {
  if (preset === "full") return { ...FULL_G15_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G15_OPTIONS };
  return { ...MINIMAL_G15_OPTIONS };
}

export const G15_PRESET_LABELS: Record<G15DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g15OptionsToPayload(options: G15DiagnosisOptions) {
  const g15: Record<string, boolean | number | string> = {
    probe_mode: options.probeMode,
    sample_size: options.sampleSize,
    timeout: options.timeout,
    zap_enabled: options.useZap,
    zap_max_minutes: options.zapMaxMinutes,
    cors_enabled: options.corsEnabled,
    crossdomain_enabled: options.crossdomainEnabled,
  };
  const sink = options.redirectSinkBase.trim();
  if (sink) {
    g15.redirect_sink_base = sink;
  }
  return { g15 };
}

const PROBE_MODE_LABELS: Record<G15ProbeMode, string> = {
  base_only: "CORS/crossdomain만",
  sample: "sample A+B",
  full: "api-tree 전체",
};

export function g15OptionsSummary(options: G15DiagnosisOptions): string {
  const parts: string[] = ["httpx", PROBE_MODE_LABELS[options.probeMode]];
  if (options.probeMode === "sample") {
    parts.push(`${options.sampleSize} ep`);
  }
  if (options.corsEnabled) parts.push("CORS");
  if (options.crossdomainEnabled) parts.push("crossdomain");
  if (options.redirectSinkBase.trim()) parts.push("custom sink");
  parts.push(`${options.timeout}s`);
  if (options.useZap) parts.push(`ZAP 40031/10028 · ${options.zapMaxMinutes}m`);
  return parts.join(" · ");
}
