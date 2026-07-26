/** Per-run options for guideline 6-2 diagnosis (POST /diagnosis/modules/6-2/run). */

export type G62DiagnosisPreset = "minimal" | "full" | "manual";

export interface G62DiagnosisOptions {
  strict: boolean;
  timeout: number;
  probeAccountEmail: string;
  useZap: boolean;
  zapMaxMinutes: number;
}

export const MINIMAL_G62_OPTIONS: G62DiagnosisOptions = {
  strict: true,
  timeout: 10,
  probeAccountEmail: "",
  useZap: false,
  zapMaxMinutes: 5,
};

export const FULL_G62_OPTIONS: G62DiagnosisOptions = {
  strict: true,
  timeout: 10,
  probeAccountEmail: "",
  useZap: true,
  zapMaxMinutes: 10,
};

export const DEFAULT_G62_OPTIONS = MINIMAL_G62_OPTIONS;

export function g62OptionsForPreset(preset: G62DiagnosisPreset): G62DiagnosisOptions {
  if (preset === "full") return { ...FULL_G62_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G62_OPTIONS };
  return { ...MINIMAL_G62_OPTIONS };
}

export const G62_PRESET_LABELS: Record<G62DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g62OptionsToPayload(options: G62DiagnosisOptions) {
  const g62: Record<string, boolean | number | string> = {
    strict: options.strict,
    timeout: options.timeout,
    zap_enabled: options.useZap,
    zap_max_minutes: options.zapMaxMinutes,
  };
  const email = options.probeAccountEmail.trim();
  if (email) {
    g62.probe_account_email = email;
  }
  return { g62 };
}

export function g62OptionsSummary(options: G62DiagnosisOptions): string {
  const parts = [
    "httpx A/B/C",
    options.useZap ? "ZAP 40023" : "httpx only",
    "inventory + dashboard",
    options.strict ? "strict" : "standard",
  ];
  if (options.probeAccountEmail.trim()) {
    parts.push(`account ${options.probeAccountEmail.trim()}`);
  } else {
    parts.push("auto account");
  }
  parts.push(`timeout ${options.timeout}s`);
  if (options.useZap) {
    parts.push(`zap ${options.zapMaxMinutes}m`);
  }
  return parts.join(" · ");
}
