/** Per-run options for guideline 4-2 diagnosis (POST /diagnosis/modules/4-2/run). */

export type G42DiagnosisPreset = "minimal" | "full" | "manual";

export interface G42DiagnosisOptions {
  timeout: number;
  reloginEnabled: boolean;
  duplicateLoginEnabled: boolean;
  duplicateLoginIpEnabled: boolean;
  logoutEnabled: boolean;
  clientLogoutEnabled: boolean;
  probeAccountEmail: string;
}

/** 동작 확인 — JWT/토큰 정적 분석만. */
export const MINIMAL_G42_OPTIONS: G42DiagnosisOptions = {
  timeout: 8,
  reloginEnabled: false,
  duplicateLoginEnabled: false,
  duplicateLoginIpEnabled: false,
  logoutEnabled: false,
  clientLogoutEnabled: false,
  probeAccountEmail: "",
};

/** 전수 — lifecycle probe 전부 (relogin · duplicate · logout). */
export const FULL_G42_OPTIONS: G42DiagnosisOptions = {
  timeout: 10,
  reloginEnabled: true,
  duplicateLoginEnabled: true,
  duplicateLoginIpEnabled: true,
  logoutEnabled: true,
  clientLogoutEnabled: true,
  probeAccountEmail: "",
};

export const DEFAULT_G42_OPTIONS = MINIMAL_G42_OPTIONS;

export function g42OptionsForPreset(preset: G42DiagnosisPreset): G42DiagnosisOptions {
  if (preset === "full") return { ...FULL_G42_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G42_OPTIONS };
  return { ...MINIMAL_G42_OPTIONS };
}

export const G42_PRESET_LABELS: Record<G42DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g42OptionsToPayload(options: G42DiagnosisOptions) {
  const g42: Record<string, boolean | number | string> = {
    timeout: options.timeout,
    relogin_enabled: options.reloginEnabled,
    duplicate_login_enabled: options.duplicateLoginEnabled,
    duplicate_login_ip_enabled: options.duplicateLoginIpEnabled,
    logout_enabled: options.logoutEnabled,
    client_logout_enabled: options.clientLogoutEnabled,
  };
  const email = options.probeAccountEmail.trim();
  if (email) {
    g42.probe_account_email = email;
  }
  return { g42 };
}

export function g42OptionsSummary(options: G42DiagnosisOptions): string {
  const parts = ["token/session analysis"];
  const lifecycle: string[] = [];
  if (options.reloginEnabled) lifecycle.push("relogin");
  if (options.duplicateLoginEnabled) lifecycle.push("duplicate");
  if (options.duplicateLoginIpEnabled) lifecycle.push("cross-IP");
  if (options.logoutEnabled) lifecycle.push(options.clientLogoutEnabled ? "logout+client" : "logout");
  if (lifecycle.length) parts.push(`lifecycle: ${lifecycle.join("+")}`);
  else parts.push("lifecycle off");
  parts.push(`${options.timeout}s`);
  if (options.probeAccountEmail.trim()) parts.push(options.probeAccountEmail.trim());
  return parts.join(" · ");
}
