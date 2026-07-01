/** Per-run options for guideline 3-2 diagnosis (POST /diagnosis/modules/3-2/run). */

export interface G32DiagnosisOptions {
  maxAttempts: number;
  timeout: number;
  intervalSec: number;
  probeAccountEmail: string;
  strict: boolean;
}

export const DEFAULT_G32_OPTIONS: G32DiagnosisOptions = {
  maxAttempts: 12,
  timeout: 10,
  intervalSec: 0.05,
  probeAccountEmail: "",
  strict: true,
};

export function g32OptionsToPayload(options: G32DiagnosisOptions) {
  const g32: Record<string, boolean | number | string> = {
    max_attempts: options.maxAttempts,
    timeout: options.timeout,
    interval_sec: options.intervalSec,
    strict: options.strict,
  };
  const email = options.probeAccountEmail.trim();
  if (email) {
    g32.probe_account_email = email;
  }
  return { g32 };
}

export function g32OptionsSummary(options: G32DiagnosisOptions): string {
  const parts = [
    "httpx lockout",
    `${options.maxAttempts} attempts`,
    options.strict ? "strict" : "standard",
    `timeout ${options.timeout}s`,
  ];
  if (options.probeAccountEmail.trim()) {
    parts.push(`account ${options.probeAccountEmail.trim()}`);
  } else {
    parts.push("auto account");
  }
  return parts.join(" · ");
}
