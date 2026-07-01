/** Per-run options for guideline 6-2 diagnosis (POST /diagnosis/modules/6-2/run). */



export interface G62DiagnosisOptions {

  strict: boolean;

  timeout: number;

  probeAccountEmail: string;

  useZap: boolean;

  zapMaxMinutes: number;

}



export const DEFAULT_G62_OPTIONS: G62DiagnosisOptions = {

  strict: true,

  timeout: 10,

  probeAccountEmail: "",

  useZap: true,

  zapMaxMinutes: 5,

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

