import type { DiagnosisG12RunOptionsPayload } from "../types";

/** Per-run options for guideline 1-2 injection diagnosis (api-tree fixed). */

export type G12DiagnosisPreset = "minimal" | "full" | "manual";

export type G12VerificationMode = "strict" | "balanced" | "aggressive";

export interface G12DiagnosisOptions {
  maxTargets: number;
  scanAllInventory: boolean;
  useInjector: boolean;
  useDirect: boolean;
  useZap: boolean;
  zapMaxMinutes: number;
  verificationMode: G12VerificationMode;
  injectionTypes: string[];
  includeUnsafeMethods: boolean;
}

/** 동작 확인 — api-tree 상위 40, direct requests, ZAP OFF. */
export const MINIMAL_G12_OPTIONS: G12DiagnosisOptions = {
  maxTargets: 40,
  scanAllInventory: false,
  useInjector: true,
  useDirect: true,
  useZap: false,
  zapMaxMinutes: 20,
  verificationMode: "balanced",
  injectionTypes: ["SQL", "NOSQL", "SSTI", "COMMAND"],
  includeUnsafeMethods: false,
};

/** 전수 — 단독 CLI와 동일: api-tree 전체 + ZAP + direct(SQL only) + aggressive. */
export const FULL_G12_OPTIONS: G12DiagnosisOptions = {
  maxTargets: 200,
  scanAllInventory: true,
  useInjector: true,
  useDirect: true,
  useZap: true,
  zapMaxMinutes: 30,
  verificationMode: "strict",
  injectionTypes: ["SQL"],
  includeUnsafeMethods: false,
};

export const DEFAULT_G12_OPTIONS = MINIMAL_G12_OPTIONS;

export function g12OptionsForPreset(preset: G12DiagnosisPreset): G12DiagnosisOptions {
  if (preset === "full") return { ...FULL_G12_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G12_OPTIONS };
  return { ...MINIMAL_G12_OPTIONS };
}

export const G12_PRESET_LABELS: Record<G12DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g12OptionsToPayload(options: G12DiagnosisOptions): { g12: DiagnosisG12RunOptionsPayload } {
  const g12: DiagnosisG12RunOptionsPayload = {
    injector_enabled: options.useInjector,
    direct_enabled: options.useDirect,
    zap_enabled: options.useZap,
    zap_max_minutes: options.zapMaxMinutes,
    verification_mode: options.verificationMode,
    injection_types: options.injectionTypes,
    scan_all_inventory: options.scanAllInventory,
    include_unsafe_methods: options.includeUnsafeMethods,
  };
  if (!options.scanAllInventory) {
    g12.max_targets = options.maxTargets;
  }
  return { g12 };
}

export function g12OptionsSummary(options: G12DiagnosisOptions): string {
  const parts: string[] = ["api-tree"];
  if (options.scanAllInventory) parts.push("inventory 전체");
  else parts.push(`상위 ${options.maxTargets}`);
  if (options.useZap) parts.push("ZAP→requests");
  if (options.useDirect) parts.push("direct requests");
  parts.push(options.injectionTypes.join("+"));
  return parts.join(" · ");
}
