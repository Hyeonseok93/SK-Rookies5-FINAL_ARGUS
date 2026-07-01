/** Per-run options for guideline 3-4 diagnosis (POST /diagnosis/modules/3-4/run). */

export type G34InventoryScope = "login_only" | "full";

export type G34DiagnosisPreset = "minimal" | "full" | "manual";

export interface G34DiagnosisOptions {
  inventoryScope: G34InventoryScope;
}

/** 동작 확인 — login matrix · host separation만. */
export const MINIMAL_G34_OPTIONS: G34DiagnosisOptions = {
  inventoryScope: "login_only",
};

/** 전수 — login + api-tree admin path heuristics 전체. */
export const FULL_G34_OPTIONS: G34DiagnosisOptions = {
  inventoryScope: "full",
};

export const DEFAULT_G34_OPTIONS = MINIMAL_G34_OPTIONS;

export function g34OptionsForPreset(preset: G34DiagnosisPreset): G34DiagnosisOptions {
  if (preset === "full") return { ...FULL_G34_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G34_OPTIONS };
  return { ...MINIMAL_G34_OPTIONS };
}

export const G34_PRESET_LABELS: Record<G34DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g34OptionsToPayload(options: G34DiagnosisOptions) {
  return {
    g34: {
      inventory_scope: options.inventoryScope,
    },
  };
}

const SCOPE_LABELS: Record<G34InventoryScope, string> = {
  login_only: "login matrix만",
  full: "login + api-tree 전체",
};

export function g34OptionsSummary(options: G34DiagnosisOptions): string {
  return `inventory 분석 · ${SCOPE_LABELS[options.inventoryScope]}`;
}
