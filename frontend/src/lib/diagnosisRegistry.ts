/** Guideline sections that require manual verification (no automated run). */
export const MANUAL_DIAGNOSIS_SECTIONS = new Set([
  "1-3",
  "1-4",
  "3-1",
  "3-3",
  "4-1",
  "4-2",
  "4-3",
  "5-1",
  "8-1",
]);

export function isManualDiagnosisSection(sectionId: string): boolean {
  return MANUAL_DIAGNOSIS_SECTIONS.has(sectionId);
}

/** Guideline sections that open an options dialog before run. */
export const DIAGNOSIS_SECTIONS_WITH_DIALOG = new Set([
  "1-2",
  "1-5",
  "2-2",
  "3-2",
  "3-5",
  "3-6",
  "6-1",
  "6-2",
  "7-1",
  "7-2",
  "7-3",
  "7-4",
]);

export function sectionHasStartDialog(sectionId: string): boolean {
  return DIAGNOSIS_SECTIONS_WITH_DIALOG.has(sectionId);
}
