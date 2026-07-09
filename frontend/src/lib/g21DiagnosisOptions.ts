/** Per-run options for guideline 2-1 diagnosis (POST /diagnosis/modules/2-1/run). */

export interface G21DiagnosisOptions {
  sellerEmail: string;
  sellerPassword: string;
  userEmail: string;
  userPassword: string;
  adminEmail: string;
  adminPassword: string;
  timeout: number;
}

export const DEFAULT_G21_OPTIONS: G21DiagnosisOptions = {
  sellerEmail: "",
  sellerPassword: "",
  userEmail: "",
  userPassword: "",
  adminEmail: "",
  adminPassword: "",
  timeout: 10,
};

export function g21OptionsToPayload(options: G21DiagnosisOptions) {
  return {
    g21: {
      seller_email: options.sellerEmail.trim(),
      seller_password: options.sellerPassword,
      user_email: options.userEmail.trim(),
      user_password: options.userPassword,
      admin_email: options.adminEmail.trim(),
      admin_password: options.adminPassword,
      timeout: options.timeout,
    },
  };
}

export function g21OptionsSummary(options: G21DiagnosisOptions): string {
  const parts = ["file upload httpx"];
  if (options.sellerEmail.trim()) parts.push(`seller: ${options.sellerEmail.trim()}`);
  if (options.userEmail.trim()) parts.push(`user: ${options.userEmail.trim()}`);
  if (options.adminEmail.trim()) parts.push(`admin: ${options.adminEmail.trim()}`);
  parts.push(`${options.timeout}s`);
  return parts.join(" · ");
}

export function g21OptionsValid(_options: G21DiagnosisOptions): boolean {
  return true;
}
