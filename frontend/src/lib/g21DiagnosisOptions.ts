/** Per-run options for guideline 2-1 diagnosis (POST /diagnosis/modules/2-1/run). */

export interface G21DiagnosisOptions {
  sellerEmail: string;
  sellerPassword: string;
  sellerId: number;
  userEmail: string;
  userPassword: string;
  timeout: number;
}

export const DEFAULT_G21_OPTIONS: G21DiagnosisOptions = {
  sellerEmail: "",
  sellerPassword: "",
  sellerId: 0,
  userEmail: "",
  userPassword: "",
  timeout: 10,
};

export function g21OptionsToPayload(options: G21DiagnosisOptions) {
  return {
    g21: {
      seller_email: options.sellerEmail.trim(),
      seller_password: options.sellerPassword,
      seller_id: options.sellerId,
      user_email: options.userEmail.trim(),
      user_password: options.userPassword,
      timeout: options.timeout,
    },
  };
}

export function g21OptionsSummary(options: G21DiagnosisOptions): string {
  const parts = ["file upload httpx"];
  if (options.sellerEmail.trim()) parts.push(`seller: ${options.sellerEmail.trim()}`);
  if (options.sellerId > 0) parts.push(`sellerId=${options.sellerId}`);
  if (options.userEmail.trim()) parts.push(`user: ${options.userEmail.trim()}`);
  parts.push(`${options.timeout}s`);
  return parts.join(" · ");
}

export function g21OptionsValid(options: G21DiagnosisOptions): boolean {
  return (
    options.sellerEmail.trim().includes("@") &&
    options.sellerPassword.trim().length > 0 &&
    options.sellerId > 0
  );
}
