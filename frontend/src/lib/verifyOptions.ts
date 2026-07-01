export interface VerifyOptions {
  useHttpx: boolean;
  useSpider: boolean;
  useAjaxSpider: boolean;
}

export const DEFAULT_VERIFY_OPTIONS: VerifyOptions = {
  useHttpx: true,
  useSpider: false,
  useAjaxSpider: false,
};
