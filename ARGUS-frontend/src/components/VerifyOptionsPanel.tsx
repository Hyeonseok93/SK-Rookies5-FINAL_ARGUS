import type { VerifyOptions } from "../lib/verifyOptions";

function Check({
  label,
  hint,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        disabled
          ? "cursor-not-allowed border-cyber-border/30 opacity-40"
          : checked
            ? "border-violet-400/40 bg-violet-500/10"
            : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 accent-violet-400"
      />
      <span>
        <span className="block text-xs font-medium text-white">{label}</span>
        <span className="block text-[10px] text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

export function VerifyOptionsPanel({
  options,
  onChange,
  disabled,
}: {
  options: VerifyOptions;
  onChange: (next: VerifyOptions) => void;
  disabled?: boolean;
}) {
  const noneSelected = !options.useHttpx && !options.useSpider && !options.useAjaxSpider;

  return (
    <div className="rounded-lg border border-cyber-border/40 bg-cyber-bg/30 p-3">
      <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
        Verify options
      </p>
      <div className="grid gap-2 sm:grid-cols-3">
        <Check
          label="httpx probe"
          hint="Query/body/header + 422 fields (recommended)"
          checked={options.useHttpx}
          disabled={disabled}
          onChange={(useHttpx) => onChange({ ...options, useHttpx })}
        />
        <Check
          label="Spider"
          hint="ZAP link crawl (frontend)"
          checked={options.useSpider}
          disabled={disabled}
          onChange={(useSpider) => onChange({ ...options, useSpider })}
        />
        <Check
          label="Ajax Spider"
          hint="ZAP browser crawl (SPA)"
          checked={options.useAjaxSpider}
          disabled={disabled}
          onChange={(useAjaxSpider) => onChange({ ...options, useAjaxSpider })}
        />
      </div>
      {noneSelected ? (
        <p className="mt-2 text-[10px] text-amber-400">Select at least one option.</p>
      ) : null}
    </div>
  );
}
