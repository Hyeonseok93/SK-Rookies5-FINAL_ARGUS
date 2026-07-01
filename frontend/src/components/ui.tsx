import type { ReactNode } from "react";

const colors: Record<string, string> = {
  GET: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  POST: "bg-sky-500/15 text-sky-400 border-sky-500/30",
  PUT: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  PATCH: "bg-violet-500/15 text-violet-400 border-violet-500/30",
  DELETE: "bg-rose-500/15 text-rose-400 border-rose-500/30",
};

export function MethodBadge({ method }: { method: string }) {
  const cls = colors[method.toUpperCase()] ?? "bg-slate-500/15 text-slate-400 border-slate-500/30";
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold ${cls}`}>
      {method}
    </span>
  );
}

export function StatCard({
  label,
  value,
  lines,
  accent = "text-cyber-accent",
  compact = false,
}: {
  label: string;
  value?: string | number;
  /** One entry per row; scrolls inside the card when taller than the value slot. */
  lines?: string[];
  accent?: string;
  compact?: boolean;
}) {
  return (
    <div className="rounded-lg border border-cyber-border bg-cyber-panel/80 p-4 backdrop-blur-sm">
      <p className="text-xs uppercase tracking-widest text-cyber-muted">{label}</p>
      {lines ? (
        <div className="stat-card-scroll mt-2 h-9 overflow-y-auto overflow-x-hidden pr-0.5">
          {lines.length === 0 ? (
            <p className={`font-bold ${accent} font-display text-3xl`}>—</p>
          ) : (
            lines.map((line) => (
              <p key={line} className={`font-mono text-sm leading-snug font-bold ${accent}`}>
                {line}
              </p>
            ))
          )}
        </div>
      ) : (
        <p
          className={`mt-2 font-bold ${accent} ${
            compact ? "font-mono text-sm leading-snug" : "font-display text-3xl"
          }`}
        >
          {value}
        </p>
      )}
    </div>
  );
}

export function Panel({
  title,
  children,
  action,
  trailing,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
  trailing?: ReactNode;
}) {
  return (
    <section className="rounded-xl border border-cyber-border bg-cyber-panel/60 backdrop-blur-sm">
      <div className="relative flex min-h-11 items-center border-b border-cyber-border px-5 py-3">
        <h2 className="font-display text-sm font-semibold tracking-wide text-cyber-accent">
          {title}
        </h2>
        {action ? (
          <div className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
            <div className="pointer-events-auto">{action}</div>
          </div>
        ) : null}
        {trailing ? <div className="ml-auto flex shrink-0">{trailing}</div> : null}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}
