export function OutcomeTag({
  active,
  label,
  count,
  onClick,
  tone,
}: {
  active: boolean;
  label: string;
  count: number;
  onClick: () => void;
  tone: "final" | "discovered" | "rejected" | "ready" | "verified";
}) {
  const styles: Record<string, { active: string; idle: string }> = {
    final: {
      active: "border-emerald-400/60 bg-emerald-500/20 text-emerald-300",
      idle: "border-cyber-border text-cyber-muted hover:border-emerald-400/40 hover:text-emerald-300/80",
    },
    discovered: {
      active: "border-sky-400/60 bg-sky-500/20 text-sky-300",
      idle: "border-cyber-border text-cyber-muted hover:border-sky-400/40 hover:text-sky-300/80",
    },
    rejected: {
      active: "border-rose-400/60 bg-rose-500/20 text-rose-300",
      idle: "border-cyber-border text-cyber-muted hover:border-rose-400/40 hover:text-rose-300/80",
    },
    ready: {
      active: "border-amber-400/60 bg-amber-500/20 text-amber-300",
      idle: "border-cyber-border text-cyber-muted hover:border-amber-400/40 hover:text-amber-300/80",
    },
    verified: {
      active: "border-violet-400/60 bg-violet-500/20 text-violet-300",
      idle: "border-cyber-border text-cyber-muted hover:border-violet-400/40 hover:text-violet-300/80",
    },
  };
  const cls = styles[tone];

  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-xs font-semibold transition ${
        active ? cls.active : cls.idle
      }`}
    >
      {label}
      <span className="ml-1.5 font-mono tabular-nums opacity-80">{count}</span>
    </button>
  );
}
