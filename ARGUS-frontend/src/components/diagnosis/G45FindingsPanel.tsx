import { useState } from "react";
import { ChevronDown, Code } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";

const SEVERITY_STYLES: Record<string, string> = {
  high: "text-rose-300",
  medium: "text-amber-300",
  low: "text-sky-300",
  info: "text-cyber-muted",
};

function G45FindingCard({ f }: { f: any }) {
  const [open, setOpen] = useState(false);
  const ev = f.evidence || {};
  
  return (
    <div className="mb-2 overflow-hidden rounded-lg border border-cyber-border/40 bg-cyber-bg/30">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start gap-3 p-3 text-left transition hover:bg-cyber-accent/5"
      >
        <ChevronDown
          className={`mt-0.5 h-4 w-4 shrink-0 text-cyber-muted transition-transform ${
            open ? "rotate-180" : ""
          }`}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span
              className={`font-mono text-[10px] uppercase font-bold ${
                SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.info
              }`}
            >
              {f.severity}
            </span>
            <span className="text-xs font-medium text-white/95 truncate">
              {f.message}
            </span>
          </div>
          {ev.url && (
            <div className="text-[11px] text-cyan-300/80 font-mono truncate">
              {ev.method || "GET"} {ev.url}
            </div>
          )}
        </div>
      </button>

      {open && (
        <div className="border-t border-cyber-border/30 p-3 space-y-3 bg-cyber-panel/10">
          
          <div className="grid gap-2 text-[11px] sm:grid-cols-2">
            {Object.entries(ev).map(([k, v]) => {
              if (k === "url" || k === "method" || k === "body") return null;
              return (
                <div key={k} className="flex flex-col">
                  <span className="text-cyber-muted capitalize">{k.replace(/_/g, " ")}:</span>
                  <span className="font-mono text-white/80 break-all">{String(v)}</span>
                </div>
              );
            })}
          </div>
          
          {ev.body && (
             <div>
               <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-cyber-muted">
                 <Code className="h-3 w-3" /> Injected Body (Payload)
               </div>
               <pre className="max-h-32 overflow-auto rounded border border-cyber-border/30 bg-[#0f111a] p-2 font-mono text-[10px] text-cyan-200/80">
                 {typeof ev.body === "object" ? JSON.stringify(ev.body, null, 2) : String(ev.body)}
               </pre>
             </div>
          )}
        </div>
      )}
    </div>
  );
}

export function G45FindingsPanel({
  findings,
}: {
  findings: { severity: string; message: string; evidence?: Record<string, unknown> }[];
}) {
  const vulnFindings = findings.filter((f) => f.severity !== "info");
  const infoFindings = findings.filter((f) => f.severity === "info");

  if (findings.length === 0) {
    return <div className="text-xs text-cyber-muted">No findings reported.</div>;
  }

  return (
    <div className="space-y-4">
      {vulnFindings.length > 0 && (
        <CollapsibleReportSection
          title="Privilege Escalation Vulnerabilities"
          subtitle={`(${vulnFindings.length})`}
          defaultOpen={true}
        >
          {vulnFindings.map((f, i) => (
            <G45FindingCard key={`vuln-${i}`} f={f} />
          ))}
        </CollapsibleReportSection>
      )}

      {infoFindings.length > 0 && (
        <CollapsibleReportSection
          title="Information / Debug Logs"
          subtitle={`(${infoFindings.length})`}
          defaultOpen={vulnFindings.length === 0}
        >
          {infoFindings.map((f, i) => (
            <G45FindingCard key={`info-${i}`} f={f} />
          ))}
        </CollapsibleReportSection>
      )}
    </div>
  );
}
