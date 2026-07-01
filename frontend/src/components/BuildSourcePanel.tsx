import { useRef } from "react";
import { Check, FileJson, Globe, Server, X } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import apiEx1Img from "../assets/API_EX1.png";
import apiEx2Img from "../assets/API_EX2.png";
import urlEx1Img from "../assets/URL_EX1.png";
import urlEx2Img from "../assets/URL_EX2.png";
import type { SourceFiles, SourceId, SourceOption } from "../types";
const SOURCE_LABELS: Record<SourceId, string> = {
  url_list: "URL List",
  api_list: "API List",
  openapi: "Swagger",
};

const SOURCE_ICONS: Record<SourceId, LucideIcon> = {
  url_list: Globe,
  api_list: Server,
  openapi: FileJson,
};

const SOURCE_EXAMPLES: Partial<Record<SourceId, { src: string; caption: string }[]>> = {
  url_list: [
    { src: urlEx1Img, caption: "Path only" },
    { src: urlEx2Img, caption: "With query (optional)" },
  ],
  api_list: [
    { src: apiEx1Img, caption: "Path only" },
    { src: apiEx2Img, caption: "With query (optional)" },
  ],
};
const EXAMPLE_THEME: Partial<
  Record<
    SourceId,
    {
      label: string;
      hint: string;
      border: string;
      header: string;
      glow: string;
      tail: string;
      connector: string;
    }
  >
> = {
  url_list: {
    label: "Example .txt",
    hint: "PATH | param, param (query optional)",
    border: "border-sky-400/45",
    header: "text-sky-300",
    glow: "shadow-[0_12px_48px_rgba(56,189,248,0.18)]",
    tail: "border-sky-400/45 bg-[#0a101c]",
    connector: "from-sky-400/70 to-sky-400/10",
  },
  api_list: {
    label: "Example .txt",
    hint: "METHOD /path | param, param (optional)",
    border: "border-amber-400/45",
    header: "text-amber-300",
    glow: "shadow-[0_12px_48px_rgba(251,191,36,0.16)]",
    tail: "border-amber-400/45 bg-[#0a101c]",
    connector: "from-amber-400/70 to-amber-400/10",
  },
};

const FILE_ACCEPT: Record<SourceId, string> = {
  url_list: ".txt",
  api_list: ".txt",
  openapi: ".json,.yaml,.yml",
};

function ExampleFormatPopover({
  id,
  images,
}: {
  id: SourceId;
  images: { src: string; caption: string }[];
}) {
  const theme = EXAMPLE_THEME[id];
  if (!theme) return null;

  return (
    <div
      className="pointer-events-none absolute top-[calc(100%+4px)] left-1/2 z-[60] w-[min(24rem,calc(100vw-3rem))] -translate-x-1/2 opacity-0 transition-all duration-300 ease-out group-hover:opacity-100 group-hover:translate-y-0.5 translate-y-1 scale-[0.97] group-hover:scale-100"
      aria-hidden
    >
      <div className="flex flex-col items-center">
        <div className={`mb-1 h-3 w-px bg-gradient-to-b ${theme.connector}`} />
        <div
          className={`relative w-full overflow-hidden rounded-xl border bg-[#0a101c]/98 p-3 backdrop-blur-xl ${theme.border} ${theme.glow}`}
        >
          <div
            className={`absolute -top-[5px] left-1/2 h-2.5 w-2.5 -translate-x-1/2 rotate-45 border-t border-l ${theme.tail}`}
          />
          <div className="mb-2 flex items-center justify-between gap-2">
            <p className={`font-display text-[11px] font-semibold uppercase tracking-widest ${theme.header}`}>
              {theme.label}
            </p>
            <span className="text-[10px] text-cyber-muted">{theme.hint}</span>
          </div>
          <div className="space-y-2">
            {images.map((image, index) => (
              <div key={image.src}>
                <p className="mb-1 text-[10px] font-medium uppercase tracking-wide text-cyber-muted/90">
                  {image.caption}
                </p>
                <div className="overflow-hidden rounded-lg border border-cyber-border/80 bg-black/40">
                  <img
                    src={image.src}
                    alt={`${SOURCE_LABELS[id]} format example ${index + 1}`}
                    className="block w-full object-contain object-left-top"
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
interface BuildSourcePanelProps {
  open: boolean;
  sources: SourceOption[];
  files: SourceFiles;
  building: boolean;
  onFileSelect: (id: SourceId, file: File | null) => void;
  onBuild: () => void;
  onClose: () => void;
}

export function BuildSourcePanel({
  open,
  sources,
  files,
  building,
  onFileSelect,
  onBuild,
  onClose,
}: BuildSourcePanelProps) {
  const inputRefs = useRef<Partial<Record<SourceId, HTMLInputElement | null>>>({});
  const readyCount = sources.filter((s) => files[s.id] != null).length;

  const openPicker = (id: SourceId) => {
    inputRefs.current[id]?.click();
  };

  return (
    <div
      className={`grid transition-all duration-500 ease-out ${
        open
          ? "relative z-40 grid-rows-[1fr] opacity-100 mb-6"
          : "grid-rows-[0fr] opacity-0 mb-0"
      }`}
    >
      <div className={`min-h-0 ${open ? "overflow-visible" : "overflow-hidden"}`}>
        <div className="overflow-visible rounded-xl border border-cyber-accent/30 bg-cyber-panel/90 shadow-[0_0_40px_rgba(0,255,200,0.08)] backdrop-blur-md">
          <div className="flex items-center justify-between border-b border-cyber-border px-5 py-3">
            <p className="font-display text-sm font-semibold tracking-wide text-cyber-accent">
              Build Attack Tree
            </p>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg p-1.5 text-cyber-muted transition hover:bg-cyber-border/40 hover:text-white"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="grid gap-3 overflow-visible p-5 pt-8 sm:grid-cols-3">
            {sources.map((source) => {
              const id = source.id;
              const hasFile = files[id] != null;
              const Icon = SOURCE_ICONS[id];
              const exampleImages = SOURCE_EXAMPLES[id];

              return (
                <div key={id} className="group relative">
                  {exampleImages && (
                    <ExampleFormatPopover id={id} images={exampleImages} />
                  )}
                  <input
                    ref={(el) => {
                      inputRefs.current[id] = el;
                    }}
                    type="file"
                    accept={FILE_ACCEPT[id]}
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0] ?? null;
                      onFileSelect(id, file);
                      e.target.value = "";
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => openPicker(id)}
                    className={`relative w-full rounded-lg border p-4 text-left transition-all duration-200 ${
                      hasFile
                        ? "border-cyber-accent/60 bg-cyber-accent/10 shadow-[inset_0_0_20px_rgba(0,255,200,0.06)]"
                        : "border-cyber-border bg-cyber-bg/60 hover:border-cyber-accent/30 hover:bg-cyber-accent/5 group-hover:shadow-[0_0_20px_rgba(0,255,200,0.06)]"
                    } ${exampleImages ? "group-hover:border-cyber-accent/40" : ""}`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div
                        className={`rounded-lg p-2 ${
                          hasFile
                            ? "bg-cyber-accent/20 text-cyber-accent"
                            : "bg-cyber-border/40 text-cyber-muted group-hover:text-cyber-accent"
                        }`}
                      >
                        <Icon className="h-5 w-5" strokeWidth={1.5} />
                      </div>
                      <div
                        className={`flex h-5 w-5 items-center justify-center rounded border transition ${
                          hasFile
                            ? "border-cyber-accent bg-cyber-accent text-cyber-bg"
                            : "border-cyber-border bg-transparent"
                        }`}
                      >
                        {hasFile && <Check className="h-3 w-3" strokeWidth={3} />}
                      </div>
                    </div>
                    <p className="mt-3 truncate text-sm font-semibold text-white">
                      {hasFile ? files[id]!.name : SOURCE_LABELS[id]}
                    </p>
                  </button>
                </div>
              );
            })}
          </div>

          <div className="flex items-center justify-end gap-2 border-t border-cyber-border px-5 py-3">
            <button
              type="button"
              onClick={onBuild}
              disabled={building || readyCount === 0}
              className="rounded-lg border border-cyber-accent/50 bg-cyber-accent/15 px-5 py-2 text-xs font-semibold text-cyber-accent transition hover:bg-cyber-accent/25 disabled:opacity-40"
            >
              {building ? "Merging…" : "Merge & Build"}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-cyber-border px-4 py-2 text-xs text-cyber-muted transition hover:text-white"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
