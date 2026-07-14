import { useCallback, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import {
  computeSectionInfoPopoverPos,
  sectionInfoPopoverStyle,
  type SectionInfoPopoverPos,
} from "./sectionInfoPopoverLayout";

const HOVER_LEAVE_MS = 140;

export type SectionInfoBadgeTone = "high" | "medium" | "low" | "note" | "pass";

export type SectionInfoContent = {
  ariaLabel: string;
  title: string;
  blurb: string;
  /** Shown under the title when set (e.g. 수동 진단) */
  modeBadge?: string;
  finds: { label: string; text: ReactNode }[];
  stepsTitle?: string;
  steps: ReactNode[];
  resultTitle?: string;
  results: { tone: SectionInfoBadgeTone; label: string; text: ReactNode }[];
};

const BADGE_CLASS: Record<SectionInfoBadgeTone, string> = {
  high: "border-rose-400/35 bg-rose-500/10 text-rose-200",
  medium: "border-amber-400/35 bg-amber-500/10 text-amber-200",
  low: "border-sky-400/35 bg-sky-500/10 text-sky-200",
  note: "border-amber-400/35 bg-amber-500/10 text-amber-200",
  pass: "border-emerald-400/35 bg-emerald-500/10 text-emerald-200",
};

export function SectionInfoPopoverShell({ content }: { content: SectionInfoContent }) {
  const anchorRef = useRef<HTMLButtonElement>(null);
  const leaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<SectionInfoPopoverPos>({
    top: 0,
    left: 0,
    maxHeight: 360,
    placement: "below",
  });

  const clearLeaveTimer = useCallback(() => {
    if (leaveTimer.current != null) {
      clearTimeout(leaveTimer.current);
      leaveTimer.current = null;
    }
  }, []);

  const updatePosition = useCallback(() => {
    const el = anchorRef.current;
    if (!el) return;
    setPos(computeSectionInfoPopoverPos(el.getBoundingClientRect()));
  }, []);

  const showCard = useCallback(() => {
    clearLeaveTimer();
    updatePosition();
    setOpen(true);
  }, [clearLeaveTimer, updatePosition]);

  const scheduleHide = useCallback(() => {
    clearLeaveTimer();
    leaveTimer.current = setTimeout(() => setOpen(false), HOVER_LEAVE_MS);
  }, [clearLeaveTimer]);

  const toggleCard = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      if (open) {
        setOpen(false);
        return;
      }
      showCard();
    },
    [open, showCard],
  );

  const popover =
    open && typeof document !== "undefined"
      ? createPortal(
          <div
            className="pointer-events-auto fixed z-[300] overflow-y-auto overflow-x-hidden rounded-xl border border-cyan-400/25 bg-[#0a1219]/98 shadow-[0_12px_40px_rgba(0,0,0,0.55)] backdrop-blur-md"
            style={sectionInfoPopoverStyle(pos)}
            onMouseEnter={showCard}
            onMouseLeave={scheduleHide}
            role="tooltip"
          >
            <div className="border-b border-cyan-400/15 bg-gradient-to-r from-cyan-500/10 to-transparent px-3.5 py-2.5">
              <div className="flex flex-wrap items-center gap-1.5">
                <p className="font-display text-xs font-semibold text-cyan-100">{content.title}</p>
                {content.modeBadge ? (
                  <span className="rounded border border-amber-400/35 bg-amber-500/10 px-1.5 py-0.5 text-[9px] font-medium leading-none text-amber-200">
                    {content.modeBadge}
                  </span>
                ) : null}
              </div>
              <p className="mt-0.5 text-[10px] leading-relaxed text-white/65">{content.blurb}</p>
            </div>

            <div className="space-y-3 px-3.5 py-3 text-[10px] leading-relaxed text-white/80">
              <section>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-300/90">
                  무엇을 찾나요?
                </p>
                <ul className="list-inside list-disc space-y-0.5 text-white/75">
                  {content.finds.map((item) => (
                    <li key={item.label}>
                      <span className="text-white/90">{item.label}</span> — {item.text}
                    </li>
                  ))}
                </ul>
              </section>

              <section className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">
                  {content.stepsTitle ?? "테스트 방법"}
                </p>
                <ol className="list-inside list-decimal space-y-1 text-white/75">
                  {content.steps.map((step, index) => (
                    <li key={index}>{step}</li>
                  ))}
                </ol>
              </section>

              <section>
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">
                  {content.resultTitle ?? "결과 읽는 법"}
                </p>
                <ul className="space-y-2">
                  {content.results.map((item) => (
                    <li key={`${item.label}-${item.tone}`} className="flex items-start gap-2">
                      <span
                        className={`inline-flex h-4 shrink-0 items-center rounded border px-1.5 text-[9px] leading-none ${BADGE_CLASS[item.tone]}`}
                      >
                        {item.label}
                      </span>
                      <span>{item.text}</span>
                    </li>
                  ))}
                </ul>
              </section>
            </div>
          </div>,
          document.body,
        )
      : null;

  return (
    <>
      <button
        ref={anchorRef}
        type="button"
        tabIndex={0}
        aria-label={content.ariaLabel}
        aria-expanded={open}
        onMouseEnter={showCard}
        onMouseLeave={scheduleHide}
        onClick={toggleCard}
        className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border border-cyan-400/45 bg-cyan-500/10 text-[11px] font-bold leading-none text-cyan-200/95 transition hover:border-cyan-300/70 hover:bg-cyan-500/20 hover:text-cyan-100"
      >
        !
      </button>
      {popover}
    </>
  );
}
