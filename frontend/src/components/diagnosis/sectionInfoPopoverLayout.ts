/** Shared viewport-aware placement for Diagnosis "!" info popovers. */

import type { CSSProperties } from "react";

export const SECTION_INFO_CARD_WIDTH = 352;

export type SectionInfoPopoverPos = {
  left: number;
  maxHeight: number;
  placement: "below" | "above";
  /** Used when placement is below — card top sticks under the icon. */
  top?: number;
  /** Used when placement is above — card bottom sticks above the icon. */
  bottom?: number;
};

export function computeSectionInfoPopoverPos(
  anchor: DOMRect,
  opts?: { cardWidth?: number; gap?: number; margin?: number; minHeight?: number },
): SectionInfoPopoverPos {
  const cardWidth = opts?.cardWidth ?? SECTION_INFO_CARD_WIDTH;
  const gap = opts?.gap ?? 8;
  const margin = opts?.margin ?? 12;
  const minHeight = opts?.minHeight ?? 140;

  let left = anchor.left + anchor.width / 2 - cardWidth / 2;
  left = Math.max(margin, Math.min(left, window.innerWidth - cardWidth - margin));

  const spaceBelow = window.innerHeight - anchor.bottom - gap - margin;
  const spaceAbove = anchor.top - gap - margin;
  // Prefer the side with more room, but only flip up when below is tight.
  const preferAbove = spaceBelow < 220 && spaceAbove > spaceBelow;

  if (preferAbove) {
    const maxHeight = Math.max(minHeight, Math.min(spaceAbove, window.innerHeight - margin * 2));
    // CSS `bottom`: distance from viewport bottom → keeps card flush above the icon.
    const bottom = Math.max(margin, window.innerHeight - anchor.top + gap);
    return { left, maxHeight, placement: "above", bottom };
  }

  const maxHeight = Math.max(minHeight, Math.min(spaceBelow, window.innerHeight - margin * 2));
  return { left, maxHeight, placement: "below", top: anchor.bottom + gap };
}

export function sectionInfoPopoverStyle(pos: SectionInfoPopoverPos): CSSProperties {
  return {
    left: pos.left,
    width: `min(${SECTION_INFO_CARD_WIDTH}px, calc(100vw - 1.5rem))`,
    maxHeight: pos.maxHeight,
    ...(pos.placement === "above"
      ? { top: "auto", bottom: pos.bottom }
      : { top: pos.top, bottom: "auto" }),
  };
}
