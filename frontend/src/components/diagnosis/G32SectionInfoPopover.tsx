import { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  computeSectionInfoPopoverPos,
  sectionInfoPopoverStyle,
  type SectionInfoPopoverPos,
} from "./sectionInfoPopoverLayout";

const HOVER_LEAVE_MS = 140;

export function G32SectionInfoPopover() {
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
              <p className="font-display text-xs font-semibold text-cyan-100">
                3-2 인증 실패 횟수 제한
              </p>
              <p className="mt-0.5 text-[10px] leading-relaxed text-white/65">
                로그인 실패가 반복될 때 계정 잠금·요청 제한이 걸리는지 자동으로 점검합니다.
              </p>
            </div>

            <div className="space-y-3 px-3.5 py-3 text-[10px] leading-relaxed text-white/80">
              <section>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-300/90">
                  무엇을 찾나요?
                </p>
                <ul className="list-inside list-disc space-y-0.5 text-white/75">
                  <li>
                    <span className="text-white/90">무차별 대입 방어 부재</span> — 비밀번호를 여러 번 틀려도 계정 잠금·차단이 없는지
                  </li>
                  <li>
                    <span className="text-white/90">속도 제한 부재</span> — 짧은 시간 반복 로그인이 제한(429 등)되지 않는지
                  </li>
                </ul>
              </section>

              <section className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">테스트 방법</p>
                <ol className="list-inside list-decimal space-y-1 text-white/75">
                  <li>
                    <span className="text-white/90">Attack Surface</span>에 로그인 URL과 테스트 계정(로그인 정보)을 등록
                  </li>
                  <li>Diagnosis에서 이 항목(3-2)을 펼치고 「진단 시작」</li>
                  <li>
                    엔진이 <span className="text-white/90">틀린 비밀번호로 연속 로그인</span>을 시도하며 잠금·차단(403/423/429·Retry-After·잠금 메시지) 발생 여부를 관측
                  </li>
                  <li>완료 후 아래 결과 표에서 심각도를 확인</li>
                </ol>
              </section>

              <section>
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">결과 읽는 법</p>
                <ul className="space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-rose-400/35 bg-rose-500/10 px-1.5 text-[9px] leading-none text-rose-200">
                      높음
                    </span>
                    <span>여러 번 실패해도 잠금·지연·차단이 전혀 없음 — 무차별 대입(brute-force) 공격 가능. 계정 잠금·요청 제한(rate limit)·CAPTCHA 등 도입 필요</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-amber-400/35 bg-amber-500/10 px-1.5 text-[9px] leading-none text-amber-200">
                      중간
                    </span>
                    <span>차단은 있으나 임계값이 높거나 우회 가능 — 실패 횟수·차단 정책 강화 권장</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-sky-400/35 bg-sky-500/10 px-1.5 text-[9px] leading-none text-sky-200">
                      낮음
                    </span>
                    <span>경미한 이슈 — 참고 수준으로 확인 권장</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-emerald-400/35 bg-emerald-500/10 px-1.5 text-[9px] leading-none text-emerald-200">
                      양호
                    </span>
                    <span>실패가 반복되면 잠금·지연·차단이 정상 작동 — 조치 불필요</span>
                  </li>
                </ul>
                <p className="mt-2 text-[9px] leading-relaxed text-white/50">
                  참고: <code className="text-cyan-300/70">429</code>(요청 과다)·<code className="text-cyan-300/70">423</code>(잠김) 응답이나 잠금 안내 메시지가 나오면 방어가 작동하는 것입니다.
                </p>
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
        aria-label="3-2 진단 안내"
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
