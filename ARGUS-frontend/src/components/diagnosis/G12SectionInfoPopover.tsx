import { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  computeSectionInfoPopoverPos,
  sectionInfoPopoverStyle,
  type SectionInfoPopoverPos,
} from "./sectionInfoPopoverLayout";

const HOVER_LEAVE_MS = 140;

export function G12SectionInfoPopover() {
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
    (event: React.MouseEvent) => {
      event.stopPropagation();
      if (open) setOpen(false);
      else showCard();
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
              <p className="font-display text-xs font-semibold text-cyan-100">1-2 삽입(Injection) 공격 가능성</p>
              <p className="mt-0.5 text-[10px] leading-relaxed text-white/65">
                API 입력값에 공격 문자열을 주입해 데이터베이스 명령 등이 의도하지 않게 실행되는지 점검합니다.
              </p>
            </div>

            <div className="space-y-3 px-3.5 py-3 text-[10px] leading-relaxed text-white/80">
              <section>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-300/90">무엇을 찾나요?</p>
                <ul className="list-inside list-disc space-y-0.5 text-white/75">
                  <li><span className="text-white/90">SQL Injection</span> — 오류·Boolean·시간 지연 반응을 이용한 삽입 취약점</li>
                  <li><span className="text-white/90">검증된 재현 신호</span> — 정상 요청과 공격 요청의 응답 차이 및 ZAP 교차 검증</li>
                </ul>
              </section>

              <section className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">테스트 방법</p>
                <ol className="list-inside list-decimal space-y-1 text-white/75">
                  <li>Base URLs에 실제 <span className="text-white/90">API 주소</span>를 API 역할로 저장합니다.</li>
                  <li>API List 또는 Swagger를 업로드해 메서드·경로·요청 파라미터를 수집합니다.</li>
                  <li>인증 API는 로그인 엔드포인트와 테스트 계정을 등록하고 Verify를 완료합니다.</li>
                  <li>Diagnosis에서 1-2를 펼쳐 「진단 시작」 후 결과의 파라미터·payload·검증 상태를 확인합니다.</li>
                </ol>
              </section>

              <section>
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">주의사항</p>
                <ul className="space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-amber-400/35 bg-amber-500/10 px-1.5 text-[9px] leading-none text-amber-200">주의</span>
                    <span>실제 공격 payload를 전송하므로 운영환경보다 격리된 테스트환경에서 실행하는 것을 권장합니다.</span>
                  </li>
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
        aria-label="1-2 진단 안내"
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
