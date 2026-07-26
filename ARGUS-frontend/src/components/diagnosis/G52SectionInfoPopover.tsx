import { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  computeSectionInfoPopoverPos,
  sectionInfoPopoverStyle,
  type SectionInfoPopoverPos,
} from "./sectionInfoPopoverLayout";

const HOVER_LEAVE_MS = 140;

export function G52SectionInfoPopover() {
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
                5-2 요청 및 응답 값 내 주요정보 포함여부 확인
              </p>
              <p className="mt-0.5 text-[10px] leading-relaxed text-white/65">
                API 요청·응답에 개인정보가 마스킹 없이 노출되는지 자동으로 점검합니다.
              </p>
            </div>

            <div className="space-y-3 px-3.5 py-3 text-[10px] leading-relaxed text-white/80">
              <section>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-300/90">
                  무엇을 찾나요?
                </p>
                <ul className="list-inside list-disc space-y-0.5 text-white/75">
                  <li>
                    <span className="text-white/90">평문 개인정보</span> — 이메일·전화번호·주민등록번호·카드·계좌·이름이 마스킹 없이 오가는지
                  </li>
                  <li>
                    <span className="text-white/90">평문 전송</span> — 개인정보가 HTTPS 없이 HTTP로 전송되는지
                  </li>
                </ul>
              </section>

              <section className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">테스트 방법</p>
                <ol className="list-inside list-decimal space-y-1 text-white/75">
                  <li>
                    <span className="text-white/90">Attack Surface</span>에 Base URL과 로그인 정보(테스트 계정)를 등록
                  </li>
                  <li>
                    <span className="text-white/90">Verify</span>로 API 인벤토리를 생성
                  </li>
                  <li>Diagnosis에서 이 항목(5-2)을 펼치고 「진단 시작」</li>
                  <li>완료 후 아래 결과 표에서 노출된 값·필드·심각도를 확인</li>
                </ol>
              </section>

              <section>
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">결과 읽는 법</p>
                <ul className="space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-rose-400/35 bg-rose-500/10 px-1.5 text-[9px] leading-none text-rose-200">
                      높음
                    </span>
                    <span>이메일·전화번호·주민등록번호·카드·계좌번호가 평문 노출 — 우선 조치(마스킹·암호화)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-amber-400/35 bg-amber-500/10 px-1.5 text-[9px] leading-none text-amber-200">
                      중간
                    </span>
                    <span>이름·은행명 등이 평문 노출, 또는 경로·구조 노출 — 마스킹·검토 권장</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-sky-400/35 bg-sky-500/10 px-1.5 text-[9px] leading-none text-sky-200">
                      낮음
                    </span>
                    <span>경미한 노출·참고 항목 — 참고 수준으로 확인 권장</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-emerald-400/35 bg-emerald-500/10 px-1.5 text-[9px] leading-none text-emerald-200">
                      양호
                    </span>
                    <span>요청·응답에 마스킹 없이 노출된 개인정보 없음 — 조치 불필요</span>
                  </li>
                </ul>
                <p className="mt-2 text-[9px] leading-relaxed text-white/50">
                  참고: <code className="text-cyan-300/70">argus-probe@example.com</code> 같은 값은 점검 도구가 넣은
                  테스트 값이라 노출로 보지 않습니다.
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
        aria-label="5-2 진단 안내"
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
