import { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";

const CARD_WIDTH = 352;
const HOVER_LEAVE_MS = 140;

export function G16SectionInfoPopover() {
  const anchorRef = useRef<HTMLButtonElement>(null);
  const leaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ top: 0, left: 0 });

  const clearLeaveTimer = useCallback(() => {
    if (leaveTimer.current != null) {
      clearTimeout(leaveTimer.current);
      leaveTimer.current = null;
    }
  }, []);

  const updatePosition = useCallback(() => {
    const el = anchorRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const margin = 12;
    let left = rect.left + rect.width / 2 - CARD_WIDTH / 2;
    left = Math.max(margin, Math.min(left, window.innerWidth - CARD_WIDTH - margin));
    setPos({ top: rect.bottom + 8, left });
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
            className="pointer-events-auto fixed z-[300] w-[min(22rem,calc(100vw-1.5rem))] overflow-hidden rounded-xl border border-cyan-400/25 bg-[#0a1219]/98 shadow-[0_12px_40px_rgba(0,0,0,0.55)] backdrop-blur-md"
            style={{ top: pos.top, left: pos.left }}
            onMouseEnter={showCard}
            onMouseLeave={scheduleHide}
            role="tooltip"
          >
            <div className="border-b border-cyan-400/15 bg-gradient-to-r from-cyan-500/10 to-transparent px-3.5 py-2.5">
              <p className="font-display text-xs font-semibold text-cyan-100">1-6 입력 값 크기 및 무결성 검증 오류</p>
              <p className="mt-0.5 text-[10px] leading-relaxed text-white/65">
                KISA/SK쉴더스/CWE/OWASP 페이로드로 크기 초과·타입 불일치 등 비정상 입력을 대량 전송해, 검증 누락으로
                서버 예외가 그대로 노출되는지 점검합니다.
              </p>
            </div>

            <div className="space-y-3 px-3.5 py-3 text-[10px] leading-relaxed text-white/80">
              <section>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-300/90">
                  무엇을 찾나요?
                </p>
                <ul className="list-inside list-disc space-y-0.5 text-white/75">
                  <li>
                    <span className="text-white/90">검증 누락 예외</span> — 타입 불일치/파싱 실패 등 입력 검증이
                    빠졌다는 게 명백한 예외가 그대로 응답에 노출
                  </li>
                  <li>
                    <span className="text-white/90">내부 정보 노출</span> — 5xx 응답에 systemMessage·스택트레이스
                    같은 서버 내부 메시지가 그대로 포함
                  </li>
                </ul>
              </section>

              <section className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">테스트 방법</p>
                <ol className="list-inside list-decimal space-y-1 text-white/75">
                  <li>
                    <span className="text-white/90">Attack Surface</span>에 Base URL(Swagger 포함)과 로그인 정보를
                    등록 (관리자 백엔드는 admin spec 별도 등록 가능)
                  </li>
                  <li>
                    <span className="text-white/90">Verify</span>로 API 인벤토리를 생성
                  </li>
                  <li>
                    Diagnosis에서 이 항목(1-6)을 펼치고 「진단 시작」 — 내부적으로 대량 퍼징 엔진이 별도 프로세스로
                    실행됩니다(수 분~최대 1시간)
                  </li>
                  <li>완료 후 결과에서 대표 취약점 최대 30건의 요청/응답 증거 스크린샷을 확인</li>
                </ol>
              </section>

              <section>
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">결과 읽는 법</p>
                <ul className="space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-rose-400/35 bg-rose-500/10 px-1.5 text-[9px] leading-none text-rose-200">
                      높음
                    </span>
                    <span>검증 누락이 확실한 예외가 5xx로 그대로 노출되고, 별도 재현 증거까지 확보된 건</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-amber-400/35 bg-amber-500/10 px-1.5 text-[9px] leading-none text-amber-200">
                      중간/낮음
                    </span>
                    <span>5xx는 발생했지만 예외 유형이 불명확하거나 근거가 약함 — 사람이 재현 확인 필요</span>
                  </li>
                </ul>
                <p className="mt-2 text-[9px] leading-relaxed text-white/50">
                  참고: Swagger 경로 placeholder 미치환, 탐색성 경로, 413(정상 사이즈 제한 거부) 등은 노이즈로 판단해
                  결과에서 자동 제외됩니다. 5xx를 받았다는 사실만으로 곧바로 높음을 매기지 않고, 엔진의 최종 분류와
                  재현 가능성을 함께 봐야 합니다.
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
        aria-label="1-6 진단 안내"
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
