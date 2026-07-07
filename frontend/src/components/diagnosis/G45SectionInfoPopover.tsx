import { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";

const CARD_WIDTH = 352;
const HOVER_LEAVE_MS = 140;

export function G45SectionInfoPopover() {
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
              <p className="font-display text-xs font-semibold text-cyan-100">4-5 일반 계정 권한 상승가능성</p>
              <p className="mt-0.5 text-[10px] leading-relaxed text-white/65">
                일반 사용자 계정으로 로그인한 상태에서 파라미터 변조 등을 통해 관리자나 타 사용자의 권한을 획득/우회할 수 있는지 점검합니다.
              </p>
            </div>

            <div className="space-y-3 px-3.5 py-3 text-[10px] leading-relaxed text-white/80">
              <section>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-300/90">
                  무엇을 찾나요?
                </p>
                <ul className="list-inside list-disc space-y-0.5 text-white/75">
                  <li>
                    <span className="text-white/90">IDOR(Insecure Direct Object Reference)</span> — 타겟 ID를 변조하여 타인의 정보 열람/수정
                  </li>
                  <li>
                    <span className="text-white/90">권한 우회</span> — 인가되지 않은 일반 계정으로 관리자 전용 기능 호출
                  </li>
                </ul>
              </section>

              <section className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">테스트 방법</p>
                <ol className="list-inside list-decimal space-y-1 text-white/75">
                  <li>
                    <span className="text-white/90">Target URL</span>에 취약점이 의심되는 API 주소를 입력합니다.
                  </li>
                  <li>
                    <span className="text-white/90">Method</span>를 선택하고 필요한 경우 헤더/본문을 구성합니다.
                  </li>
                  <li>Diagnosis에서 이 항목(4-5)을 펼치고 「진단 시작」</li>
                  <li>완료 후 결과에서 발견된 취약점과 인젝션 파라미터를 확인합니다.</li>
                </ol>
              </section>

              <section>
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">결과 읽는 법</p>
                <ul className="space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-rose-400/35 bg-rose-500/10 px-1.5 text-[9px] leading-none text-rose-200">
                      높음
                    </span>
                    <span>타 사용자의 계정 정보 탈취 또는 관리자 기능 접근 성공 — 즉각적인 조치(권한 검증 로직 추가) 필요</span>
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
        aria-label="4-5 진단 안내"
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
