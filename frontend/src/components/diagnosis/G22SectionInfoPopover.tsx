import { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";

const CARD_WIDTH = 352;
const HOVER_LEAVE_MS = 140;

export function G22SectionInfoPopover() {
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
              <p className="font-display text-xs font-semibold text-cyan-100">2-2 중요 정보 파일 다운로드</p>
              <p className="mt-0.5 text-[10px] leading-relaxed text-white/65">
                파일·리포트 다운로드 API가 안전한지 자동으로 점검합니다.
              </p>
            </div>

            <div className="space-y-3 px-3.5 py-3 text-[10px] leading-relaxed text-white/80">
              <section>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-300/90">
                  무엇을 찾나요?
                </p>
                <ul className="list-inside list-disc space-y-0.5 text-white/75">
                  <li>
                    <span className="text-white/90">경로 조작</span> —{" "}
                    <code className="text-cyan-300/85">../</code> 등으로 서버 파일을 읽어올 수 있는지
                  </li>
                  <li>
                    <span className="text-white/90">비로그인 다운로드</span> — 로그인 없이 파일이 내려오는지
                  </li>
                </ul>
              </section>

              <section className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">테스트 방법</p>
                <ol className="list-inside list-decimal space-y-1 text-white/75">
                  <li>
                    <span className="text-white/90">Attack Surface</span> → Download Endpoints에 실제 다운로드 URL을
                    등록
                  </li>
                  <li>Diagnosis에서 이 항목(2-2)을 펼치고 「진단 시작」</li>
                  <li>
                    <span className="text-white/90">등록된 엔드포인트 진단</span> 선택 (등록한 URL만 빠르게 점검)
                  </li>
                  <li>완료 후 아래 결과 표에서 유형·API·심각도를 확인</li>
                </ol>
              </section>

              <section>
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">결과 읽는 법</p>
                <ul className="space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-rose-400/35 bg-rose-500/10 px-1.5 text-[9px] leading-none text-rose-200">
                      높음
                    </span>
                    <span>파일 내용 노출 또는 로그인 없이 다운로드 — 우선 조치</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-amber-400/35 bg-amber-500/10 px-1.5 text-[9px] leading-none text-amber-200">
                      중간
                    </span>
                    <span>
                      악성 경로 문자열을 거부하지 않음 — 입력값 검증 보완 권장.
                      {" "}
                      <code className="text-cyan-300/80">../</code>
                      는 상위 폴더로 이동하는 경로 표기이며, 정상 API는 이를 차단하거나 무시해야 합니다.
                    </span>
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
        aria-label="2-2 진단 안내"
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
