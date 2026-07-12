import { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";

const CARD_WIDTH = 352;
const HOVER_LEAVE_MS = 140;

export function G61SectionInfoPopover() {
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
              <p className="font-display text-xs font-semibold text-cyan-100">6-1 오류페이지를 통한 정보 노출 여부</p>
              <p className="mt-0.5 text-[10px] leading-relaxed text-white/65">
                파라미터·바디·경로·메소드·헤더를 비정상 값으로 바꿔 강제로 에러를 유발한 뒤, 에러 응답에 DB·
                스택트레이스·서버 경로 같은 내부 정보가 노출되는지 점검합니다.
              </p>
            </div>

            <div className="space-y-3 px-3.5 py-3 text-[10px] leading-relaxed text-white/80">
              <section>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-300/90">
                  무엇을 찾나요?
                </p>
                <ul className="list-inside list-disc space-y-0.5 text-white/75">
                  <li>
                    <span className="text-white/90">DBMS 오류 노출</span> — SQL 예외 텍스트, DB 벤더/구문 오류,
                    제약조건 상세
                  </li>
                  <li>
                    <span className="text-white/90">익셉션/스택트레이스 노출</span> — Java/Python/.NET/Node/Rails
                    스택트레이스, 서버 파일 경로(/var/www, C:\ 등)
                  </li>
                  <li>
                    <span className="text-white/90">HTTP/서버 오류 노출</span> — Whitelabel·Tomcat·IIS 기본 에러
                    페이지, JSON systemMessage/trace/stack 필드, 서버 배너
                  </li>
                </ul>
              </section>

              <section className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">테스트 방법</p>
                <ol className="list-inside list-decimal space-y-1 text-white/75">
                  <li>
                    <span className="text-white/90">Attack Surface</span>에 Base URL(API 서버)을 등록
                  </li>
                  <li>
                    <span className="text-white/90">Verify</span>로 API 인벤토리를 생성
                  </li>
                  <li>
                    Diagnosis에서 이 항목(6-1)을 펼치고 「진단 시작」 — 파라미터/바디/경로/메소드/헤더 5개 트리거군을
                    조합해 강제로 오류를 유발합니다
                  </li>
                  <li>완료 후 결과에서 노출 항목(rule_id)과 응답 스니펫을 확인</li>
                </ol>
              </section>

              <section>
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">결과 읽는 법</p>
                <ul className="space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-rose-400/35 bg-rose-500/10 px-1.5 text-[9px] leading-none text-rose-200">
                      높음(실패)
                    </span>
                    <span>
                      SQL 예외, Java/Python 스택트레이스처럼 오탐 여지가 거의 없는 "명확한 시그니처"가 잡힌 경우 —
                      즉시 fail 처리
                    </span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="inline-flex h-4 shrink-0 items-center rounded border border-amber-400/35 bg-amber-500/10 px-1.5 text-[9px] leading-none text-amber-200">
                      참고(수동확인)
                    </span>
                    <span>
                      서버 경로 언급, 장황한 에러 본문 등 일반적인 문자열/키워드 매칭만으로 잡힌 경우 — 자동으로
                      fail 처리하지 않고 warn으로 낮춰 진단자 확인을 요청
                    </span>
                  </li>
                </ul>
                <p className="mt-2 text-[9px] leading-relaxed text-white/50">
                  참고: "확인 필요" 항목만 있고 확정 시그니처가 하나도 없으면 섹션 상태는 fail이 아니라 warn으로
                  표시되고, 결과 메시지에 "진단자 확인 필요" 목록이 함께 붙습니다.
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
        aria-label="6-1 진단 안내"
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
