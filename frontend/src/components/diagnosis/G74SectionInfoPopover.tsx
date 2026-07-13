import { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  computeSectionInfoPopoverPos,
  sectionInfoPopoverStyle,
  type SectionInfoPopoverPos,
} from "./sectionInfoPopoverLayout";

const HOVER_LEAVE_MS = 140;

export function G74SectionInfoPopover() {
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
              <p className="font-display text-xs font-semibold text-cyan-100">7-4 취약한 보안설정</p>
              <p className="mt-0.5 text-[10px] leading-relaxed text-white/65">
                웹 보안 설정과 사용 중인 오픈소스 의존성의 알려진 취약점을 함께 점검합니다.
              </p>
            </div>

            <div className="space-y-3 px-3.5 py-3 text-[10px] leading-relaxed text-white/80">
              <section>
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-cyan-300/90">무엇을 찾나요?</p>
                <ul className="list-inside list-disc space-y-0.5 text-white/75">
                  <li><span className="text-white/90">웹 보안 설정</span> — 보안 헤더, TLS, 노출 포트, 서버 버전 설정</li>
                  <li><span className="text-white/90">의존성 취약점</span> — 설치된 라이브러리 버전과 CVE/GitHub Advisory 비교</li>
                </ul>
              </section>

              <section className="rounded-lg border border-cyber-border/30 bg-cyber-bg/40 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-cyan-300/90">테스트 방법</p>
                <ol className="list-inside list-decimal space-y-1 text-white/75">
                  <li>Base URLs에 점검할 API/웹 주소와 역할을 저장합니다.</li>
                  <li><span className="font-semibold text-amber-200">Dependency 파일(deps)을 반드시 업로드합니다.</span></li>
                  <li>Gradle/Maven dependency tree 또는 지원되는 npm/pip 의존성 목록을 사용합니다.</li>
                  <li>Diagnosis에서 7-4를 펼쳐 「진단 시작」 후 설정 결과와 라이브러리별 CVE를 확인합니다.</li>
                </ol>
              </section>

              <section className="rounded-lg border border-amber-400/30 bg-amber-500/10 px-2.5 py-2">
                <p className="mb-1 text-[10px] font-semibold text-amber-200">왜 deps 파일이 필요한가요?</p>
                <p className="text-white/75">
                  HTTP 응답이나 화면만으로는 서버가 사용하는 라이브러리 이름과 정확한 버전을 알 수 없습니다. deps 파일에서 컴포넌트와 설치 버전을 추출해야 취약 버전 범위와 비교해 CVE/SCA 판정을 할 수 있습니다.
                </p>
                <p className="mt-1 text-amber-100/85">
                  미업로드 시 보안 헤더·TLS·포트 검사는 가능하지만 의존성 취약점 검사는 제외되거나 불완전합니다.
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
        aria-label="7-4 진단 안내"
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
