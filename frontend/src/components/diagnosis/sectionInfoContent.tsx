import type { ReactNode } from "react";
import type { SectionInfoContent } from "./SectionInfoPopoverShell";

function strong(text: string): ReactNode {
  return <span className="text-white/90">{text}</span>;
}

function code(text: string): ReactNode {
  return <code className="text-cyan-300/85">{text}</code>;
}

/** Sections that previously had no G22-style "!" popover. */
export const SECTION_INFO_CONTENT: Record<string, SectionInfoContent> = {
  "1-1": {
    ariaLabel: "1-1 진단 안내",
    title: "1-1 XSS / CSRF 공격 가능성",
    blurb: "입력에 스크립트를 넣거나 교차 사이트 요청을 위조해 세션·권한이 도용되는지 자동으로 점검합니다.",
    finds: [
      { label: "XSS", text: "반사형·저장형 스크립트 삽입으로 브라우저에서 악성 코드가 실행되는지" },
      { label: "CSRF", text: "Origin/Referer·토큰·SameSite 보호 부족으로 로그인 사용자 요청을 위조할 수 있는지" },
      { label: "CORS 위험", text: "Origin 반사·자격 증명 허용 등 불안전한 교차 출처 설정" },
    ],
    steps: [
      <>Attack Surface에 Base URL·테스트 계정을 등록하고 Verify로 api-tree를 준비합니다.</>,
      <>Diagnosis에서 1-1을 펼치고 「진단 시작」을 실행합니다.</>,
      <>엔진이 파라미터 퍼징·CSRF/CORS 신호를 수집합니다.</>,
      <>결과 카드에서 취약 유형·증거 스크린샷·조치 가이드를 확인합니다.</>,
    ],
    results: [
      { tone: "high", label: "높음", text: "확정 XSS 실행 또는 CSRF/CORS로 인증 세션 도용이 가능한 경우" },
      {
        tone: "note",
        label: "주의",
        text: "실제 페이로드를 전송하므로 격리된 테스트 환경을 권장합니다.",
      },
    ],
  },
  "1-3": {
    ariaLabel: "1-3 진단 안내",
    title: "1-3 파라미터 값 및 히든(Hidden) 필드 조작 가능성",
    blurb: "화면에서 안 보이거나 고정된 금액·역할·ID·상태 값을 API로 바꿔도 서버가 그대로 반영하는지 수동으로 확인합니다.",
    modeBadge: "수동 진단",
    finds: [
      { label: "히든·비즈니스 값 조작", text: "할인·금액·memberId·role·status 등이 서버에 반영되는지" },
      { label: "권한·소유자 우회", text: "ID/role 변경으로 타인 데이터·상위 권한이 되는지" },
    ],
    stepsTitle: "수동 진단 방법",
    steps: [
      <>Attack Surface에서 Verify로 api-tree를 만들고, 주문·결제·프로필 수정 등 {strong("비즈니스 API")}를 고릅니다.</>,
      <>브라우저에서 정상 요청 1회 수행 후 DevTools Network(또는 Burp)에서 요청 body/query를 복사합니다.</>,
      <>
        숨은 필드·고정 값을 바꿔 재전송합니다. 예: 금액 {code("10000→0")}, {code("role=user→admin")}, 타인{" "}
        {code("userId")}.
      </>,
      <>
        응답 JSON·화면 결과가 바뀌면 취약. 요청/응답 캡처와 조작 전후를 기록합니다. (자동 「진단 시작」 없음)
      </>,
    ],
    results: [
      { tone: "high", label: "높음", text: "조작값이 응답·비즈니스 결과에 반영(0원, 타인 ID, role 상승 등)" },
      {
        tone: "note",
        label: "참고",
        text: <>경로 조작은 {strong("2-2")}, SQL은 {strong("1-2")}, 쿠키/토큰은 {strong("4-1·4-2")}와 구분합니다.</>,
      },
    ],
  },
  "1-4": {
    ariaLabel: "1-4 진단 안내",
    title: "1-4 SSRF / File Inclusion 공격 가능성",
    blurb: "URL·파일 경로형 파라미터로 내부망·로컬 파일에 접근할 수 있는지 SSRF·LFI/RFI 관점으로 수동 점검합니다.",
    modeBadge: "수동 진단",
    finds: [
      { label: "SSRF", text: "서버가 임의 URL을 가져와 내부 IP·메타데이터에 닿는지" },
      { label: "File Inclusion", text: "경로 주입으로 서버 로컬/원격 파일을 읽는지" },
    ],
    stepsTitle: "수동 진단 방법",
    steps: [
      <>api-tree·Swagger에서 {code("url")}·{code("callback")}·{code("file")}·{code("path")}·{code("template")} 파라미터가 있는 API를 골라 목록을 만듭니다.</>,
      <>
        허가된 테스트 환경에서만 시도합니다. SSRF 예: {code("http://127.0.0.1")}·{code("http://169.254.169.254")} /
        LFI 예: {code("../../../etc/passwd")}·{code("file:///...")}.
      </>,
      <>응답 본문·상태코드·지연 시간을 baseline(정상 URL)과 비교합니다. 내부 에러·파일 내용·비정상 지연이 있으면 기록합니다.</>,
      <>재현 요청·응답 캡처를 남깁니다. Diagnosis 「진단 시작」은 없습니다.</>,
    ],
    resultTitle: "주의사항",
    results: [
      { tone: "note", label: "주의", text: "실제 내부망 요청이 나가므로 허가·격리 환경에서만 수행합니다." },
      {
        tone: "note",
        label: "참고",
        text: <>다운로드 path traversal은 {strong("2-2")}, 업로드는 {strong("2-1")}과 구분합니다.</>,
      },
    ],
  },
  "1-5": {
    ariaLabel: "1-5 진단 안내",
    title: "1-5 검증되지 않은 리다이렉트와 포워드",
    blurb: "리다이렉트 파라미터·CORS 설정으로 사용자를 외부 사이트로 보낼 수 있는지 자동 점검합니다.",
    finds: [
      { label: "Open Redirect", text: "Location/meta/JS location에 외부 URL이 반영되는지" },
      { label: "CORS", text: "Origin * 또는 reflect + credentials 등 과도한 교차 출처 허용" },
    ],
    steps: [
      <>Attack Surface Base URL·계정 등록 후 Verify로 inventory를 준비합니다.</>,
      <>Diagnosis 1-5 「진단 시작」→ probeMode·CORS/(선택) ZAP 옵션을 고릅니다.</>,
      <>필요 시 Redirect sink URL을 지정하고 실행합니다.</>,
      <>결과에서 외부 리다이렉트·CORS 카테고리와 심각도를 확인합니다.</>,
    ],
    results: [
      { tone: "high", label: "높음", text: "확정 open redirect 또는 credentials 포함 CORS 위험 설정" },
      {
        tone: "note",
        label: "참고",
        text: "값만 반사되고 리다이렉트 증거가 없으면 확정 취약점이 아닐 수 있습니다.",
      },
    ],
  },
  "2-1": {
    ariaLabel: "2-1 진단 안내",
    title: "2-1 악성코드파일 업로드",
    blurb: "업로드 API가 위험 확장자를 차단하는지, 응답에 서버 내부 경로·주소가 노출되는지 자동 점검합니다.",
    finds: [
      {
        label: "확장자 우회",
        text: "php/jsp/asp 등 위험 확장자·이중확장자·Content-Type 위장이 통과하는지",
      },
      { label: "경로·주소 노출", text: "응답에 절대경로·내부 IP·스택트레이스가 나오는지" },
    ],
    steps: [
      <>Attack Surface에 계정·Base URL을 두고 Verify합니다(또는 Upload Endpoints 등록).</>,
      <>Diagnosis 2-1 「진단 시작」→ httpx/ZAP·인증 패스·대상 수를 설정합니다.</>,
      <>정상 이미지 baseline과 위험 확장자 매트릭스를 업로드합니다.</>,
      <>결과에서 차단 실패·경로 노출 findings를 확인합니다.</>,
    ],
    results: [
      { tone: "high", label: "높음", text: "위험 확장자가 2xx로 수용되어 차단되지 않음" },
      {
        tone: "note",
        label: "주의",
        text: <>서버 실행 여부는 HTTP만으로 확정 불가. Path traversal 다운로드는 {strong("2-2")}.</>,
      },
    ],
  },
  "3-1": {
    ariaLabel: "3-1 진단 안내",
    title: "3-1 패스워드 정책 유무 및 반영 여부",
    blurb: "회원가입·비밀번호 변경에 길이·복잡도 정책이 실제로 적용되는지 수동 확인합니다.",
    modeBadge: "수동 진단",
    finds: [
      { label: "정책 부재", text: "짧은·단순 비밀번호도 가입·변경이 되는지" },
      { label: "클라이언트만 검증", text: "UI만 막고 API로는 약한 비밀번호가 통과하는지" },
    ],
    stepsTitle: "수동 진단 방법",
    steps: [
      <>대상의 회원가입·비밀번호 변경·재설정 화면을 엽니다. (테스트 계정만 사용)</>,
      <>
        UI에서 약한 비밀번호를 시도합니다. 예: {code("1234")}, {code("aaaa")}, 계정명과 동일, 너무 짧은 값.
      </>,
      <>
        DevTools/Burp로 같은 요청을 API에 직접 보내 UI 검증을 우회합니다. 서버가 400/422로 거절하는지 확인합니다.
      </>,
      <>정책 문구 표시 여부·UI/API 결과 차이를 기록합니다. Diagnosis 「진단 시작」 없음.</>,
    ],
    resultTitle: "판정 기준",
    results: [
      { tone: "high", label: "취약", text: "UI·API 모두 약한 비밀번호를 수용 — 서버측 정책 미적용" },
      {
        tone: "note",
        label: "주의",
        text: "테스트 후 약한 비밀번호를 남기지 말고 즉시 변경·삭제합니다.",
      },
    ],
  },
  "3-3": {
    ariaLabel: "3-3 진단 안내",
    title: "3-3 계정 정보 파악 가능성",
    blurb: "로그인·가입·찾기 응답이 ‘있는 계정’과 ‘없는 계정’을 구분하는지 수동으로 확인합니다.",
    modeBadge: "수동 진단",
    finds: [
      { label: "계정 열거", text: "메시지·상태코드·응답시간이 존재/부재 계정을 다르게 알려주는지" },
      { label: "아이디/이메일 힌트", text: "중복 검사·찾기에서 등록 여부를 과도하게 노출하는지" },
    ],
    stepsTitle: "수동 진단 방법",
    steps: [
      <>로그인·회원가입·아이디/비밀번호 찾기 API(또는 화면)를 준비합니다.</>,
      <>
        A: 존재하는 테스트 계정 + 틀린 비밀번호 / B: 존재하지 않는 아이디·이메일로 동일 조건 요청을 보냅니다.
      </>,
      <>status·JSON message/code·본문 길이·응답 시간을 표로 비교합니다. (예: “비밀번호 오류” vs “계정 없음”)</>,
      <>
        구분이 되면 열거 위험으로 기록. 자동 보완은 {strong("6-2")}(로그인 실패 응답 통일성). 「진단 시작」 없음.
      </>,
    ],
    resultTitle: "판정 기준",
    results: [
      { tone: "medium", label: "취약", text: "존재/부재 계정의 메시지·코드·지연이 달라 계정 존재 여부를 알 수 있음" },
      { tone: "pass", label: "양호", text: "실패 응답이 동일해 존재 여부를 구분할 수 없음" },
    ],
  },
  "3-4": {
    ariaLabel: "3-4 진단 안내",
    title: "3-4 관리자 페이지 분리 여부",
    blurb: "user·admin 로그인·UI·API가 같은 서버/URL을 쓰는지 inventory·login matrix로 점검합니다.",
    finds: [
      { label: "로그인 미분리", text: "user·admin이 동일 로그인 URL 또는 동일 host:port를 공유" },
      { label: "Admin 동일 origin", text: "관리자 화면·API가 사용자 base와 같음" },
      { label: "추측 가능 경로", text: <>{code("/admin")} 등 예측 쉬운 경로 패턴</> },
    ],
    steps: [
      <>Attack Surface에 user/admin Base·로그인 URL을 구분 등록하고 Verify를 완료합니다.</>,
      <>Diagnosis 3-4 「진단 시작」→ Login matrix / +api-tree 범위를 선택합니다.</>,
      <>정적 분석 결과를 기다립니다.</>,
      <>결과에서 동일 로그인·동일 서버·guessable path를 확인합니다.</>,
    ],
    results: [
      { tone: "medium", label: "이슈", text: "동일 로그인/호스트/origin — 관리자 진입면 분리 미흡" },
      { tone: "pass", label: "긍정", text: "admin 전용 서브도메인 분리는 양호 신호" },
    ],
  },
  "3-5": {
    ariaLabel: "3-5 진단 안내",
    title: "3-5 검색엔진 정보 노출 가능성",
    blurb: "robots.txt·noindex/nofollow 상태를 인벤토리로 수집해 검색엔진 노출 여부를 검토합니다.",
    finds: [
      { label: "robots.txt", text: "프론트 Base의 Disallow/Allow/Sitemap 유무·접근성" },
      { label: "색인 제어", text: "페이지에 noindex/nofollow 메타·헤더가 없는지" },
    ],
    steps: [
      <>Attack Surface에 frontend Base와 API Base를 등록하고 Verify합니다.</>,
      <>Diagnosis 3-5 「진단 시작」→ probeMode를 선택합니다.</>,
      <>anonymous·authenticated 패스로 robots·페이지를 probe합니다.</>,
      <>결과에서 robots 부재·noindex 없음 등 검토 필요 행을 확인합니다.</>,
    ],
    resultTitle: "주의사항",
    results: [
      {
        tone: "note",
        label: "참고",
        text: "SPA는 초기 HTML만 보며 JS 렌더 meta는 놓칠 수 있습니다. 누락만으로 자동 fail하지 않습니다.",
      },
    ],
  },
  "3-6": {
    ariaLabel: "3-6 진단 안내",
    title: "3-6 백업 파일 및 테스트 파일 존재 여부",
    blurb: "공개 Base에 backup·.env·phpinfo 등 백업·테스트·디버그 파일이 노출되는지 wordlist로 점검합니다.",
    finds: [
      { label: "백업·시크릿", text: "아카이브·SQL·.env·설정 백업이 anonymous로 내려오는지" },
      { label: "테스트·디버그", text: "phpinfo·test·debug 아티팩트 노출" },
    ],
    steps: [
      <>Base URL을 Attack Surface에 등록합니다.</>,
      <>Diagnosis 3-6 「진단 시작」→ wordlist / +api-tree 범위를 선택합니다.</>,
      <>anonymous 후 authenticated로 동일 URL을 GET합니다.</>,
      <>결과에서 파일 유형·auth 모드·심각도를 확인합니다.</>,
    ],
    results: [
      { tone: "high", label: "높음", text: "비밀·덤프·백업이 비로그인으로 접근 가능하면 우선 조치" },
      {
        tone: "note",
        label: "경계",
        text: <>디렉터리 listing은 {strong("7-2")}, 파라미터 traversal은 {strong("2-2")}.</>,
      },
    ],
  },
  "4-1": {
    ariaLabel: "4-1 진단 안내",
    title: "4-1 쿠키 및 웹 스토리지 조작 가능성",
    blurb: "쿠키 플래그와 세션 쿠키·스토리지 변조로 타 계정·관리자 API에 접근되는지 수동 점검합니다.",
    modeBadge: "수동 진단",
    finds: [
      { label: "쿠키 플래그", text: "HttpOnly·Secure·SameSite 누락" },
      { label: "교차 쿠키", text: "다른 계정 쿠키로 소유자·관리자 데이터가 노출되는지" },
      { label: "변조", text: "빈값·쓰레기·JWT mutate 후에도 인증이 유지되는지" },
    ],
    stepsTitle: "수동 진단 방법",
    steps: [
      <>테스트 계정 2개 이상 준비. 로그인 후 DevTools → Application → Cookies / Local Storage를 엽니다.</>,
      <>Set-Cookie에 {code("HttpOnly")}·{code("Secure")}·{code("SameSite")}가 있는지 확인합니다.</>,
      <>
        계정 A 쿠키/토큰을 계정 B 브라우저에 붙여 넣고 민감 API·마이페이지를 재호출합니다. (교차 세션)
      </>,
      <>
        쿠키·localStorage 값을 비우거나 변조한 뒤 API가 여전히 200인지 확인. 캡처 기록. 「진단 시작」 없음.
      </>,
    ],
    resultTitle: "판정 기준",
    results: [
      { tone: "high", label: "높음", text: "타 계정 쿠키로 관리자/타인 데이터 접근, 또는 변조 후에도 인증 유지" },
      {
        tone: "note",
        label: "경계",
        text: <>JWT 수명·로그아웃은 {strong("4-2")}, 권한 상승 API는 {strong("4-5")}와 구분합니다.</>,
      },
    ],
  },
  "4-2": {
    ariaLabel: "4-2 진단 안내",
    title: "4-2 인증(세션 및 토큰) 값 안전성 설정 여부",
    blurb: "JWT/세션 토큰의 수명·재발급·중복 로그인·로그아웃 무효화를 수동으로 확인합니다.",
    modeBadge: "수동 진단",
    finds: [
      { label: "JWT·토큰", text: "exp 없음·수명 과다·약한 alg·낮은 엔트로피" },
      { label: "세션·재로그인", text: "재로그인 동일 토큰, 중복 세션 후에도 유효" },
      { label: "로그아웃", text: "logout 후에도 access/refresh가 유효한지" },
    ],
    stepsTitle: "수동 진단 방법",
    steps: [
      <>로그인 후 access/refresh·세션 쿠키 값을 복사합니다. JWT면 jwt.io 등으로 {code("exp")}·{code("alg")}를 확인합니다.</>,
      <>같은 계정으로 다시 로그인해 토큰이 바뀌는지, 두 브라우저 동시 로그인이 모두 유효한지 확인합니다.</>,
      <>로그아웃(또는 토큰 폐기 API) 후, 복사해 둔 예전 토큰으로 /me·보호 API를 다시 호출합니다.</>,
      <>만료·재사용·로그아웃 결과를 기록합니다. Diagnosis 「진단 시작」 없음.</>,
    ],
    results: [
      { tone: "high", label: "높음", text: "로그아웃 후에도 토큰 유효, 또는 만료 없는/예측 가능한 토큰" },
      { tone: "note", label: "참고", text: "쿠키 플래그·교차 세션은 4-1에서 따로 봅니다." },
    ],
  },
  "4-3": {
    ariaLabel: "4-3 진단 안내",
    title: "4-3 접근제어 우회 가능성 확인",
    blurb: "인증은 있으나 인가가 느슨해 URL·메서드·헤더 조작으로 권한 밖 기능에 접근하는지 수동 확인합니다.",
    modeBadge: "수동 진단",
    finds: [
      { label: "인가 우회", text: "일반 계정으로 admin/seller 전용 API·화면이 열리는지" },
      { label: "강제 브라우징", text: "숨긴 경로·HTTP 메서드 변경으로 보호 기능 우회" },
      { label: "헤더 스푸핑", text: "X-User-Id·역할 헤더만 바꿔 권한이 바뀌는지" },
    ],
    stepsTitle: "수동 진단 방법",
    steps: [
      <>일반·관리자(또는 seller) 계정을 준비하고, Verify inventory에서 관리자/보호 API 목록을 만듭니다.</>,
      <>일반 계정으로 로그인한 뒤 관리자 URL·API를 직접 호출합니다. (브라우저 주소창 / Burp)</>,
      <>
        GET↔POST·메서드 변경, {code("X-Role")}·{code("X-User-Id")} 등 헤더 조작을 시도합니다.
      </>,
      <>
        200·데이터 노출이면 인가 우회. {strong("4-4")}(비로그인)·{strong("4-5")}(IDOR)와 겹치면 교차 기록. 「진단 시작」 없음.
      </>,
    ],
    resultTitle: "판정 기준",
    results: [
      { tone: "high", label: "높음", text: "일반 계정으로 관리 기능·타인 보호 API가 성공" },
      {
        tone: "note",
        label: "경계",
        text: <>비로그인 접근은 {strong("4-4")}, 객체 ID 교차는 {strong("4-5")} 우선.</>,
      },
    ],
  },
  "5-1": {
    ariaLabel: "5-1 진단 안내",
    title: "5-1 소스코드 내 주요정보 노출 여부",
    blurb: "프론트 번들·맵 파일·주석에 API 키·비밀번호·내부 URL 등 비밀이 박혀 있는지 수동 점검합니다.",
    modeBadge: "수동 진단",
    finds: [
      { label: "하드코딩 시크릿", text: "JS/HTML/설정에 API key·token·DB 비밀번호" },
      { label: "소스맵·주석", text: ".map·주석에 내부 엔드포인트·계정 힌트" },
    ],
    stepsTitle: "수동 진단 방법",
    steps: [
      <>배포 사이트에서 JS 번들 URL을 수집합니다. (Network 탭 → .js) 가능하면 {code(".map")}도 함께합니다.</>,
      <>
        에디터/검색으로 {code("apiKey")}·{code("secret")}·{code("password")}·{code("Bearer")}·{code("AKIA")} 등을 검색합니다.
      </>,
      <>HTML 주석·공개 Git·모바일 설정 파일도 같은 키워드로 확인합니다.</>,
      <>
        발견 시 키 종류·위치를 기록하고 폐기·교체. {strong("5-2")}는 요청/응답 개인정보 — 코드에 심긴 비밀만 5-1. 「진단 시작」 없음.
      </>,
    ],
    resultTitle: "주의사항",
    results: [
      {
        tone: "note",
        label: "주의",
        text: "발견된 키는 즉시 폐기·교체하고 저장소 히스토리까지 점검합니다.",
      },
    ],
  },
  "6-2": {
    ariaLabel: "6-2 진단 안내",
    title: "6-2 일괄적인 오류 처리 페이지 존재 여부",
    blurb: "로그인 실패 응답이 동일한지 비교해 계정 존재 여부 노출(열거)을 자동 점검합니다.",
    finds: [
      {
        label: "응답 불일치",
        text: "존재 계정+틀린 PW vs 없는 계정 실패의 status/message/code가 다름",
      },
      { label: "ZAP 보조", text: "Username Enumeration 알림(선택)" },
    ],
    steps: [
      <>Verify로 로그인 API를 탐지하고 Test Accounts를 등록합니다.</>,
      <>Diagnosis 6-2 「진단 시작」→ Strict 비교·(선택) ZAP을 설정합니다.</>,
      <>존재/없음 계정 실패 시나리오를 각 로그인 target에 보냅니다.</>,
      <>결과에서 메시지·코드 차이와 심각도를 확인합니다.</>,
    ],
    results: [
      { tone: "medium", label: "중간", text: "실패 응답이 상이 — 계정 enumeration 위험" },
      { tone: "pass", label: "통과", text: "실패 응답이 동일하면 양호(샘플만 표시)" },
    ],
  },
  "7-1": {
    ariaLabel: "7-1 진단 안내",
    title: "7-1 Client Request Method",
    blurb: "TRACE echo·OPTIONS Allow의 위험 메서드(TRACK/CONNECT 등) 허용 여부를 점검합니다.",
    finds: [
      { label: "TRACE echo", text: "TRACE 2xx + 요청 경로/헤더가 본문에 반사" },
      { label: "Dangerous Allow", text: "Allow에 TRACE/TRACK/CONNECT" },
    ],
    steps: [
      <>Attack Surface Base URL을 등록합니다.</>,
      <>Diagnosis 7-1 「진단 시작」→ probeMode·Strict risky를 설정합니다.</>,
      <>Base/inventory 경로에 TRACE·OPTIONS를 보냅니다.</>,
      <>결과 표의 Issue·Methods·Allow·Severity를 확인합니다.</>,
    ],
    results: [
      { tone: "high", label: "높음", text: "TRACE echo 확인 — 메서드 비활성화 권장" },
      {
        tone: "note",
        label: "참고",
        text: <>디렉터리 listing은 {strong("7-2")}, 헤더 제품정보는 {strong("7-3")}.</>,
      },
    ],
  },
  "7-2": {
    ariaLabel: "7-2 진단 안내",
    title: "7-2 파일 목록화 가능성",
    blurb: "내장 wordlist로 디렉터리 인덱싱(Index of 등)이 켜져 있는지 자동 probe합니다.",
    finds: [
      { label: "Directory listing", text: "Apache/nginx/IIS/Tomcat 등 목록화 시그니처" },
      { label: "노출 경로", text: <>{code("/uploads/")} · {code("/examples/")} 등 열거 가능한 디렉터리</> },
    ],
    steps: [
      <>Base URL을 Attack Surface에 등록합니다.</>,
      <>Diagnosis 7-2 「진단 시작」→ wordlist / +api-tree 옵션을 선택합니다.</>,
      <>각 path에 trailing slash 유무로 GET합니다.</>,
      <>결과의 Path·Listing·Severity를 확인합니다.</>,
    ],
    results: [
      {
        tone: "high",
        label: "높음",
        text: "실제 listing 본문 확인 시 디렉터리 인덱싱 비활성·접근 통제",
      },
    ],
  },
  "7-3": {
    ariaLabel: "7-3 진단 안내",
    title: "7-3 서버 헤더정보 노출",
    blurb: "응답 헤더에 Server·X-Powered-By·버전·환경명 등 스택 정보가 노출되는지 점검합니다.",
    finds: [
      { label: "제품·버전", text: "nginx/1.x, PHP/8, Express 등 Server·X-Powered-By" },
      { label: "환경·스택 힌트", text: "X-Environment·커스텀 version/powered 헤더" },
    ],
    steps: [
      <>Base URL 등록 후 Diagnosis 7-3 「진단 시작」.</>,
      <>Strict / CDN 헤더 포함 등 옵션을 설정합니다.</>,
      <>응답 헤더를 수집·중복 제거합니다.</>,
      <>헤더 노출 요약에서 Base×헤더 값을 확인합니다.</>,
    ],
    results: [
      { tone: "medium", label: "중간", text: "버전·제품명·환경명 노출 — 헤더 최소화 권장" },
      {
        tone: "note",
        label: "경계",
        text: <>본문 스택트레이스는 {strong("6-1")}, TLS·쿠키 설정은 {strong("7-4")}.</>,
      },
    ],
  },
  "8-1": {
    ariaLabel: "8-1 진단 안내",
    title: "8-1 취약점 진단 항목에 정의되지 않은 취약점",
    blurb: "가이드 1–7에 없는 이슈(비즈니스 로직·신기능·서드파티 등)를 별도 항목으로 기록하는 수동 슬롯입니다.",
    modeBadge: "수동 진단",
    finds: [
      { label: "가이드 외 취약점", text: "기타 항목에 매핑되지 않는 보안 결함" },
      { label: "환경 특화 이슈", text: "커스텀 워크플로·연동·설정 실수" },
    ],
    stepsTitle: "수동 진단 방법",
    steps: [
      <>1–7 자동·수동 항목을 먼저 모두 수행합니다.</>,
      <>남은 위험(로직 버그, 레이스, 서드파티 연동 등)을 재현하고 요청/응답·화면 증거를 남깁니다.</>,
      <>가능하면 가장 가까운 가이드 번호로 재분류하고, 불가할 때만 8-1로 기록합니다.</>,
      <>제목·재현 절차·영향·조치 권고를 문서화합니다. Diagnosis 「진단 시작」 없음.</>,
    ],
    resultTitle: "주의사항",
    results: [
      {
        tone: "note",
        label: "주의",
        text: "중복 보고를 피하려면 기존 항목과 연결해 기록합니다.",
      },
    ],
  },
};

export function hasRegistrySectionInfo(sectionId: string): boolean {
  return Object.prototype.hasOwnProperty.call(SECTION_INFO_CONTENT, sectionId);
}
