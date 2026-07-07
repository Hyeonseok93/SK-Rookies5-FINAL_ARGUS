/** KISA Web/API 개발보안 Guideline — sections 1-1 through 8-1 (content TBD). */
export interface GuidelineSection {
  id: string;
  title: string;
  chapter: number;
  description?: string;
}

export const GUIDELINE_SECTIONS: GuidelineSection[] = [
  { 
    id: "1-1", 
    title: "XSS / CSRF 공격 가능성", 
    chapter: 1, 
    description: "• XSS (교차 사이트 스크립팅)\n  공격자가 웹 페이지에 악성 스크립트를 삽입하여, 다른 사용자가 해당 페이지를 열람할 때 브라우저에서 스크립트가 실행되도록 하는 취약점입니다. 주로 세션 쿠키 탈취나 권한 도용에 악용됩니다.\n\n• CSRF (교차 사이트 요청 위조)\n  사용자가 자신의 의지와는 무관하게, 공격자가 의도한 특정 요청(수정, 삭제 등)을 웹 서버로 전송하게 만드는 취약점입니다. 사용자가 이미 인증된 상태(로그인 상태)일 때 피해가 발생합니다." 
  },
  { id: "1-2", title: "삽입(Injection) 공격 가능성", chapter: 1 },
  { id: "1-3", title: "파라미터 값 및 히든(Hidden) 필드 조작 가능성", chapter: 1 },
  { id: "1-4", title: "SSRF / File Inclusion 공격 가능성", chapter: 1 },
  { id: "1-5", title: "검증되지 않은 리다이렉트와 포워드", chapter: 1 },
  { id: "1-6", title: "입력 값 크기 및 무결성 검증 오류", chapter: 1 },
  { id: "2-1", title: "악성코드파일 업로드", chapter: 2 },
  { id: "2-2", title: "중요 정보 파일 다운로드 가능성", chapter: 2 },
  { id: "3-1", title: "패스워드 정책 유무 및 반영 여부", chapter: 3 },
  { id: "3-2", title: "인증 실패 횟수 제한", chapter: 3 },
  { id: "3-3", title: "계정 정보 파악 가능성", chapter: 3 },
  { id: "3-4", title: "관리자 페이지 분리 여부", chapter: 3 },
  { id: "3-5", title: "검색엔진 정보 노출 가능성", chapter: 3 },
  { id: "3-6", title: "백업 파일 및 테스트 파일 존재 여부", chapter: 3 },
  { id: "4-1", title: "쿠키(Cookie) 및 웹 스토리지(Web Storage) 조작 가능성", chapter: 4 },
  { id: "4-2", title: "인증(세션 및 토큰) 값 안전성 설정 여부", chapter: 4 },
  { id: "4-3", title: "접근제어 우회 가능성 확인", chapter: 4 },
  { id: "4-4", title: "비인증 상태로 중요 page접근 가능성", chapter: 4 },
  { id: "4-5", title: "일반계정 권한 상승 가능성", chapter: 4, description: "자동 진단(IDOR, 권한 덮어쓰기) 지원 모듈입니다. 진단을 위해 최소 2개의 일반 권한(USER) 계정이 필요하며, 결과는 보조 자료로 활용해야 합니다." },
  { id: "5-1", title: "소스코드 내 주요정보 노출 여부", chapter: 5 },
  { id: "5-2", title: "요청 및 응답 값 내 주요정보 포함여부 확인", chapter: 5 },
  { id: "6-1", title: "오류페이지를 통한 정보 노출 여부", chapter: 6 },
  { id: "6-2", title: "일괄적인 오류 처리 페이지 존재 여부", chapter: 6 },
  { id: "7-1", title: "Client Request Method", chapter: 7 },
  { id: "7-2", title: "파일 목록화 가능성", chapter: 7 },
  { id: "7-3", title: "서버 헤더정보 노출", chapter: 7 },
  { id: "7-4", title: "취약한 보안설정", chapter: 7 },
  { id: "8-1", title: "취약점 진단 항목에 정의되지 않은 취약점", chapter: 8 },
];
