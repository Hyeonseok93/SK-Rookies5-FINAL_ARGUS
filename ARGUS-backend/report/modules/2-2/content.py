"""rule_id별 탐지 기법 설명 + SK 가이드라인 대응방안 문구."""

from __future__ import annotations

from typing import Any

# SK remediation split for PDF table rendering
SK_REMEDIATION_BEFORE_TABLE = '별도의 다운로드 애플리케이션을 사용해야 할 경우 웹 애플리케이션 (DocBase) 하위 폴더가 아닌 상위 경로 폴더 또는 타 드라이브에서 제공되어야 하며 파일이 위치하는 경로를 변수로써 사용하지 말고 해당 파일의 키 값을 변수로 사용하여 다운로드를 제공해야 합니다.\n파일이 위치하는 경로가 다양한 경우에는 경로 맵핑 변수를 활용하여 서버에서 위치를 맵핑하여 처리해야 하며 파일 업로드가 많고 소스 위치가 다양할 경우에는 필터 기능을 활용하여 처리하는 것을 권고합니다.\n※ 필터 기능관련 지원이 필요한 경우 IT보안 담당자를 통해 서버관리자에게 요청하여 지원 받을 수 있습니다.\n파일 다운로드 모듈의 경로를 처리하는 파라미터 변수에 대해 Server Side Language(PHP, ASP, JSP 등)에서 아래 표의 특수문자(path traversal 문자열)를 포함하는 파라미터 변수일 경우 에러를 발생시켜 프로세스를 중단하도록 처리해야 합니다.'

SK_FILTER_TABLE_TITLE = '다운로드 파일 필터링 문자 목록'
SK_FILTER_CHARS = ['../', './', '..\\', '.\\', '%', ';']

SK_REMEDIATION_AFTER_TABLE = '또한, 요청 사용자의 권한, 유효세션에 대한 검증 및 다운로드 하려는 파일의 정보를 최소한으로 제공하거나 인지 불가하도록 구현해야 합니다.'

SK_REMEDIATION_2_2 = (
    SK_REMEDIATION_BEFORE_TABLE
    + "\n\n"
    + SK_FILTER_TABLE_TITLE
    + "\n"
    + "\n".join(f"- {c}" for c in SK_FILTER_CHARS)
    + "\n\n"
    + SK_REMEDIATION_AFTER_TABLE
)

RULE_COPY: dict[str, dict[str, str]] = {
    '2-2-path-traversal': {
        "type_label": '경로 조작 · 파일 노출',
        "technique": '다운로드·보고서·템플릿 등 파일 경로를 받는 파라미터(path, filename, template, logoUrl 등)에 상위 디렉터리 이동(../)·절대경로·민감 파일 경로 같은 Path Traversal payload를 주입한 뒤, 정상(baseline) 요청과 공격 요청의 응답(상태코드·본문·파일 내용)을 비교합니다. 요청한 파일 내용(/etc/passwd, 로그, 설정파일 등)이 응답에 포함되면 취약으로 판정합니다.',
        "remediation": SK_REMEDIATION_2_2,
    },
    '2-2-unauth-download': {
        "type_label": '비로그인 다운로드',
        "technique": '동일한 다운로드·첨부 응답 API를 비로그인(anonymous) 세션과 로그인 세션으로 각각 호출하여 인증 없이도 HTTP 200과 파일/첨부(Content-Disposition, PDF·octet-stream 등) 응답이 내려오는지 비교합니다. 비로그인만으로 다운로드가 가능하면 취약으로 판정합니다.',
        "remediation": SK_REMEDIATION_2_2,
    },
    '2-2-forced-browse': {
        "type_label": '강제 파일 탐색',
        "technique": '백업·설정·숨김 파일 등 추측 가능한 경로를 wordlist로 강제 요청(Forced Browse)하여 비공개 파일·디렉터리 목록이 노출되는지 확인합니다.',
        "remediation": SK_REMEDIATION_2_2,
    },
    '2-2-input-validation': {
        "type_label": '입력값 검증 미흘',
        "technique": '파일 경로·이름 파라미터에 악성 path 조작 문자열을 전송했을 때 서버가 거부·정규화하지 않고 요청을 수용하는지(응답 변화 포함) 확인합니다.',
        "remediation": SK_REMEDIATION_2_2,
    },
}

DEFAULT_COPY = {
    "type_label": '중요 정보 파일 다운로드',
    "technique": '중요 정보 파일 다운로드 가능성(2-2) 진단으로 해당 엔드포인트에 대해 비로그인 접근·경로 조작·강제 탐색 등 파일 처리 취약 여부를 시험합니다.',
    "remediation": SK_REMEDIATION_2_2,
}


def copy_for_rule(rule_id: str | None) -> dict[str, str]:
    key = (rule_id or "").strip()
    return dict(RULE_COPY.get(key, DEFAULT_COPY))


def severity_label_ko(sev: str) -> str:
    mapping = {
        "high": '높음',
        "medium": '중간',
        "low": '낮음',
        "info": '정보',
    }
    return mapping.get((sev or "").lower(), sev or "-")


def build_url(ev: dict[str, Any]) -> str:
    for key in ("url", "anonymous_url", "authenticated_url", "attack_url"):
        val = ev.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    base = str(ev.get("base_url") or "").rstrip("/")
    path = str(ev.get("path") or "")
    if base and path:
        if not path.startswith("/"):
            path = "/" + path
        return base + path
    return path or base or "-"


def build_result_rows(finding: dict[str, Any]) -> list[tuple[str, str]]:
    """Section 2 summary: related URL and optional parameter."""
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    src = ev.get("source_evidence") if isinstance(ev.get("source_evidence"), dict) else {}
    method = str(ev.get("method") or "").upper()
    url = build_url(ev)
    url_display = f"{method} {url}".strip() if method else url

    rows: list[tuple[str, str]] = [
        ("URL", url_display or "-"),
    ]

    param = ev.get("param") or src.get("param")
    if param:
        param_in = ev.get("param_in") or src.get("param_in")
        param_text = f"{param} ({param_in})" if param_in else str(param)
        rows.append(('파라미터', param_text))
    return rows


def build_result_lines(finding: dict[str, Any]) -> list[str]:
    return [f"{k}: {v}" for k, v in build_result_rows(finding)]
