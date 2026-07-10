"""Reflected XSS probe payloads — reflected_detector.py의 리다이렉트 페이로드와 같은
전송/응답비교 구조를 재사용하되, "리다이렉트로 이어지는가" 대신 "스크립트/HTML이
이스케이프 없이 그대로 반사되는가"를 판별하기 위한 페이로드 세트다.
"""

from __future__ import annotations


def build_xss_payloads(marker: str) -> list[tuple[str, str]]:
    """(payload_value, description) 목록을 반환한다.

    Args:
        marker: 이번 스캔 실행에 고유한 토큰(run_id). 응답에 우연히 존재하는 각괄호
            문자열과 실제 페이로드 반사를 구분하기 위해 모든 페이로드에 삽입한다.
    """
    tag = f"argusxss{marker}"
    return [
        (f"<script>/*{tag}*/</script>", "기본 <script> 태그 반사"),
        (f'"><script>/*{tag}*/</script>', "속성값 탈출 후 <script> 태그 삽입"),
        (f"<img src=x onerror=/*{tag}*/1>", "onerror 이벤트 핸들러 반사"),
        (f"<svg onload=/*{tag}*/1>", "onload 이벤트 핸들러 반사 (svg)"),
    ]
