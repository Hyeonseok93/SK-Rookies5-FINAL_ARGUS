"""5-2 finding을 증거 shot으로 그룹핑 (엔드포인트 × 계정당 스크린샷 1장)

통합 규칙:
  * response_body finding   → (엔드포인트, 계정)으로 그룹핑. 해당 계정이 그 엔드포인트에서
                              노출하는 모든 값을 한 shot에 함께 강조.
  * request_body/request_url→ 엔드포인트 단위로만 그룹핑(우리가 보내는 프로브는 계정과
                              무관하게 동일) → 엔드포인트당 "프로브 요청" shot 1장.
  * transport (http plain)  → 전용 shot 없음. http:// 는 모든 shot의 주소창에 이미
                              보이므로 그쪽으로 흡수됨.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from diagnosis.result import DiagnosisFinding

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
_PROBE_ACCOUNT = "__probe__"

_CATEGORY_LABELS = {
    "email": "이메일",
    "phone": "전화번호",
    "name": "이름",
    "rrn": "주민등록번호",
    "passport": "여권번호",
    "payment": "카드번호",
    "account": "계좌번호",
    "bank": "은행정보",
    "path": "경로/구조",
}


@dataclass
class Shot:
    seq: int
    endpoint_id: str
    kind: str  # "response" | "request"
    account: str  # auth_mode 문자열, "anonymous", 또는 "__probe__"
    severity: str = "info"
    categories: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    url_markers: list[str] = field(default_factory=list)
    request_body_markers: list[str] = field(default_factory=list)
    response_body_markers: list[str] = field(default_factory=list)
    field_paths: list[str] = field(default_factory=list)

    def account_label(self) -> str:
        if self.kind == "request":
            return "프로브 요청 (계정 무관)"
        if self.account in ("", "anonymous"):
            return "익명"
        # "authenticated:yerin@travel.com:login" → "yerin@travel.com"으로 축약
        parts = self.account.split(":")
        return parts[1] if len(parts) >= 2 else self.account

    def category_label(self) -> str:
        seen: list[str] = []
        for c in self.categories:
            label = _CATEGORY_LABELS.get(c, c)
            if label not in seen:
                seen.append(label)
        return ", ".join(seen) if seen else "개인정보"


def real_findings(findings: list[DiagnosisFinding]) -> list[DiagnosisFinding]:
    """합성된 '5-2 스캔 통계' info finding은 버리고 개인정보 탐지 건만 남김"""
    return [f for f in findings if (f.evidence or {}).get("rule_id")]


def _accounts_for(ev: dict) -> list[str]:
    """이 값을 정확히 관측한 모든 인증 pass(축약된 'multiple'을 펼침)"""
    modes = ev.get("auth_modes")
    if isinstance(modes, list) and modes:
        return [str(m) for m in modes]
    return [str(ev.get("auth_mode") or "anonymous")]


def _bump_severity(shot: Shot, severity: str) -> None:
    if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(shot.severity, 0):
        shot.severity = severity


def _add_meta(shot: Shot, ev: dict, severity: str) -> None:
    _bump_severity(shot, severity)
    cat = str(ev.get("category") or "")
    if cat and cat not in shot.categories:
        shot.categories.append(cat)
    rule = str(ev.get("rule_id") or "")
    if rule and rule not in shot.rule_ids:
        shot.rule_ids.append(rule)
    fp = ev.get("field_path")
    if fp and fp not in shot.field_paths:
        shot.field_paths.append(str(fp))


def select_shots(findings: list[DiagnosisFinding]) -> list[Shot]:
    """finding을 (엔드포인트 × 계정) 노출당 하나의 shot으로 합침"""
    shots: dict[tuple[str, str, str], Shot] = {}

    def _get(endpoint_id: str, kind: str, account: str) -> Shot:
        key = (endpoint_id, kind, account)
        shot = shots.get(key)
        if shot is None:
            shot = Shot(seq=0, endpoint_id=endpoint_id, kind=kind, account=account)
            shots[key] = shot
        return shot

    for f in real_findings(findings):
        ev = f.evidence or {}
        endpoint_id = str(ev.get("endpoint_id") or "")
        direction = str(ev.get("direction") or "")
        marker = ev.get("marker")

        if direction == "response_body":
            for account in _accounts_for(ev):
                shot = _get(endpoint_id, "response", account)
                if marker and marker not in shot.response_body_markers:
                    shot.response_body_markers.append(str(marker))
                _add_meta(shot, ev, f.severity)
        elif direction in ("request_body", "request_url"):
            shot = _get(endpoint_id, "request", _PROBE_ACCOUNT)
            if direction == "request_url":
                if marker and marker not in shot.url_markers:
                    shot.url_markers.append(str(marker))
            else:
                if marker and marker not in shot.request_body_markers:
                    shot.request_body_markers.append(str(marker))
            _add_meta(shot, ev, f.severity)
        # transport → 주소창으로 흡수됨. 전용 shot 없음.

    ordered = sorted(
        shots.values(),
        key=lambda s: (s.endpoint_id, s.kind, s.account),
    )
    for i, shot in enumerate(ordered, start=1):
        shot.seq = i
    return ordered
