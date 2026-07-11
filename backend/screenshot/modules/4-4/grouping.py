"""스크린샷 대상 4-4 finding을 선정: 케이스(trigger)별 대표 finding 최대 3건

4-4 케이스(trigger)와 각 케이스가 만드는 프레임 쌍:

  unauth_access_confirmed   (HIGH/MED) 익명·인증 모두 2xx — 서버측 미보호 확정
  anon_ok_auth_denied       (HIGH)     익명 2xx인데 인증은 401/403 (이상 신호)
  unauth_access_no_account  (HIGH/MED) 익명 2xx, 비교 계정 없음

선정된 각 finding → 기본(정상, 인증 접근) 프레임 + 비교(비정상, 비인증 접근) 프레임,
INFO인 `client_side_guard_only` trigger는 기본적으로 제외 (서버측 노출 아님)
"""

from __future__ import annotations

from dataclasses import dataclass

from diagnosis.result import DiagnosisFinding

_RULE_ID = "4-4-unauth-page-access"
_PER_CASE = 3

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}

# 케이스 순서 = 리포트 우선순위. 높을수록 먼저
_CASE_PRIORITY = {
    "unauth_access_confirmed": 3,
    "anon_ok_auth_denied": 2,
    "unauth_access_no_account": 1,
}
_EXCLUDED_TRIGGERS = frozenset({"client_side_guard_only"})

_TRIGGER_LABELS = {
    "unauth_access_confirmed": "비인증 중요 페이지 접근 확인",
    "anon_ok_auth_denied": "익명 성공 · 인증 거부 (이상 신호)",
    "unauth_access_no_account": "비인증 접근 성공 (비교 계정 없음)",
}


@dataclass
class Shot:
    seq: int
    endpoint_id: str
    trigger: str
    severity: str
    method: str
    path: str
    base_url: str
    origin_enforces_auth: bool = False

    def trigger_label(self) -> str:
        return _TRIGGER_LABELS.get(self.trigger, self.trigger)

    def case_slug(self) -> str:
        return {
            "unauth_access_confirmed": "confirmed",
            "anon_ok_auth_denied": "anon-ok-auth-denied",
            "unauth_access_no_account": "no-account",
        }.get(self.trigger, "case")


def real_findings(findings: list[DiagnosisFinding]) -> list[DiagnosisFinding]:
    """합성된 '4-4 진단 통계' info finding은 버리고 페이지 접근 탐지 건만 남김"""
    return [f for f in findings if (f.evidence or {}).get("rule_id") == _RULE_ID]


def _origin_enforces(ev: dict) -> bool:
    meta = ev.get("meta") if isinstance(ev.get("meta"), dict) else ev
    val = meta.get("origin_enforces_auth")
    return bool(val)


def select_shots(findings: list[DiagnosisFinding]) -> list[Shot]:
    """finding을 trigger별로 그룹핑하고, 케이스마다 대표성이 높은 상위 3건을 남김"""
    by_trigger: dict[str, list[Shot]] = {}
    seen_endpoints: set[str] = set()

    for f in real_findings(findings):
        ev = f.evidence or {}
        trigger = str(ev.get("trigger") or "")
        if trigger in _EXCLUDED_TRIGGERS or trigger not in _CASE_PRIORITY:
            continue
        endpoint_id = str(ev.get("endpoint_id") or "")
        if not endpoint_id or endpoint_id in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_id)
        by_trigger.setdefault(trigger, []).append(
            Shot(
                seq=0,
                endpoint_id=endpoint_id,
                trigger=trigger,
                severity=f.severity,
                method=str(ev.get("method") or "GET"),
                path=str(ev.get("path") or "/"),
                base_url=str(ev.get("base_url") or ""),
                origin_enforces_auth=_origin_enforces(ev),
            )
        )

    selected: list[Shot] = []
    for trigger in sorted(by_trigger, key=lambda t: _CASE_PRIORITY.get(t, 0), reverse=True):
        ranked = sorted(
            by_trigger[trigger],
            key=lambda s: (
                _SEVERITY_RANK.get(s.severity, 0),
                s.origin_enforces_auth,
                -len(s.path),
            ),
            reverse=True,
        )
        selected.extend(ranked[:_PER_CASE])

    for i, shot in enumerate(selected, start=1):
        shot.seq = i
    return selected
