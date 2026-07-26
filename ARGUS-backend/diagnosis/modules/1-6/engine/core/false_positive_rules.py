# =============================================================================
# core/false_positive_rules.py
#
# 목적:
#   특정 문자열(예: "jsontoken")이 sensitive/leak 키워드와 우연히 겹쳐서
#   발생하는 오탐(false positive)을 한 곳에서 관리합니다.
#
#   기존에는 fuzzer.py(_has_real_sensitive_leak)와 collector.py
#   (_classify_finding) 두 곳에 각각 하드코딩되어 있었습니다. 새로운
#   오탐 패턴이 나올 때마다 두 파일을 동시에 고쳐야 했고, 서로 다르게
#   갱신될 위험도 있었습니다.
#
#   이제는 새로운 오탐이 발견되면 아래 FALSE_POSITIVE_SUPPRESSIONS
#   테이블에 항목만 추가하면 됩니다. fuzzer.py / collector.py 쪽 로직은
#   손댈 필요가 없습니다.
# =============================================================================

# key   : 응답 스니펫(소문자)에서 찾을 하위 문자열
# value : {
#     "suppress_leak"  : True면 fuzzer._has_real_sensitive_leak()에서
#                        이 용어가 있을 때 "leak 아님"으로 처리
#     "downgrade_from" : collector._classify_finding()에서 risk가 이 값일 때만
#                        downgrade_to로 낮춤 (None이면 downgrade 미적용)
#     "downgrade_to"   : 낮출 대상 risk 값
#     "reason"         : evidence_reason에 남길 설명 (한 줄)
# }
FALSE_POSITIVE_SUPPRESSIONS = {
    "jsontoken": {
        "suppress_leak": True,
        "downgrade_from": "CRITICAL",
        "downgrade_to": "HIGH",
        "reason": "JsonToken parser wording is not a secret leak",
    },
    "json token": {
        "suppress_leak": True,
        "downgrade_from": "CRITICAL",
        "downgrade_to": "HIGH",
        "reason": "JsonToken parser wording is not a secret leak",
    },
    "jsonwebtoken": {
        "suppress_leak": True,
        "downgrade_from": None,
        "downgrade_to": None,
        "reason": "JsonWebToken library name, not a leaked token value",
    },
    "token `": {
        "suppress_leak": True,
        "downgrade_from": None,
        "downgrade_to": None,
        "reason": "parser/log message quoting the word 'token'",
    },
    "token.start": {
        "suppress_leak": True,
        "downgrade_from": None,
        "downgrade_to": None,
        "reason": "tokenizer position field, not a leaked token",
    },
    "token_start": {
        "suppress_leak": True,
        "downgrade_from": None,
        "downgrade_to": None,
        "reason": "tokenizer position field, not a leaked token",
    },
}


def is_suppressed_leak(body_lower: str) -> bool:
    """
    fuzzer.py의 _has_real_sensitive_leak()에서 사용.
    suppress_leak=True인 용어가 스니펫에 있으면 True (= leak 아님으로 처리).
    """
    return any(
        term in body_lower
        for term, rule in FALSE_POSITIVE_SUPPRESSIONS.items()
        if rule.get("suppress_leak")
    )


def apply_risk_downgrade(snippet_lower: str, current_risk):
    """
    collector.py의 _classify_finding()에서 사용.

    Args:
        snippet_lower: 소문자로 변환된 응답 스니펫
        current_risk:  finding["risk"] 현재 값

    Returns:
        (new_risk, reason) 튜플.
        매칭되는 규칙이 없으면 (current_risk, None).
    """
    for term, rule in FALSE_POSITIVE_SUPPRESSIONS.items():
        if term in snippet_lower:
            downgrade_from = rule.get("downgrade_from")
            downgrade_to = rule.get("downgrade_to")
            if downgrade_from is not None and downgrade_to is not None \
                    and current_risk == downgrade_from:
                return downgrade_to, rule.get("reason", "")
            return current_risk, rule.get("reason", "")
    return current_risk, None