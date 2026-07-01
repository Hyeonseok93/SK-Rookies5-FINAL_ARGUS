"""Classify TRACE echo and Allow-header method policy (7-1)."""

from __future__ import annotations

from dataclasses import dataclass

DANGEROUS_ALLOW_METHODS = frozenset({"TRACE", "TRACK", "CONNECT"})
RISKY_ALLOW_METHODS = frozenset({"PUT", "DELETE"})


@dataclass(frozen=True)
class MethodIssue:
    severity: str
    issue_type: str
    reason: str
    method: str | None = None
    matched_methods: tuple[str, ...] = ()
    allow_header: str | None = None


def parse_allow_header(value: str) -> set[str]:
    return {part.strip().upper() for part in value.split(",") if part.strip()}


def _body_text(body: str | bytes) -> str:
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return body


def classify_trace_response(
    status: int | None,
    body: str | bytes,
    *,
    request_path: str,
) -> MethodIssue | None:
    """TRACE enabled when server returns 2xx and echoes the request in the body."""
    if status is None or status < 200 or status >= 300:
        return None
    text = _body_text(body)
    upper = text.upper()
    if "TRACE" not in upper:
        return None
    path = request_path or "/"
    echoed = path in text or "HTTP/1." in upper or "/ HTTP" in upper
    if not echoed:
        return None
    return MethodIssue(
        severity="high",
        issue_type="trace_echo",
        reason="TRACE request echoed in response body",
        method="TRACE",
    )


def classify_allow_header(allow: str | None, *, strict_risky: bool) -> list[MethodIssue]:
    if not allow or not str(allow).strip():
        return []
    methods = parse_allow_header(str(allow))
    issues: list[MethodIssue] = []

    dangerous = tuple(sorted(DANGEROUS_ALLOW_METHODS & methods))
    if dangerous:
        sev = "high" if any(m in ("TRACE", "TRACK") for m in dangerous) else "medium"
        issues.append(
            MethodIssue(
                severity=sev,
                issue_type="allow_dangerous",
                reason="Allow header advertises dangerous HTTP methods",
                matched_methods=dangerous,
                allow_header=str(allow).strip(),
            )
        )

    if strict_risky:
        risky = tuple(sorted(RISKY_ALLOW_METHODS & methods))
        if risky:
            issues.append(
                MethodIssue(
                    severity="low",
                    issue_type="allow_risky",
                    reason="Allow header advertises PUT or DELETE",
                    matched_methods=risky,
                    allow_header=str(allow).strip(),
                )
            )
    return issues


def scan_rules_from_config(raw: dict) -> dict[str, bool]:
    cfg = raw.get("diagnosis_7_1") or raw.get("scan_7_1") or {}
    return {
        "strict_risky": bool(cfg.get("strict_risky", True)),
    }
