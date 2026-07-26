"""Parse Set-Cookie lines and classify HttpOnly / Secure / SameSite issues."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SESSION_COOKIE_HINTS = re.compile(
    r"(session|sess|sid|token|auth|jwt|access|refresh|login|user)",
    re.IGNORECASE,
)

CHECK_TO_RULE_ID = {
    "cookie_missing_secure": "4-1-cookie-missing-secure",
    "cookie_missing_httponly": "4-1-cookie-missing-httponly",
    "cookie_missing_samesite": "4-1-cookie-missing-samesite",
    "cookie_samesite_none_insecure": "4-1-cookie-samesite-none-insecure",
}


@dataclass
class CookieFlagIssue:
    check_type: str
    reason: str
    severity: str
    cookie_name: str
    cookie_flags: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_type": self.check_type,
            "reason": self.reason,
            "severity": self.severity,
            "cookie_name": self.cookie_name,
            "cookie_flags": self.cookie_flags,
            "rule_id": CHECK_TO_RULE_ID.get(self.check_type, "4-1-cookie-flags"),
        }


def parse_cookie_flags(cookie_line: str) -> dict[str, bool | str]:
    parts = [p.strip() for p in cookie_line.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    flags: dict[str, bool | str] = {"name": name}
    for part in parts[1:]:
        low = part.lower()
        if low == "secure":
            flags["secure"] = True
        elif low == "httponly":
            flags["httponly"] = True
        elif low.startswith("samesite="):
            flags["samesite"] = part.split("=", 1)[1].strip()
    return flags


def _is_auth_cookie(name: str, auth_cookie_names: set[str]) -> bool:
    if name in auth_cookie_names:
        return True
    return bool(SESSION_COOKIE_HINTS.search(name))


def scan_cookie_attributes(
    cookie_lines: list[str],
    *,
    is_https: bool,
    strict: bool = True,
    auth_cookie_names: set[str] | None = None,
) -> list[CookieFlagIssue]:
    """Static analysis of Set-Cookie attribute flags."""
    if not cookie_lines:
        return []

    auth_names = auth_cookie_names or set()
    issues: list[CookieFlagIssue] = []

    for line in cookie_lines:
        flags = parse_cookie_flags(line)
        name = str(flags.get("name") or "")
        if not name:
            continue

        auth_like = _is_auth_cookie(name, auth_names)

        if is_https and not flags.get("secure"):
            issues.append(
                CookieFlagIssue(
                    check_type="cookie_missing_secure",
                    reason="Set-Cookie without Secure on HTTPS",
                    severity="medium",
                    cookie_name=name,
                    cookie_flags=line,
                )
            )

        samesite = str(flags.get("samesite") or "").lower()
        if samesite == "none" and not flags.get("secure"):
            issues.append(
                CookieFlagIssue(
                    check_type="cookie_samesite_none_insecure",
                    reason="SameSite=None requires Secure",
                    severity="high",
                    cookie_name=name,
                    cookie_flags=line,
                )
            )
        elif strict and not samesite:
            issues.append(
                CookieFlagIssue(
                    check_type="cookie_missing_samesite",
                    reason="Set-Cookie missing SameSite",
                    severity="medium" if auth_like else "low",
                    cookie_name=name,
                    cookie_flags=line,
                )
            )

        if strict and auth_like and not flags.get("httponly"):
            issues.append(
                CookieFlagIssue(
                    check_type="cookie_missing_httponly",
                    reason="Auth/session cookie without HttpOnly",
                    severity="high" if name in auth_names else "medium",
                    cookie_name=name,
                    cookie_flags=line,
                )
            )

    return issues
