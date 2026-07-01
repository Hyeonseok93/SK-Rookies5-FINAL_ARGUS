"""JWT / opaque token static analysis for guideline 4-2."""

from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from typing import Any

from diagnosis.result import DiagnosisFinding

JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
WEAK_ALGORITHMS = frozenset({"none", ""})


def is_jwt(token: str) -> bool:
    return bool(JWT_RE.match(str(token or "").strip()))


def _b64_json(segment: str) -> dict[str, Any] | None:
    raw = str(segment or "").strip()
    if not raw:
        return None
    pad = "=" * (-len(raw) % 4)
    try:
        data = base64.urlsafe_b64decode(raw + pad)
        parsed = json.loads(data.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    parts = str(token or "").strip().split(".")
    if len(parts) != 3:
        return None
    header = _b64_json(parts[0])
    payload = _b64_json(parts[1])
    if header is None or payload is None:
        return None
    return header, payload


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def analyze_token(
    token: str,
    *,
    label: str,
    login_url: str,
    email: str,
    max_lifetime_sec: int,
    min_token_length: int,
    min_entropy: float,
) -> list[DiagnosisFinding]:
    """Return 4-2 findings for a single access/refresh token string."""
    tok = str(token or "").strip()
    if not tok:
        return []

    findings: list[DiagnosisFinding] = []
    base_evidence = {
        "token_label": label,
        "login_url": login_url,
        "email": email,
        "token_length": len(tok),
    }

    if len(tok) < min_token_length:
        findings.append(
            DiagnosisFinding(
                severity="medium",
                message=f"[4-2] Short auth token ({len(tok)} chars) for `{email}` — guessability risk",
                evidence={
                    **base_evidence,
                    "rule_id": "4-2-token-complexity",
                    "reason": f"token length {len(tok)} < minimum {min_token_length}",
                    "remediation": "Use longer, high-entropy session or JWT values",
                },
            )
        )

    entropy = shannon_entropy(tok)
    if entropy < min_entropy:
        findings.append(
            DiagnosisFinding(
                severity="medium",
                message=f"[4-2] Low-entropy auth token for `{email}` (H={entropy:.2f})",
                evidence={
                    **base_evidence,
                    "rule_id": "4-2-token-complexity",
                    "reason": f"Shannon entropy {entropy:.2f} below threshold {min_entropy}",
                    "entropy": round(entropy, 3),
                    "remediation": "Issue tokens from a CSPRNG; avoid predictable patterns",
                },
            )
        )

    if not is_jwt(tok):
        return findings

    decoded = decode_jwt(tok)
    if decoded is None:
        findings.append(
            DiagnosisFinding(
                severity="low",
                message=f"[4-2] Malformed JWT structure for `{email}`",
                evidence={
                    **base_evidence,
                    "rule_id": "4-2-jwt-structure",
                    "reason": "JWT segments are not valid base64 JSON",
                    "remediation": "Use standard JWT encoding (header.payload.signature)",
                },
            )
        )
        return findings

    header, payload = decoded
    alg = str(header.get("alg") or "").strip()
    alg_lower = alg.lower()
    jwt_evidence = {
        **base_evidence,
        "algorithm": alg,
        "jwt_header": header,
        "jwt_claims": {k: payload.get(k) for k in ("exp", "iat", "nbf", "sub", "jti") if k in payload},
    }

    if alg_lower in WEAK_ALGORITHMS:
        findings.append(
            DiagnosisFinding(
                severity="high",
                message=f"[4-2] Weak JWT algorithm `{alg or 'missing'}` for `{email}`",
                evidence={
                    **jwt_evidence,
                    "rule_id": "4-2-jwt-weak-alg",
                    "reason": "alg none or missing — signature not enforced",
                    "remediation": "Use asymmetric signing (e.g. RS256/ES256) and reject alg=none",
                },
            )
        )

    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is None:
        findings.append(
            DiagnosisFinding(
                severity="medium",
                message=f"[4-2] JWT has no exp claim for `{email}` — timeout not enforced in token",
                evidence={
                    **jwt_evidence,
                    "rule_id": "4-2-jwt-no-exp",
                    "reason": "exp claim missing",
                    "remediation": "Add exp (and iat) with recommended idle/session timeout (~30 minutes)",
                },
            )
        )
    elif iat is not None:
        try:
            lifetime = int(exp) - int(iat)
        except (TypeError, ValueError):
            lifetime = None
        if lifetime is not None and lifetime > max_lifetime_sec:
            findings.append(
                DiagnosisFinding(
                    severity="medium",
                    message=(
                        f"[4-2] JWT lifetime {lifetime}s exceeds recommended "
                        f"{max_lifetime_sec}s for `{email}`"
                    ),
                    evidence={
                        **jwt_evidence,
                        "rule_id": "4-2-jwt-long-lived",
                        "reason": f"exp-iat={lifetime}s > max {max_lifetime_sec}s",
                        "lifetime_sec": lifetime,
                        "max_lifetime_sec": max_lifetime_sec,
                        "remediation": "Shorten access-token lifetime and use refresh rotation",
                    },
                )
            )

    return findings


def analyze_sessions_tokens(
    sessions: list[dict[str, Any]],
    *,
    max_lifetime_sec: int,
    min_token_length: int,
    min_entropy: float,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """Analyze access + refresh tokens from login sessions."""
    findings: list[DiagnosisFinding] = []
    seen: set[tuple[str, str, str]] = set()
    stats = {"tokens_analyzed": 0, "jwt_tokens": 0, "opaque_tokens": 0}

    for session in sessions:
        email = str(session.get("email") or "")
        login_url = str(session.get("login_url") or "")
        for label, key in (("access", "access_token"), ("refresh", "refresh_token")):
            token = str(session.get(key) or "").strip()
            if not token:
                continue
            dedupe_key = (email, login_url, label)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            stats["tokens_analyzed"] += 1
            if is_jwt(token):
                stats["jwt_tokens"] += 1
            else:
                stats["opaque_tokens"] += 1
            findings.extend(
                analyze_token(
                    token,
                    label=label,
                    login_url=login_url,
                    email=email,
                    max_lifetime_sec=max_lifetime_sec,
                    min_token_length=min_token_length,
                    min_entropy=min_entropy,
                )
            )

    return findings, stats
