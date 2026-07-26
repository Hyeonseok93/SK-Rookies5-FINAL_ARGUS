"""TLS / certificate checks for guideline 7-4 (stdlib `ssl` only, target-agnostic).

config `targets` 로 들어온 base_url 중 scheme 이 https 인 것만 골라
아래 4가지를 점검한다. 특정 도메인 하드코딩 없음 — 어떤 https 대상이든 동작.

  1. 인증서 만료 / 임박        → tls_cert_expired / tls_cert_expiring_soon
  2. 신뢰 체인 검증 실패        → tls_cert_untrusted_chain (self-signed, 불완전 체인, 미확인 CA)
  3. 호스트명 불일치            → tls_cert_hostname_mismatch
  4. 취약 프로토콜(TLS 1.0/1.1) → tls_weak_protocol

http 대상은 여기서 무시된다(전송구간 암호화 부재는 security_rules 가 이미 잡음).
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from diagnosis.result import DiagnosisFinding

EXPIRY_WARN_DAYS = 30

# 취약 프로토콜 후보. OpenSSL 빌드에 따라 설정 불가할 수 있어 예외 처리함.
_WEAK_PROTOCOLS: list[tuple[str, Any]] = []
for _name in ("TLSv1", "TLSv1_1"):
    _ver = getattr(ssl.TLSVersion, _name, None)
    if _ver is not None:
        _WEAK_PROTOCOLS.append((_name.replace("_", "."), _ver))


def _remediation(check_type: str) -> str:
    hints = {
        "tls_cert_expired": "Renew the TLS certificate immediately",
        "tls_cert_expiring_soon": "Renew the TLS certificate before it expires",
        "tls_cert_untrusted_chain": (
            "Install the full certificate chain from a trusted CA "
            "(do not use self-signed certificates in production)"
        ),
        "tls_cert_hostname_mismatch": "Issue a certificate whose CN/SAN matches the served hostname",
        "tls_weak_protocol": "Disable TLS 1.0/1.1; allow only TLS 1.2 and TLS 1.3",
    }
    return hints.get(check_type, "Harden the TLS configuration")


def _split_host_port(base_url: str) -> tuple[str | None, int]:
    parsed = urlparse(base_url)
    return parsed.hostname, (parsed.port or 443)


def _finding(
    severity: str,
    check_type: str,
    reason: str,
    base_url: str,
    host: str,
    **extra: Any,
) -> DiagnosisFinding:
    return DiagnosisFinding(
        severity=severity,
        message=f"[7-4] TLS/certificate issue ({reason}) on {base_url}",
        evidence={
            "rule_id": "7-4-weak-security",
            "source": "tls",
            "engine": "tls",
            "check_type": check_type,
            "reason": reason,
            "base_url": base_url,
            "url": base_url,
            "label": base_url,
            "host": host,
            "remediation": _remediation(check_type),
            **extra,
        },
    )


def _parse_cert_time(value: str) -> datetime | None:
    """OpenSSL notAfter 형식 'Jun 10 12:00:00 2027 GMT' → aware datetime(UTC)."""
    try:
        dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _check_certificate(
    base_url: str, host: str, port: int, timeout: float, findings: list[DiagnosisFinding]
) -> bool:
    """검증 handshake 수행. 도달 가능하면 True(취약해도 True), 못 닿으면 False."""
    ctx = ssl.create_default_context()  # check_hostname=True, CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        # 검증 통과 → 유효한 인증서. 만료 임박만 확인.
        not_after = (cert or {}).get("notAfter")
        expiry = _parse_cert_time(not_after) if not_after else None
        if expiry is not None:
            days = (expiry - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(
                    _finding("high", "tls_cert_expired",
                             "Certificate has expired", base_url, host,
                             not_after=not_after, days_remaining=days)
                )
            elif days <= EXPIRY_WARN_DAYS:
                findings.append(
                    _finding("medium", "tls_cert_expiring_soon",
                             f"Certificate expires in {days} day(s)", base_url, host,
                             not_after=not_after, days_remaining=days)
                )
        return True
    except ssl.SSLCertVerificationError as exc:
        msg = str(exc).lower()
        if "expired" in msg:
            findings.append(_finding("high", "tls_cert_expired",
                                     "Certificate has expired", base_url, host, detail=str(exc)))
        elif "hostname mismatch" in msg or "doesn't match" in msg or "match either" in msg:
            findings.append(_finding("high", "tls_cert_hostname_mismatch",
                                     "Certificate hostname does not match the served host",
                                     base_url, host, detail=str(exc)))
        elif "self-signed" in msg or "self signed" in msg:
            findings.append(_finding("high", "tls_cert_untrusted_chain",
                                     "Self-signed certificate (not trusted)",
                                     base_url, host, detail=str(exc)))
        elif "unable to get local issuer" in msg or "unable to verify" in msg:
            findings.append(_finding("high", "tls_cert_untrusted_chain",
                                     "Incomplete chain or untrusted CA",
                                     base_url, host, detail=str(exc)))
        else:
            findings.append(_finding("high", "tls_cert_untrusted_chain",
                                     f"Certificate verification failed: {exc}",
                                     base_url, host, detail=str(exc)))
        return True  # 서버엔 닿았고, 인증서가 문제인 것
    except (ssl.SSLError, socket.timeout, TimeoutError, ConnectionError, OSError):
        return False  # 못 닿음 — 취약점 아님(정보성)


def _check_weak_protocols(
    base_url: str, host: str, port: int, timeout: float, findings: list[DiagnosisFinding]
) -> None:
    """TLS 1.0/1.1 로 handshake 가 성립하면 취약 프로토콜 지원으로 판정."""
    for label, version in _WEAK_PROTOCOLS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, AttributeError):
            # 이 Python/OpenSSL 빌드는 해당 버전 강제가 불가 → 클라이언트 측에서 점검 불가
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated = ssock.version()
            findings.append(
                _finding("medium", "tls_weak_protocol",
                         f"Server accepts weak protocol {label}", base_url, host,
                         protocol=label, negotiated=negotiated)
            )
        except (ssl.SSLError, socket.timeout, TimeoutError, ConnectionError, OSError):
            pass  # handshake 실패 = 그 약한 프로토콜을 거부함(정상)


def check_tls_for_base_urls(
    base_urls: list[str],
    *,
    timeout: float = 8.0,
    on_progress: Any | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "https_targets": 0,
        "checked": 0,
        "unreachable": 0,
        "issues": 0,
        "weak_protocol_probe_supported": bool(_WEAK_PROTOCOLS),
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
    }
    seen: set[tuple[str, int]] = set()

    for base in base_urls:
        base = (base or "").strip().rstrip("/")
        if not base:
            continue
        parsed = urlparse(base)
        if (parsed.scheme or "").lower() != "https":
            continue  # http 는 여기서 무시 (security_rules 가 no_transport_encryption 으로 잡음)
        host, port = _split_host_port(base)
        if not host:
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)

        stats["https_targets"] += 1
        before = len(findings)
        reachable = _check_certificate(base, host, port, timeout, findings)
        if reachable:
            stats["checked"] += 1
            _check_weak_protocols(base, host, port, timeout, findings)
        else:
            stats["unreachable"] += 1
            findings.append(
                DiagnosisFinding(
                    severity="info",
                    message=f"[7-4] TLS target unreachable: {base}",
                    evidence={
                        "rule_id": "7-4-weak-security",
                        "source": "tls",
                        "engine": "tls",
                        "base_url": base,
                        "url": base,
                        "host": host,
                        "reason": "TLS endpoint unreachable",
                    },
                )
            )

        for f in findings[before:]:
            sev = f.severity
            if sev in stats["by_severity"]:
                stats["by_severity"][sev] += 1
            if sev != "info":
                stats["issues"] += 1

        if on_progress:
            on_progress(endpoint_id=base)

    return findings, stats