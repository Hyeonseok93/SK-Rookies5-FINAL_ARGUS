"""Payload source metadata for diagnosis 1-6.

The actual payload generators are embedded under engine/payloads and loaded by
engine/main.py. This module documents the sources used by the 1-6 module.
"""

from __future__ import annotations


def payload_sources() -> list[str]:
    return [
        "KISA",
        "SK Shielders",
        "CWE",
        "OWASP",
    ]
