"""HTTP transport for 2-1 — re-exports shared diagnosis transports (2-2 pattern)."""

from __future__ import annotations

from diagnosis.probe_transport import HttpxTransport, ProbeResponse, ZapTransport

__all__ = ["HttpxTransport", "ZapTransport", "ProbeResponse"]
