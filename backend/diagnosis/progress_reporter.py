"""Shared progress reporting for diagnosis module scanners."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.services import diagnosis_progress as dp

ProgressCallback = Callable[..., None]


def phase(
    message: str,
    *,
    phase_name: str = "running",
    done: int | None = None,
    total: int | None = None,
    percent: int | None = None,
    requests_sent: int | None = None,
) -> None:
    dp.update(
        phase=phase_name,
        message=message,
        endpoints_done=done if done is not None else None,
        endpoints_total=total if total is not None else None,
        requests_sent=requests_sent,
        percent=percent,
    )


def prepare(total: int, message: str) -> None:
    phase(message, phase_name="preparing", done=0, total=max(0, total))


def zap_phase(message: str = "ZAP scan…", *, done: int | None = None, total: int | None = None) -> None:
    phase(message, phase_name="zap", done=done, total=total, percent=90 if total is None else None)


def endpoint_progress(
    *,
    total: int,
    phase_name: str = "probe",
    prefix: str = "",
) -> ProgressCallback:
    """Return a callback compatible with run_endpoints / run_*_probes on_progress hooks."""

    def _cb(**kw: Any) -> None:
        done = int(kw.get("endpoints_done") or kw.get("done") or 0)
        total_n = int(kw.get("endpoints_total") or kw.get("total") or total)
        item = str(kw.get("endpoint_id") or kw.get("item") or kw.get("label") or "")
        req = kw.get("requests_sent")
        msg = f"{prefix}{done}/{total_n}".strip()
        if item:
            msg = f"{msg} · {item[:80]}"
        dp.update(
            phase=phase_name,
            message=msg,
            endpoints_done=done,
            endpoints_total=total_n,
            requests_sent=int(req) if req is not None else None,
        )

    return _cb


def step_progress(*, total: int, phase_name: str, label: str) -> Callable[[int, str | None], None]:
    def _cb(done: int, detail: str | None = None) -> None:
        msg = f"{label} {done}/{total}"
        if detail:
            msg += f" · {detail[:80]}"
        phase(msg, phase_name=phase_name, done=done, total=total)

    return _cb
