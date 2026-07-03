"""Run guideline 2-2 probes with a shared transport (httpx or ZAP)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from collections.abc import Callable
from typing import Any

from diagnosis.replay.recorder import ReplaySession
from diagnosis.result import DiagnosisFinding
from inventory.schema import Endpoint

_MODULE_DIR = Path(__file__).resolve().parent


def _load_local(name: str):
    path = _MODULE_DIR / f"{name}.py"
    mod_name = f"diag_g22_runner_{name}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def run_2_2_probes(
    transport: Any,
    *,
    engine: str,
    candidates: list[Endpoint],
    base_urls: list[str],
    traversal_payloads: list[str],
    browse_paths: list[str],
    auth: dict[str, Any] | None = None,
    account_auths: list[dict[str, Any]] | None = None,
    unauth_probe_enabled: bool = True,
    idor_probe_enabled: bool = True,
    idor_seeds: dict[str, Any] | None = None,
    replay_session: ReplaySession | None = None,
    auth_pool: Any | None = None,
    login_report: dict[str, Any] | None = None,
    timeout: float = 12.0,
    on_progress: Callable[..., None] | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """
    Execute 2-2 checks through the given transport using ARGUS classification logic.

    replay_session is attached only when engine == \"httpx\" (primary evidence).
    """
    auth_access = _load_local("auth_access")
    probes = _load_local("probes")

    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "engine": engine,
        "traversal_payloads": len(traversal_payloads),
        "browse_paths": len(browse_paths),
    }
    record_replay = replay_session if engine == "httpx" else None

    if auth_pool:
        auth_pool.ensure_valid()
        auth = auth_pool.primary()
        account_auths = auth_pool.sessions()

    if unauth_probe_enabled and candidates:
        unauth_findings, unauth_stats = auth_access.run_unauth_download_probes(
            candidates,
            sessions=account_auths,
            transport=transport,
            engine=engine,
            timeout=timeout,
            replay_session=record_replay,
            login_report=login_report,
        )
        findings.extend(unauth_findings)
        stats["unauth_probe"] = unauth_stats

    if idor_probe_enabled and account_auths and len(account_auths) >= 2 and candidates:
        if auth_pool:
            auth_pool.ensure_valid()
            account_auths = auth_pool.sessions()
        idor = _load_local("idor_probe")
        idor_findings, idor_stats = idor.run_idor_probes(
            candidates,
            account_auths=account_auths,
            transport=transport,
            engine=engine,
            idor_seeds=idor_seeds,
            timeout=timeout,
            replay_session=record_replay,
            login_report=login_report,
        )
        findings.extend(idor_findings)
        stats["idor_probe"] = idor_stats

    findings.extend(
        probes.run_traversal_probes(
            candidates,
            traversal_payloads,
            transport=transport,
            engine=engine,
            auth=auth,
            timeout=timeout,
            replay_session=record_replay,
            auth_pool=auth_pool,
            login_report=login_report,
            on_progress=on_progress,
        )
    )
    findings.extend(
        probes.run_forced_browse(
            base_urls,
            browse_paths,
            transport=transport,
            engine=engine,
            auth=auth,
            timeout=timeout,
            replay_session=record_replay,
            auth_pool=auth_pool,
        )
    )
    stats["findings"] = len(findings)
    return findings, stats
