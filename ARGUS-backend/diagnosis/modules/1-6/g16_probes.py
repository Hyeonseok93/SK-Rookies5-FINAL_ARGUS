"""Embedded W16 engine runner for diagnosis 1-6."""

from __future__ import annotations

import subprocess
import sys
import time
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from g16_auth import redact_roles
from g16_inventory import login_override
from g16_targets import EngineTarget
from inventory.net import probe_base_url

# Config values that carry a base URL and must follow the probe host under Docker.
_URL_OPTION_KEYS = frozenset({"ui_target", "login_target"})


@dataclass
class ProbeRun:
    returncode: int
    stdout: str
    stderr: str
    command: list[str]


def bool_flag(args: list[str], cfg: dict[str, Any], key: str, flag: str) -> None:
    if bool(cfg.get(key, False)):
        args.append(flag)


def latest_w16_run(output_dir: Path) -> Path | None:
    candidates = [p for p in output_dir.glob("W16_*") if p.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _read_progress(progress_path: Path) -> tuple[int, str, int]:
    if not progress_path.is_file():
        return 0, "", 0
    try:
        lines = progress_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0, "", 0
    lines = [line for line in lines if line.strip()]
    seen_endpoints: set[tuple[str, str]] = set()
    for line in lines:
        parts = line.split("|")
        if len(parts) >= 3:
            seen_endpoints.add((parts[1].lower(), parts[2]))
    return len(lines), lines[-1] if lines else "", len(seen_endpoints)


def _last_progress_parts(last_line: str) -> tuple[str, str, str, str, str] | None:
    parts = last_line.split("|")
    if len(parts) >= 5:
        role, method, path, payload, source = parts[:5]
        return role, method, path, payload, source
    return None


def _progress_message(
    last_line: str,
    *,
    requests_sent: int,
    endpoints_done: int,
    endpoints_total: int,
) -> str:
    parts = _last_progress_parts(last_line)
    prefix = "1-6 scan"
    if endpoints_total > 0:
        prefix = f"1-6 scan {endpoints_done}/{endpoints_total} endpoints"
    if parts is None:
        return f"{prefix}, {requests_sent} requests sent"
    _role, method, path, _payload, _source = parts
    return f"{prefix}, {requests_sent} requests sent - now {method.upper()} {path}"


def _count_openapi_endpoints(api_spec: Path) -> int:
    if not api_spec.is_file() or api_spec.suffix.lower() not in {".json"}:
        return 0
    try:
        raw = json.loads(api_spec.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    methods = {"get", "post", "put", "patch", "delete", "options", "head"}
    total = 0
    for item in (raw.get("paths") or {}).values():
        if not isinstance(item, dict):
            continue
        total += sum(1 for method in item if str(method).lower() in methods)
    return total


def build_command(
    cfg: dict[str, Any],
    engine_target: EngineTarget,
    output_dir: Path,
    roles: list[str],
    data_dir: Path | None = None,
) -> list[str]:
    cmd = [
        str(cfg.get("python") or sys.executable),
        str(engine_target.main_py),
        "--target",
        engine_target.target,
        "--api-spec",
        str(engine_target.api_spec),
        "--output",
        str(output_dir),
        "--roles",
        *roles,
    ]

    effective_cfg = dict(cfg)
    if data_dir is not None:
        for key, value in login_override(data_dir, engine_target.target).items():
            effective_cfg.setdefault(key, value)

    optional_pairs = [
        ("ui_target", "--ui-target"),
        ("login_spec", "--login-spec"),
        ("login_target", "--login-target"),
        ("login_path", "--login-path"),
        ("zap_host", "--zap-host"),
        ("zap_key", "--zap-key"),
    ]
    for key, flag in optional_pairs:
        value = effective_cfg.get(key)
        if value:
            if key.endswith("spec"):
                value_path = Path(str(value))
                if not value_path.is_absolute():
                    value = str(engine_target.engine_root / value_path)
            elif key in _URL_OPTION_KEYS:
                # Docker: keep login/UI targets on the host, not the container.
                value = probe_base_url(str(value))
            cmd.extend([flag, str(value)])

    for key, flag in [
        ("skip_zap", "--skip-zap"),
        ("skip_spider", "--skip-spider"),
        ("skip_selenium", "--skip-selenium"),
    ]:
        bool_flag(cmd, cfg, key, flag)

    if cfg.get("max_requests"):
        cmd.extend(["--max-requests", str(cfg["max_requests"])])
    if cfg.get("max_requests_per_endpoint"):
        cmd.extend(["--max-requests-per-endpoint", str(cfg["max_requests_per_endpoint"])])
    if cfg.get("max_workers"):
        cmd.extend(["--max-workers", str(cfg["max_workers"])])
    return cmd


def run_engine(
    cfg: dict[str, Any],
    engine_target: EngineTarget,
    output_dir: Path,
    roles: list[str],
    data_dir: Path | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> ProbeRun:
    cmd = build_command(cfg, engine_target, output_dir, roles, data_dir=data_dir)
    timeout_sec = int(cfg.get("timeout_sec", 3600))
    endpoints_total = int(cfg.get("endpoints_total") or _count_openapi_endpoints(engine_target.api_spec))
    started_at = time.monotonic()
    stdout_path = output_dir / "w16_engine_stdout.log"
    stderr_path = output_dir / "w16_engine_stderr.log"
    stdout_file = stdout_path.open("w", encoding="utf-8", errors="replace")
    stderr_file = stderr_path.open("w", encoding="utf-8", errors="replace")
    env = os.environ.copy()
    if isinstance(cfg.get("role_login_targets"), dict):
        # Docker: each per-role login base must target the host, not the container.
        role_login_targets = {
            role: probe_base_url(str(base))
            for role, base in cfg["role_login_targets"].items()
        }
        env["ARGUS_ROLE_LOGIN_TARGETS"] = json.dumps(role_login_targets)
    if isinstance(cfg.get("role_login_paths"), dict):
        env["ARGUS_ROLE_LOGIN_PATHS"] = json.dumps(cfg["role_login_paths"])
    proc = subprocess.Popen(
        cmd,
        cwd=str(engine_target.engine_root),
        env=env,
        text=True,
        stdout=stdout_file,
        stderr=stderr_file,
    )
    stdout, stderr = "", ""
    last_count = -1
    last_heartbeat = -1
    while proc.poll() is None:
        elapsed = int(time.monotonic() - started_at)
        if elapsed > timeout_sec:
            proc.kill()
            proc.wait()
            stdout_file.close()
            stderr_file.close()
            stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.is_file() else ""
            stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.is_file() else ""
            raise subprocess.TimeoutExpired(cmd, timeout_sec, output=stdout, stderr=stderr)

        run_dir = latest_w16_run(output_dir)
        if run_dir is not None:
            count, last_line, endpoints_done = _read_progress(run_dir / "temp_progress.txt")
            if progress_callback and count != last_count:
                cap = int(cfg.get("max_requests") or 0)
                update: dict[str, Any] = {
                    "phase": "running",
                    "message": _progress_message(
                        last_line,
                        requests_sent=count,
                        endpoints_done=endpoints_done,
                        endpoints_total=endpoints_total,
                    ),
                    "requests_sent": count,
                    "endpoints_done": endpoints_done,
                    "endpoints_total": endpoints_total,
                }
                if cap > 0:
                    update["requests_cap"] = cap
                    update["percent"] = min(95, max(3, int(count * 95 / cap)))
                elif endpoints_total > 0:
                    update["percent"] = min(95, max(10, int(endpoints_done * 95 / endpoints_total)))
                else:
                    update["percent"] = 10 if count <= 0 else min(95, 10 + (count % 85))
                progress_callback(update)
                last_count = count
            elif progress_callback and count <= 0 and elapsed // 10 != last_heartbeat:
                progress_callback(
                    {
                        "phase": "running",
                        "message": f"1-6 W16 preparing login/ZAP/fuzzing ({elapsed}s)",
                        "requests_sent": 0,
                        "endpoints_done": 0,
                        "endpoints_total": endpoints_total,
                        "percent": min(9, 3 + elapsed // 30),
                    }
                )
                last_heartbeat = elapsed // 10
        elif progress_callback and elapsed // 10 != last_heartbeat:
            progress_callback(
                {
                    "phase": "running",
                    "message": f"1-6 W16 engine starting ({elapsed}s)",
                    "requests_sent": 0,
                    "endpoints_done": 0,
                    "endpoints_total": endpoints_total,
                    "percent": min(8, 3 + elapsed // 30),
                }
            )
            last_heartbeat = elapsed // 10
        time.sleep(1.0)

    proc.wait()
    stdout_file.close()
    stderr_file.close()
    stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.is_file() else ""
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.is_file() else ""
    return ProbeRun(
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        command=redact_roles(cmd),
    )