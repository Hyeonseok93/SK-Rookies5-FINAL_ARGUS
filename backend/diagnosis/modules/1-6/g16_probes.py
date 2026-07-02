"""Embedded W16 engine runner for diagnosis 1-6."""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from g16_auth import redact_roles
from g16_targets import EngineTarget


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


def _read_progress(progress_path: Path) -> tuple[int, str]:
    if not progress_path.is_file():
        return 0, ""
    try:
        lines = progress_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0, ""
    lines = [line for line in lines if line.strip()]
    return len(lines), lines[-1] if lines else ""


def _progress_message(last_line: str) -> str:
    parts = last_line.split("|")
    if len(parts) >= 5:
        role, method, path, payload, source = parts[:5]
        return f"1-6 fuzzing {method.upper()} {path} with {payload} ({source}, {role})"
    return "1-6 W16 fuzzing in progress"


def build_command(
    cfg: dict[str, Any],
    engine_target: EngineTarget,
    output_dir: Path,
    roles: list[str],
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

    optional_pairs = [
        ("ui_target", "--ui-target"),
        ("login_spec", "--login-spec"),
        ("login_target", "--login-target"),
        ("login_path", "--login-path"),
        ("zap_host", "--zap-host"),
        ("zap_key", "--zap-key"),
    ]
    for key, flag in optional_pairs:
        value = cfg.get(key)
        if value:
            if key.endswith("spec"):
                value_path = Path(str(value))
                if not value_path.is_absolute():
                    value = str(engine_target.engine_root / value_path)
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
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> ProbeRun:
    cmd = build_command(cfg, engine_target, output_dir, roles)
    timeout_sec = int(cfg.get("timeout_sec", 3600))
    started_at = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        cwd=str(engine_target.engine_root),
        text=True,
        capture_output=True,
    )
    stdout, stderr = "", ""
    last_count = -1
    while proc.poll() is None:
        if time.monotonic() - started_at > timeout_sec:
            proc.kill()
            stdout, stderr = proc.communicate()
            raise subprocess.TimeoutExpired(cmd, timeout_sec, output=stdout, stderr=stderr)

        run_dir = latest_w16_run(output_dir)
        if run_dir is not None:
            count, last_line = _read_progress(run_dir / "temp_progress.txt")
            if progress_callback and count != last_count:
                cap = int(cfg.get("max_requests") or 0)
                update: dict[str, Any] = {
                    "phase": "running",
                    "message": _progress_message(last_line),
                    "requests_sent": count,
                }
                if cap > 0:
                    update["requests_cap"] = cap
                    update["percent"] = min(95, max(3, int(count * 95 / cap)))
                else:
                    update["percent"] = 10 if count <= 0 else min(95, 10 + (count % 85))
                progress_callback(update)
                last_count = count
        time.sleep(1.0)

    stdout, stderr = proc.communicate()
    return ProbeRun(
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        command=redact_roles(cmd),
    )
