"""Run section-specific screenshot capture after a diagnosis report is saved."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import BACKEND_ROOT
from diagnosis.paths import section_evidence_dir, section_report_path

_AUTO_CAPTURE_SECTIONS = frozenset({"1-2", "1-5", "2-2", "7-4"})
_CAPTURE_TIMEOUT_SECONDS = 300


def supports(section_id: str) -> bool:
    return section_id in _AUTO_CAPTURE_SECTIONS


def capture_after_diagnosis(section_id: str, data_dir: Path) -> dict[str, Any]:
    """Capture evidence synchronously; never turn a valid diagnosis into a failure."""
    if not supports(section_id):
        return {"attempted": False, "ok": True}

    script = BACKEND_ROOT / "screenshot" / "modules" / section_id / "capture.py"
    report = section_report_path(data_dir, section_id)
    output = section_evidence_dir(data_dir, section_id)
    output.mkdir(parents=True, exist_ok=True)
    error_path = output / "capture-error.json"

    if not script.is_file() or not report.is_file():
        missing = script if not script.is_file() else report
        result = {
            "attempted": False,
            "ok": False,
            "error": f"Required capture input is missing: {missing}",
        }
        _write_error(error_path, section_id, result["error"])
        return result

    command = [
        sys.executable,
        str(script),
        "--report",
        str(report),
        "--output",
        str(output),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=BACKEND_ROOT,
            capture_output=True,
            text=True,
            timeout=_CAPTURE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        error = f"{type(exc).__name__}: {exc}"
        _write_error(error_path, section_id, error)
        return {"attempted": True, "ok": False, "error": error}

    if completed.returncode != 0:
        error = (completed.stderr or completed.stdout or "capture failed").strip()[-4000:]
        _write_error(error_path, section_id, error)
        return {
            "attempted": True,
            "ok": False,
            "returncode": completed.returncode,
            "error": error,
        }

    error_path.unlink(missing_ok=True)
    return {"attempted": True, "ok": True}


def _write_error(path: Path, section_id: str, error: str) -> None:
    path.write_text(
        json.dumps(
            {
                "section_id": section_id,
                "ok": False,
                "error": error,
                "captured_at": datetime.now(UTC).isoformat(),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
