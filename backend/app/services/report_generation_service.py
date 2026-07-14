"""Generate and resolve section-specific final diagnosis reports."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import BACKEND_ROOT
from diagnosis.paths import section_evidence_dir, section_report_path


_REPORT_TIMEOUT_SECONDS = 300


def _generator_path(section_id: str) -> Path:
    return BACKEND_ROOT / "report" / "modules" / section_id / "generate.py"


def supports(section_id: str) -> bool:
    """Return true when a report generator exists for the section."""
    return _generator_path(section_id).is_file()


def generate_after_capture(section_id: str, data_dir: Path) -> dict[str, Any]:
    """Generate a final report without turning a valid diagnosis into a failure."""
    script = _generator_path(section_id)
    if not script.is_file():
        return {"attempted": False, "ok": True}

    source_report = section_report_path(data_dir, section_id)
    evidence_dir = section_evidence_dir(data_dir, section_id)
    output_dir = data_dir / "report" / section_id / "final"
    output_dir.mkdir(parents=True, exist_ok=True)
    error_path = output_dir / "report-error.json"

    if not source_report.is_file() or not evidence_dir.is_dir():
        missing = source_report if not source_report.is_file() else evidence_dir
        error = f"Required report input is missing: {missing}"
        _write_error(error_path, section_id, error)
        return {"attempted": False, "ok": False, "error": error}

    command = [
        sys.executable,
        str(script),
        "--report",
        str(source_report),
        "--evidence",
        str(evidence_dir),
        "--output",
        str(output_dir),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=BACKEND_ROOT,
            capture_output=True,
            text=True,
            timeout=_REPORT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        error = f"{type(exc).__name__}: {exc}"
        _write_error(error_path, section_id, error)
        return {"attempted": True, "ok": False, "error": error}

    if completed.returncode != 0:
        error = (completed.stderr or completed.stdout or "report generation failed").strip()[-4000:]
        _write_error(error_path, section_id, error)
        return {
            "attempted": True,
            "ok": False,
            "returncode": completed.returncode,
            "error": error,
        }

    error_path.unlink(missing_ok=True)
    try:
        result = json.loads(completed.stdout)
    except ValueError:
        result = {"ok": True}
    return {"attempted": True, **result}


def resolve_report_file(section_id: str, filename: str, data_dir: Path | None = None) -> Path | None:
    """Resolve an allow-listed generated artifact below the section final directory."""
    allowed = {"report.html", "report.pdf", "report-data.json", "report-manifest.json"}
    if filename not in allowed:
        return None
    root_data = data_dir or (BACKEND_ROOT / "data")
    root = (root_data / "report" / section_id / "final").resolve()
    target = (root / filename).resolve()
    if target.parent != root or not target.is_file():
        return None
    return target


def _write_error(path: Path, section_id: str, error: str) -> None:
    path.write_text(
        json.dumps(
            {
                "section_id": section_id,
                "ok": False,
                "error": error,
                "generated_at": datetime.now(UTC).isoformat(),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
