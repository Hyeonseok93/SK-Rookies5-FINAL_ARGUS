"""CLI and orchestration entry point for the ARGUS 7-4 final report."""

from __future__ import annotations

import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from builder import build_report  # noqa: E402
from pdf_exporter import export_pdf  # noqa: E402
from renderer import render_html  # noqa: E402


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(text, encoding="utf-8")
    temp.replace(path)


def generate_report(
    report_path: Path,
    evidence_dir: Path,
    output_dir: Path,
    *,
    include_pdf: bool = True,
) -> dict[str, Any]:
    document = build_report(report_path, evidence_dir)
    html = render_html(document)
    output_dir.mkdir(parents=True, exist_ok=True)
    data_path, html_path, pdf_path = (
        output_dir / "report-data.json",
        output_dir / "report.html",
        output_dir / "report.pdf",
    )
    _write_text_atomic(data_path, json.dumps(document.to_dict(), ensure_ascii=False, indent=2))
    _write_text_atomic(html_path, html)
    if include_pdf:
        export_pdf(html_path, pdf_path)
    elif pdf_path.exists():
        pdf_path.unlink()
    result = {
        "ok": True,
        "section_id": "7-4",
        "report_id": document.report_id,
        "findings": len(document.findings),
        "warnings": document.warnings,
        "artifacts": {
            "data": str(data_path),
            "html": str(html_path),
            "pdf": str(pdf_path) if include_pdf else None,
        },
        "source_sha256": sha256(report_path.read_bytes()).hexdigest(),
    }
    _write_text_atomic(output_dir / "report-manifest.json", json.dumps(result, ensure_ascii=False, indent=2))
    return result


def _backend_root() -> Path:
    return _MODULE_DIR.parents[2]


def main() -> int:
    backend_root = _backend_root()
    parser = argparse.ArgumentParser(description="Generate the ARGUS 7-4 HTML/PDF final report")
    parser.add_argument("--report", type=Path, default=backend_root / "data/report/7-4/latest.yaml")
    parser.add_argument("--evidence", type=Path, default=backend_root / "data/report/7-4/evidence")
    parser.add_argument("--output", type=Path, default=backend_root / "data/report/7-4/final")
    parser.add_argument("--no-pdf", action="store_true")
    args = parser.parse_args()
    try:
        result = generate_report(args.report, args.evidence, args.output, include_pdf=not args.no_pdf)
    except Exception as exc:
        error = {"ok": False, "section_id": "7-4", "error": f"{type(exc).__name__}: {exc}"}
        args.output.mkdir(parents=True, exist_ok=True)
        _write_text_atomic(args.output / "report-error.json", json.dumps(error, ensure_ascii=False, indent=2))
        print(json.dumps(error, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    (args.output / "report-error.json").unlink(missing_ok=True)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

