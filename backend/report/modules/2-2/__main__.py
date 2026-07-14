"""CLI: python path/to/__main__.py  or  python -m report"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_DIR = Path(__file__).resolve().parent
_BACKEND = _DIR.parents[2]  # .../backend
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))

from generate import build_pdf


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate ARGUS 2-2 PDF report")
    default_report = _BACKEND / "data" / "report" / "2-2"
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=default_report,
        help="Directory containing latest.yaml and evidence/ (default: data/report/2-2)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output PDF path (default: <report-dir>/result.pdf)",
    )
    args = parser.parse_args(argv)
    out = build_pdf(args.report_dir, args.out)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
