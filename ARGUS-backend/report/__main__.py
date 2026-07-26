"""python -m report  →  generate 2-2 PDF (hyphen folder is not an importable package)."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> None:
    target = Path(__file__).resolve().parent / "modules" / "2-2" / "__main__.py"
    if not target.is_file():
        raise SystemExit(f"missing 2-2 report entry: {target}")
    # Forward argv so argparse in section __main__ still works.
    sys.argv = [str(target), *sys.argv[1:]]
    runpy.run_path(str(target), run_name="__main__")


if __name__ == "__main__":
    main()
