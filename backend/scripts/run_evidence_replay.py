#!/usr/bin/env python3
"""Re-run evidence capture for replayable diagnosis findings."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services import diagnosis_service  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="ARGUS evidence replay (Playwright screenshots)")
    parser.add_argument("section_id", help="Guideline section, e.g. 2-2")
    parser.add_argument("--finding-id", help="Replay one finding only")
    parser.add_argument("--list", action="store_true", help="List replayable findings")
    parser.add_argument("--no-playwright", action="store_true", help="HTTP replay only, skip screenshots")
    args = parser.parse_args()

    if args.list:
        rows = diagnosis_service.list_replay_findings(args.section_id)
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    results = diagnosis_service.run_replay(
        args.section_id,
        finding_id=args.finding_id,
        use_playwright=not args.no_playwright,
    )
    print(json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2))
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
