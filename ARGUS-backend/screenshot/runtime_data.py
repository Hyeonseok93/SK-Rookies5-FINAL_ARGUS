"""Resolve the active ARGUS workspace for screenshot CLIs/engines."""

from __future__ import annotations

import os
from pathlib import Path


def runtime_data_dir(backend_root: Path | None = None) -> Path:
    env = (os.environ.get("ARGUS_DATA_DIR") or "").strip()
    if env:
        return Path(env)
    if backend_root is not None:
        return backend_root / "data"
    # screenshot/runtime_data.py -> backend root
    return Path(__file__).resolve().parents[1] / "data"
