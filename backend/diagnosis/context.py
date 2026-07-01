"""Runtime context passed to each diagnosis module."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DiagnosisContext:
    data_dir: Path
    config: dict[str, Any] = field(default_factory=dict)
    raw_config: dict[str, Any] = field(default_factory=dict)
