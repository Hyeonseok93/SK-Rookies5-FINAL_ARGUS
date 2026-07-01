"""Discover and register all guideline diagnosis modules."""

from __future__ import annotations

import importlib.util
from functools import lru_cache
from pathlib import Path

from diagnosis.base import DiagnosisModule
from diagnosis.catalog import SECTIONS

MODULES_DIR = Path(__file__).resolve().parent / "modules"


def _load_module_from_dir(module_dir: Path) -> DiagnosisModule:
    module_py = module_dir / "module.py"
    if not module_py.is_file():
        raise FileNotFoundError(f"Missing module.py: {module_py}")
    module_name = f"diagnosis_module_{module_dir.name.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, module_py)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load diagnosis module: {module_py}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    instance = getattr(mod, "module", None)
    if instance is None:
        raise RuntimeError(f"{module_py} must export `module`")
    return instance


@lru_cache
def get_modules() -> dict[str, DiagnosisModule]:
    registered: dict[str, DiagnosisModule] = {}
    for entry in SECTIONS:
        section_id = entry["id"]
        module_dir = MODULES_DIR / section_id
        if not module_dir.is_dir():
            continue
        registered[section_id] = _load_module_from_dir(module_dir)
    return registered


def get_module(section_id: str) -> DiagnosisModule | None:
    return get_modules().get(section_id)


def module_dir(section_id: str) -> Path:
    return MODULES_DIR / section_id


def list_registered_ids() -> list[str]:
    return sorted(get_modules().keys())
