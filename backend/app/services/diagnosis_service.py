"""Orchestrate guideline diagnosis modules (1-1 … 8-1)."""

from __future__ import annotations

from pathlib import Path

from app.config import BACKEND_ROOT, load_config, config_to_inventory_dict
from diagnosis.catalog import SECTION_BY_ID, SECTIONS
from diagnosis.context import DiagnosisContext
from diagnosis.registry import get_module, get_modules, list_registered_ids
from diagnosis.result import SectionReport


def _context(raw_overrides: dict | None = None) -> DiagnosisContext:
    cfg = load_config()
    import os
    import yaml

    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (BACKEND_ROOT / "config.yaml")
    raw: dict = {}
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    if raw_overrides:
        if "diagnosis_2_2" in raw_overrides:
            base_g22 = dict(raw.get("diagnosis_2_2") or {})
            base_g22.update(raw_overrides["diagnosis_2_2"])
            raw = {**raw, "diagnosis_2_2": base_g22}
        elif "diagnosis_7_3" in raw_overrides:
            base_g73 = dict(raw.get("diagnosis_7_3") or {})
            base_g73.update(raw_overrides["diagnosis_7_3"])
            raw = {**raw, "diagnosis_7_3": base_g73}
        elif "diagnosis_7_1" in raw_overrides:
            base_g71 = dict(raw.get("diagnosis_7_1") or {})
            base_g71.update(raw_overrides["diagnosis_7_1"])
            raw = {**raw, "diagnosis_7_1": base_g71}
        elif "diagnosis_7_2" in raw_overrides:
            base_g72 = dict(raw.get("diagnosis_7_2") or {})
            base_g72.update(raw_overrides["diagnosis_7_2"])
            raw = {**raw, "diagnosis_7_2": base_g72}
        elif "diagnosis_7_4" in raw_overrides:
            base_g74 = dict(raw.get("diagnosis_7_4") or {})
            base_g74.update(raw_overrides["diagnosis_7_4"])
            raw = {**raw, "diagnosis_7_4": base_g74}
        elif "diagnosis_5_2" in raw_overrides:
            base_g52 = dict(raw.get("diagnosis_5_2") or {})
            base_g52.update(raw_overrides["diagnosis_5_2"])
            raw = {**raw, "diagnosis_5_2": base_g52}
        elif "diagnosis_6_1" in raw_overrides:
            base_g61 = dict(raw.get("diagnosis_6_1") or {})
            base_g61.update(raw_overrides["diagnosis_6_1"])
            raw = {**raw, "diagnosis_6_1": base_g61}
        elif "diagnosis_6_2" in raw_overrides:
            base_g62 = dict(raw.get("diagnosis_6_2") or {})
            base_g62.update(raw_overrides["diagnosis_6_2"])
            raw = {**raw, "diagnosis_6_2": base_g62}
        elif "diagnosis_3_6" in raw_overrides:
            base_g36 = dict(raw.get("diagnosis_3_6") or {})
            base_g36.update(raw_overrides["diagnosis_3_6"])
            raw = {**raw, "diagnosis_3_6": base_g36}
        elif "diagnosis_3_5" in raw_overrides:
            base_g35 = dict(raw.get("diagnosis_3_5") or {})
            base_g35.update(raw_overrides["diagnosis_3_5"])
            raw = {**raw, "diagnosis_3_5": base_g35}
        elif "diagnosis_3_2" in raw_overrides:
            base_g32 = dict(raw.get("diagnosis_3_2") or {})
            base_g32.update(raw_overrides["diagnosis_3_2"])
            raw = {**raw, "diagnosis_3_2": base_g32}
        elif "diagnosis_1_5" in raw_overrides:
            base_g15 = dict(raw.get("diagnosis_1_5") or {})
            base_g15.update(raw_overrides["diagnosis_1_5"])
            raw = {**raw, "diagnosis_1_5": base_g15}
        elif "diagnosis_4_1" in raw_overrides:
            base_g41 = dict(raw.get("diagnosis_4_1") or {})
            base_g41.update(raw_overrides["diagnosis_4_1"])
            raw = {**raw, "diagnosis_4_1": base_g41}
        else:
            raw = {**raw, **raw_overrides}

    return DiagnosisContext(
        data_dir=BACKEND_ROOT / "data",
        config=config_to_inventory_dict(cfg),
        raw_config=raw,
    )


def catalog() -> list[dict]:
    registered = set(list_registered_ids())
    items: list[dict] = []
    for entry in SECTIONS:
        section_id = entry["id"]
        mod = get_module(section_id)
        items.append(
            {
                "id": section_id,
                "title": entry["title"],
                "chapter": entry["chapter"],
                "registered": section_id in registered,
                "implemented": bool(mod.implemented) if mod else False,
                "diagnosable": bool(getattr(mod, "diagnosable", True)) if mod else True,
                "review_later": bool(getattr(mod, "review_later", False)) if mod else False,
                "status_label": getattr(mod, "status_label", None) if mod else None,
                "engine": mod.engine if mod else "missing",
            }
        )
    return items


def get_report(section_id: str) -> SectionReport | None:
    if section_id not in SECTION_BY_ID:
        return None
    mod = get_module(section_id)
    if mod is None:
        return None
    ctx = _context()
    return mod.load_report(ctx)


def run_section(
    section_id: str,
    *,
    g22_options: dict | None = None,
    g71_options: dict | None = None,
    g73_options: dict | None = None,
    g72_options: dict | None = None,
    g74_options: dict | None = None,
    g52_options: dict | None = None,
    g61_options: dict | None = None,
    g62_options: dict | None = None,
    g36_options: dict | None = None,
    g35_options: dict | None = None,
    g32_options: dict | None = None,
    g15_options: dict | None = None,
    g41_options: dict | None = None,
) -> SectionReport:
    if section_id not in SECTION_BY_ID:
        raise KeyError(f"Unknown section: {section_id}")
    mod = get_module(section_id)
    if mod is None:
        raise RuntimeError(f"Module not registered: {section_id}")
    if not getattr(mod, "diagnosable", True):
        raise ValueError(f"Section {section_id} is not diagnosable automatically")

    overrides: dict | None = None
    if g22_options and section_id == "2-2":
        overrides = {"diagnosis_2_2": {k: v for k, v in g22_options.items() if v is not None}}
    elif g71_options and section_id == "7-1":
        overrides = {"diagnosis_7_1": {k: v for k, v in g71_options.items() if v is not None}}
    elif g73_options and section_id == "7-3":
        overrides = {"diagnosis_7_3": {k: v for k, v in g73_options.items() if v is not None}}
    elif g72_options and section_id == "7-2":
        overrides = {"diagnosis_7_2": {k: v for k, v in g72_options.items() if v is not None}}
    elif g74_options and section_id == "7-4":
        overrides = {"diagnosis_7_4": {k: v for k, v in g74_options.items() if v is not None}}
    elif g52_options and section_id == "5-2":
        overrides = {"diagnosis_5_2": {k: v for k, v in g52_options.items() if v is not None}}
    elif g61_options and section_id == "6-1":
        overrides = {"diagnosis_6_1": {k: v for k, v in g61_options.items() if v is not None}}
    elif g62_options and section_id == "6-2":
        overrides = {"diagnosis_6_2": {k: v for k, v in g62_options.items() if v is not None}}
    elif g36_options and section_id == "3-6":
        overrides = {"diagnosis_3_6": {k: v for k, v in g36_options.items() if v is not None}}
    elif g35_options and section_id == "3-5":
        overrides = {"diagnosis_3_5": {k: v for k, v in g35_options.items() if v is not None}}
    elif g32_options and section_id == "3-2":
        overrides = {"diagnosis_3_2": {k: v for k, v in g32_options.items() if v is not None}}
    elif g15_options and section_id == "1-5":
        overrides = {"diagnosis_1_5": {k: v for k, v in g15_options.items() if v is not None}}
    elif g41_options and section_id == "4-1":
        overrides = {"diagnosis_4_1": {k: v for k, v in g41_options.items() if v is not None}}

    ctx = _context(overrides)
    from app.services import diagnosis_progress as dp

    dp.reset(section_id=section_id, message=f"Running {section_id}…")
    try:
        report = mod.run(ctx)
    except Exception as exc:
        dp.fail(str(exc)[:300])
        raise
    dp.finish(f"{section_id}: {report.status}")
    return report


def run_all() -> list[SectionReport]:
    ctx = _context()
    reports: list[SectionReport] = []
    for section_id in sorted(get_modules().keys()):
        mod = get_modules()[section_id]
        if not getattr(mod, "diagnosable", True):
            continue
        reports.append(mod.run(ctx))
    return reports


def list_replay_findings(section_id: str) -> list[dict]:
    from diagnosis.replay.service import list_replayable_findings

    if section_id not in SECTION_BY_ID:
        raise KeyError(f"Unknown section: {section_id}")
    return list_replayable_findings(section_id)


def run_replay(section_id: str, *, finding_id: str | None = None, use_playwright: bool = True) -> list:
    from diagnosis.replay.service import run_section_replay

    if section_id not in SECTION_BY_ID:
        raise KeyError(f"Unknown section: {section_id}")

    import os
    import yaml
    from app.config import BACKEND_ROOT

    env_path = os.environ.get("CONFIG_PATH")
    config_path = Path(env_path) if env_path else (BACKEND_ROOT / "config.yaml")
    raw: dict = {}
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    return run_section_replay(
        section_id,
        finding_id=finding_id,
        raw_config=raw,
        use_playwright=use_playwright,
    )
