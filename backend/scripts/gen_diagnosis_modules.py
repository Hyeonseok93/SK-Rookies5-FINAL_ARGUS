"""Generate diagnosis module shells (1-1 … 8-1)."""

from __future__ import annotations

from pathlib import Path

from diagnosis.catalog import SECTIONS

MODULES_DIR = Path(__file__).resolve().parent.parent / "diagnosis" / "modules"

MANIFEST_TPL = """id: "{id}"
title: "{title}"
chapter: {chapter}
implemented: false
engine: pending
"""

MODULE_PY = '''"""Diagnosis module {id}: {title}"""

from pathlib import Path

from diagnosis.base import StubDiagnosisModule

_module_dir = Path(__file__).resolve().parent
module = StubDiagnosisModule.from_manifest(_module_dir / "manifest.yaml")
'''


def main() -> None:
    for entry in SECTIONS:
        section_id = entry["id"]
        module_dir = MODULES_DIR / section_id
        module_dir.mkdir(parents=True, exist_ok=True)
        (module_dir / "manifest.yaml").write_text(MANIFEST_TPL.format(**entry), encoding="utf-8")
        (module_dir / "module.py").write_text(
            MODULE_PY.format(id=section_id, title=entry["title"]),
            encoding="utf-8",
        )
        assets = module_dir / "assets"
        assets.mkdir(exist_ok=True)
        (assets / ".gitkeep").write_text("", encoding="utf-8")
        print(f"created {section_id}")
    print(f"total {len(SECTIONS)}")


if __name__ == "__main__":
    main()
