"""2-2 evidence 폴더에서 PNG 샷을 읽고 한글 라벨을 붙인다."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

SHOT_LABELS: dict[str, str] = {
    "main_site": "메인 화면",
    "logged_in_main": "로그인 후 메인",
    "feature_page": "기능 페이지",
    "baseline_evidence": "Baseline 요청/응답",
    "attack_evidence": "Attack 요청/응답",
    "auth_evidence": "인증 세션 증거",
    "anon_evidence": "비로그인 증거",
    "ui_result": "UI 결과",
    "file_compare": "파일 내용 비교",
}

_KIND_FROM_NAME = re.compile(
    r"^(?:\d{2}_)?(?P<kind>[a-z0-9_]+?)(?:_\d+)?\.(?:png|jpe?g|webp)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class EvidenceShot:
    kind: str
    label: str
    path: Path


def shot_label(kind: str) -> str:
    return SHOT_LABELS.get(kind, kind)


def _kind_from_filename(name: str) -> str:
    m = _KIND_FROM_NAME.match(name)
    if not m:
        return Path(name).stem
    return m.group("kind")


def load_shots_for_finding(evidence_root: Path, finding_id: str) -> list[EvidenceShot]:
    """evidence/{finding_id}/*.png 를 파일명 순으로 반환."""
    folder = evidence_root / finding_id
    if not folder.is_dir():
        return []

    ordered: list[EvidenceShot] = []
    seen: set[Path] = set()
    manifest_path = folder / "manifest.json"
    if manifest_path.is_file():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            data = {}
        artifacts = data.get("artifacts") if isinstance(data, dict) else None
        if isinstance(artifacts, list):
            for item in artifacts:
                if not isinstance(item, dict):
                    continue
                raw = str(item.get("path") or "").strip()
                if not raw:
                    continue
                candidate = Path(raw)
                local = folder / candidate.name
                if not local.is_file():
                    rel = raw.replace("\\", "/")
                    marker = f"/{finding_id}/"
                    idx = rel.find(marker)
                    if idx >= 0:
                        local = evidence_root / finding_id / rel[idx + len(marker) :]
                if not local.is_file():
                    continue
                kind = str(item.get("kind") or _kind_from_filename(local.name))
                ordered.append(EvidenceShot(kind=kind, label=shot_label(kind), path=local.resolve()))
                seen.add(local.resolve())

    extras: list[EvidenceShot] = []
    for png in sorted(folder.glob("*.png")):
        resolved = png.resolve()
        if resolved in seen:
            continue
        kind = _kind_from_filename(png.name)
        extras.append(EvidenceShot(kind=kind, label=shot_label(kind), path=resolved))
    return ordered + extras
