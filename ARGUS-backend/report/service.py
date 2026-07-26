"""결과서(PDF) 생성 서비스 — report/modules/{section_id}/builder.py 를 로드해 실행

디렉터리 이름('5-2')이 파이썬 식별자가 아니므로 경로 기반으로 동적 임포트
(diagnosis / screenshot 모듈이 쓰는 것과 동일한 패턴)
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_MODULES_DIR = Path(__file__).resolve().parent / "modules"


def _load_builder(section_id: str):
    module_dir = _MODULES_DIR / section_id
    builder_path = module_dir / "builder.py"
    if not builder_path.is_file():
        return None

    pkg_name = f"report_{section_id.replace('-', '_')}"
    # content.py 를 상대 임포트(`from . import content`)로 쓰기 위해 패키지로 등록
    if pkg_name not in sys.modules:
        pkg_spec = importlib.util.spec_from_file_location(
            pkg_name, module_dir / "__init__.py", submodule_search_locations=[str(module_dir)]
        )
        if pkg_spec is None or pkg_spec.loader is None:
            return None
        pkg = importlib.util.module_from_spec(pkg_spec)
        sys.modules[pkg_name] = pkg
        pkg_spec.loader.exec_module(pkg)

    builder_name = f"{pkg_name}.builder"
    spec = importlib.util.spec_from_file_location(builder_name, builder_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[builder_name] = mod
    spec.loader.exec_module(mod)
    return mod


def report_pdf_path(section_id: str, data_dir: Path) -> Path | None:
    """이미 생성된 결과서 PDF 경로(존재 여부와 무관하게 규약 경로)를 반환"""
    builder = _load_builder(section_id)
    if builder is None:
        return None
    return builder.pdf_output_path(data_dir)


def generate_report(section_id: str, data_dir: Path) -> Path | None:
    """섹션 결과서를 생성(덮어쓰기)하고 경로를 반환. 실패 시 None"""
    builder = _load_builder(section_id)
    if builder is None:
        logger.info("결과서 빌더 없음: section_id=%s", section_id)
        return None
    return builder.build_report(data_dir)
