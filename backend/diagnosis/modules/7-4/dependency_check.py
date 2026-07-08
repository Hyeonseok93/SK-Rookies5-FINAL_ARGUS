"""Software Composition Analysis for 7-4 — multi-format dependency parser.

지원 형식 (자동 감지):
  1. Gradle  — ./gradlew :<mod>:dependencies --configuration runtimeClasspath
  2. Maven   — mvn dependency:tree -Dscope=runtime
  3. pip     — pip freeze  /  requirements.txt  (pinned versions)
  4. npm     — npm ls --all --json  /  package-lock.json (lockfileVersion 1~3)

Flow:
  deps 파일 (txt/json)
    → 형식 자동 감지 → 파서 선택
    → (package_name, version, ecosystem) 목록
    → OSV /v1/querybatch  (ecosystem 별)
    → 취약점 있는 것만 DiagnosisFinding
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path
from typing import Any

from diagnosis.result import DiagnosisFinding

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

# ──────────────────────────────────────────────
# 형식 감지
# ──────────────────────────────────────────────

def _detect_format(text: str, filename: str = "") -> str:
    """파일 내용/이름으로 형식 감지 → 'gradle' | 'maven' | 'pip' | 'npm_json' | 'unknown'."""
    stripped = text.strip()

    # npm ls --json 또는 package-lock.json
    if stripped.startswith("{") and ('"dependencies"' in stripped or '"packages"' in stripped or '"name"' in stripped):
        return "npm_json"

    lines = [l for l in stripped.splitlines() if l.strip()]
    first = lines[0] if lines else ""

    # Maven: [INFO] 접두어 + maven-dependency-plugin
    if any("[INFO]" in l for l in lines[:20]):
        return "maven"

    # Gradle: 트리 문자 +--- / \---
    if any(re.search(r"[+\\]\-{3}", l) for l in lines[:30]):
        return "gradle"

    # pip: package==version 또는 package>=version
    pip_like = sum(1 for l in lines[:20] if re.match(r"^[A-Za-z0-9_.\\-]+(==|>=|<=|~=|!=)", l.strip()))
    if pip_like >= max(1, len(lines[:20]) // 3):
        return "pip"

    # 파일명 힌트
    fname = filename.lower()
    if "requirements" in fname:
        return "pip"
    if "package-lock" in fname or "package.json" in fname:
        return "npm_json"
    if "pom" in fname:
        return "maven"

    return "unknown"


# ──────────────────────────────────────────────
# 파서 1: Gradle
# ──────────────────────────────────────────────

_GRADLE_COORD_RE = re.compile(r"([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)")


def parse_gradle_dependencies(text: str) -> list[tuple[str, str, str]]:
    """gradle dependency-tree → [(group:artifact, version, 'Maven')] (중복 제거)."""
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # 트리 프리픽스(+---, \---, |    등) 제거
        cleaned = re.sub(r"^[\s|+\\\-]+", "", line)
        if not cleaned or cleaned.startswith("project "):
            continue
        # (*) 재귀 생략 마커, (c) 제약(constraint) 마커는 좌표 자체가 아니므로
        # 줄 전체를 버리지 않고 마커만 제거한 뒤 계속 진행
        cleaned = re.sub(r"\s*\((?:\*|c)\)\s*$", "", cleaned).strip()
        if not cleaned:
            continue

        if "->" in cleaned:
            # a:b:1.0 -> 2.0 -> 3.0 처럼 화살표가 여러 번 나올 수 있으므로
            # 가장 마지막 화살표 뒤 값을 최종 강제(resolved) 버전으로 사용
            parts = [p.strip() for p in cleaned.split("->")]
            left = parts[0]
            ver = ""
            for p in reversed(parts[1:]):
                if p:
                    ver = p.split()[0]
                    break
            ga_m = re.match(r"([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+)", left)
            if ga_m and re.match(r"^[0-9]", ver):
                key = (ga_m.group(1), ver)
                if key not in seen:
                    seen.add(key)
                    result.append((key[0], key[1], "Maven"))
                continue

        m = _GRADLE_COORD_RE.match(cleaned)
        if m:
            key = (m.group(1), m.group(2))
            if key not in seen:
                seen.add(key)
                result.append((key[0], key[1], "Maven"))
    return result

# ──────────────────────────────────────────────
# 파서 2: Maven
# ──────────────────────────────────────────────

# [INFO] +- groupId:artifactId:jar:version:scope
# [INFO] \- groupId:artifactId:jar:version:scope (test → skip)
_MVN_DEP_RE = re.compile(
    r"\[INFO\][\s|+\\\-]+([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+):[A-Za-z0-9_.\-]+:([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)"
)
_SKIP_SCOPES = {"test", "provided", "system"}


def parse_maven_dependencies(text: str) -> list[tuple[str, str, str]]:
    """mvn dependency:tree 출력 → [(group:artifact, version, 'Maven')] (test 스코프 제외)."""
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        m = _MVN_DEP_RE.search(line)
        if not m:
            continue
        ga, ver, scope = m.group(1), m.group(2), m.group(3).lower()
        if scope in _SKIP_SCOPES:
            continue
        key = (ga, ver)
        if key not in seen:
            seen.add(key)
            result.append((ga, ver, "Maven"))
    return result


# ──────────────────────────────────────────────
# 파서 3: pip
# ──────────────────────────────────────────────

# pip freeze: Package==1.2.3  또는 Package==1.2.3+local
# requirements.txt: Package>=1.2.3, Package~=1.2.3, Package<=1.2.3 등도 지원
# (단, ==가 아닌 경우 "명시된 최소/기준 버전"일 뿐 실제 설치 버전과 다를 수 있음)
_PIP_RE = re.compile(
    r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|<=|~=)\s*([A-Za-z0-9_.\-+]+)"
)
_PIP_SKIP_PREFIXES = ("#", "-r ", "-c ", "git+", "http://", "https://")


def parse_pip_dependencies(text: str) -> list[tuple[str, str, str]]:
    """pip freeze / requirements.txt → [(package, version, 'PyPI')] (중복 제거).

    ==, >=, <=, ~= 를 모두 인식한다. ==가 아닌 경우 정확한 설치 버전이 아니라
    파일에 명시된 기준 버전으로 스캔하므로, 실제 설치 버전과 다를 수 있다는 점에
    주의가 필요하다 (정확도를 높이려면 `pip freeze` 결과를 사용할 것).
    """
    seen: set[str] = set()
    result: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()  # 인라인 주석 제거
        if not stripped or any(stripped.startswith(p) for p in _PIP_SKIP_PREFIXES):
            continue
        m = _PIP_RE.match(stripped)
        if m:
            pkg, ver = m.group(1), m.group(3)
            # "Django>=3.2,<4.0" 처럼 여러 조건이 붙은 경우 첫 조건의 버전만 사용
            ver = ver.split(",")[0].split("+")[0]
            name_lower = pkg.lower()
            if name_lower not in seen:
                seen.add(name_lower)
                result.append((pkg, ver, "PyPI"))
    return result


# ──────────────────────────────────────────────
# 파서 4: npm (npm ls --json / package-lock.json)
# ──────────────────────────────────────────────

def _extract_npm_deps(obj: Any, seen: set[tuple[str, str]], result: list[tuple[str, str, str]]) -> None:
    """재귀적으로 npm 의존성 추출 (lockfileVersion 1~3 + npm ls --json 공통)."""
    if not isinstance(obj, dict):
        return
    # lockfileVersion 1/2: {"dependencies": {"name": {"version": "x.y.z", ...}}}
    for key in ("dependencies", "packages"):
        deps = obj.get(key)
        if not isinstance(deps, dict):
            continue
        for pkg_key, pkg_val in deps.items():
            if not isinstance(pkg_val, dict):
                continue
            # lockfileVersion 3 packages 키는 "node_modules/name" 형태
            name = pkg_key.lstrip("/")
            if name.startswith("node_modules/"):
                name = name[len("node_modules/"):]
            if not name:
                continue
            ver = str(pkg_val.get("version") or "").strip()
            if not ver or ver.startswith("file:") or ver.startswith("link:"):
                continue
            # dev dep 제외
            if pkg_val.get("dev") or pkg_val.get("devDependency"):
                continue
            key_t = (name, ver)
            if key_t not in seen:
                seen.add(key_t)
                result.append((name, ver, "npm"))
            # 재귀 (lockfileVersion 1 nested deps)
            _extract_npm_deps(pkg_val, seen, result)


def parse_npm_dependencies(text: str) -> list[tuple[str, str, str]]:
    """npm ls --json / package-lock.json → [(name, version, 'npm')] (dev 제외)."""
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str, str]] = []
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return result
    _extract_npm_deps(obj, seen, result)
    return result


# ──────────────────────────────────────────────
# 통합 파서 (자동 감지)
# ──────────────────────────────────────────────

def parse_dependencies(text: str, filename: str = "") -> tuple[list[tuple[str, str, str]], str]:
    """형식 자동 감지 후 파싱 → ([(name, version, ecosystem)], detected_format)."""
    fmt = _detect_format(text, filename)
    if fmt == "gradle":
        return parse_gradle_dependencies(text), "gradle"
    if fmt == "maven":
        return parse_maven_dependencies(text), "maven"
    if fmt == "pip":
        return parse_pip_dependencies(text), "pip"
    if fmt == "npm_json":
        return parse_npm_dependencies(text), "npm"
    # unknown: Gradle 파서로 시도 후 안 되면 pip 시도
    coords = parse_gradle_dependencies(text)
    if coords:
        return coords, "gradle(fallback)"
    coords = parse_pip_dependencies(text)
    if coords:
        return coords, "pip(fallback)"
    return [], "unknown"


# ──────────────────────────────────────────────
# OSV 쿼리 (ecosystem 별)
# ──────────────────────────────────────────────

def _osv_batch_query(
    coords: list[tuple[str, str, str]], *, timeout: float = 20.0
) -> list[list[str]]:
    """OSV querybatch → 각 coord 에 대한 취약점 id 목록(같은 순서)."""
    queries = [
        {"package": {"ecosystem": ecosystem, "name": name}, "version": ver}
        for name, ver, ecosystem in coords
    ]
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    out: list[list[str]] = []
    for entry in data.get("results", []):
        vulns = entry.get("vulns") or []
        out.append([v.get("id") for v in vulns if v.get("id")])
    while len(out) < len(coords):
        out.append([])
    return out


def _osv_severity(vuln_id: str, *, timeout: float = 10.0) -> tuple[str, str]:
    """개별 취약점 상세 조회 → (severity, summary). 실패 시 medium."""
    try:
        with urllib.request.urlopen(OSV_VULN_URL + vuln_id, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except Exception:
        return "medium", ""
    summary = str(data.get("summary") or data.get("details") or "")[:200]
    score = None
    for sev in data.get("severity", []) or []:
        s = str(sev.get("score", ""))
        try:
            score = float(s)
        except (ValueError, TypeError):
            pass
    db = data.get("database_specific") or {}
    sev_label = str(db.get("severity", "")).lower()
    if score is not None:
        if score >= 9.0:
            return "high", summary
        if score >= 7.0:
            return "high", summary
        if score >= 4.0:
            return "medium", summary
        return "low", summary
    if "critical" in sev_label or "high" in sev_label:
        return "high", summary
    if "moderate" in sev_label or "medium" in sev_label:
        return "medium", summary
    if "low" in sev_label:
        return "low", summary
    return "medium", summary


# ──────────────────────────────────────────────
# 메인 진단 함수
# ──────────────────────────────────────────────

def scan_gradle_dependency_files(
    dep_files: list[Path],
    *,
    label: str = "deps",
    detail_lookup: bool = True,
    on_progress: Any | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    """여러 형식의 의존성 파일을 파싱해 CVE를 조회한다.

    지원 형식: Gradle / Maven / pip / npm (자동 감지).
    """
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "dependency_files": 0,
        "formats_detected": [],
        "components": 0,
        "vulnerable_components": 0,
        "total_cves": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "osv_error": None,
    }

    coords: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for path in dep_files:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        stats["dependency_files"] += 1
        parsed, fmt = parse_dependencies(text, filename=Path(path).name)
        if fmt not in stats["formats_detected"]:
            stats["formats_detected"].append(fmt)
        for item in parsed:
            if item not in seen:
                seen.add(item)
                coords.append(item)

    stats["components"] = len(coords)
    if not coords:
        return findings, stats

    try:
        vuln_lists = _osv_batch_query(coords)
    except Exception as exc:
        stats["osv_error"] = str(exc)[:200]
        return findings, stats

    for (name, ver, ecosystem), vuln_ids in zip(coords, vuln_lists):
        if not vuln_ids:
            continue
        stats["vulnerable_components"] += 1
        stats["total_cves"] += len(vuln_ids)

        worst = "low"
        summaries: list[str] = []
        cve_details: list[dict[str, str]] = []
        for vid in vuln_ids[:10]:
            if detail_lookup:
                sev, summary = _osv_severity(vid)
            else:
                sev, summary = "medium", ""
            cve_details.append({"id": vid, "severity": sev, "summary": summary})
            if summary:
                summaries.append(f"{vid}: {summary}")
            order = {"low": 0, "medium": 1, "high": 2}
            if order[sev] > order[worst]:
                worst = sev

        stats["by_severity"][worst] += 1
        if on_progress:
            on_progress(endpoint_id=name)

        label_str = f"[{ecosystem}] {name}:{ver}"
        findings.append(
            DiagnosisFinding(
                severity=worst,
                message=(
                    f"[7-4] Vulnerable dependency: {name}:{ver} "
                    f"({len(vuln_ids)} known CVE(s)) [{ecosystem}]"
                ),
                evidence={
                    "rule_id": "7-4-weak-security",
                    "source": "sca",
                    "engine": "osv",
                    "check_type": "vulnerable_dependency",
                    "ecosystem": ecosystem,
                    "reason": f"{name}:{ver} has {len(vuln_ids)} known vulnerability(ies)",
                    "component": name,
                    "version": ver,
                    "base_url": label_str,
                    "url": label_str,
                    "label": label_str,
                    "cve_ids": vuln_ids,
                    "cve_details": cve_details,
                    "evidence_summary": " | ".join(summaries[:3]),
                    "remediation": (
                        f"Upgrade {name} to a fixed version; "
                        f"review advisories: {', '.join(vuln_ids[:5])}"
                    ),
                },
            )
        )

    return findings, stats