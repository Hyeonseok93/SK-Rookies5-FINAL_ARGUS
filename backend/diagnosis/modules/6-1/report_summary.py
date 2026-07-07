"""Compact summary for 6-1 reports (avoids shipping 70k+ raw findings to the UI)."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from diagnosis.result import DiagnosisFinding

SUMMARY_VERSION = 4

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}

SK_LABELS: dict[str, str] = {
    "dbms": "DBMS 오류",
    "exception": "익셉션 오류",
    "http": "HTTP/서버 오류",
}

SK_EXPLAIN: dict[str, str] = {
    "dbms": "SQL/DBMS 예외·제품명·제약 조건 등 DB 단서가 응답에 포함됩니다.",
    "exception": "스택 트레이스, 프레임워크 내부, 소스 경로 등 예외 정보가 노출됩니다.",
    "http": "서버 오류 메시지(systemMessage 등), 상세 HTTP 오류 페이지, debug 필드, ZAP 오류 패턴입니다.",
}

CATEGORY_LABELS: dict[str, str] = {
    "database": "DBMS",
    "stack_trace": "스택/예외",
    "path_disclosure": "경로 노출",
    "framework": "프레임워크",
    "verbose_error": "HTTP/서버 오류",
    "zap_error_disclosure": "ZAP HTTP",
}

RULE_LABELS: dict[str, str] = {
    "sql_exception": "SQL 예외 텍스트",
    "db_vendor": "DB 제품명",
    "db_syntax": "DB syntax",
    "db_constraint": "DB constraint",
    "java_stack": "Java 스택",
    "java_caused": "Java Caused by",
    "python_trace": "Python traceback",
    "python_file": "Python source path",
    "php_fatal": "PHP fatal",
    "php_parse": "PHP parse",
    "php_warning": "PHP warning",
    "dotnet_stack": ".NET exception",
    "nested_exception": "Nested exception",
    "spring_framework": "Spring exception",
    "spring_whitelabel": "Spring Whitelabel",
    "hibernate": "Hibernate",
    "tomcat": "Tomcat 기본 오류",
    "verbose_field": "debug/developer 필드",
    "verbose_500": "Verbose 5xx",
    "verbose_500_body": "5xx 상세 본문",
    "json_system_message": "systemMessage 노출",
    "server_error_message": "서버 오류 message",
    "json_error_field": "error 필드 노출",
    "api_error_envelope": "API 오류 envelope",
    "json_trace_field": "JSON trace",
    "json_stack_field": "JSON stack",
    "json_exception_field": "JSON exception",
    "web_server_banner": "웹서버 버전",
    "6-1-zap-90022": "Application Error Disclosure",
    "6-1-zap-10023": "Debug Error Disclosure",
}


def _sk_class(ev: dict[str, Any]) -> str:
    sk = str(ev.get("sk_class") or ev.get("kisa_class") or "").strip().lower()
    if sk in SK_LABELS:
        return sk
    category = str(ev.get("category") or "")
    rule_id = str(ev.get("rule_id") or "")
    if category == "database" or rule_id.startswith("sql_") or rule_id.startswith("db_"):
        return "dbms"
    if category in ("stack_trace", "path_disclosure", "framework"):
        return "exception"
    return "http"


def _origin_label(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return "—"
    try:
        u = urlparse(text if "://" in text else f"http://{text}")
        host = u.hostname or text
        port = u.port
        if port and not ((host == "localhost" and port in (80, 443)) or port in (80, 443)):
            return f"{host}:{port}"
        return host
    except Exception:
        return text.replace("http://", "").replace("https://", "").rstrip("/")


def _field(chunk: str, name: str, *, indent: int = 4) -> str | None:
    m = re.search(rf"^{' ' * indent}{re.escape(name)}: (.+)$", chunk, re.M)
    if not m:
        return None
    val = m.group(1).strip()
    if val in ("''", '""', "null", "~"):
        return None
    if val.startswith("'") and val.endswith("'"):
        return val[1:-1]
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    return val


def _parse_finding_chunk(chunk: str) -> dict[str, Any] | None:
    severity = _field(chunk, "severity", indent=0) or _field(chunk, "severity", indent=2)
    if not severity:
        m = re.match(r"- severity:\s*(\w+)", chunk.strip())
        severity = m.group(1) if m else None
    if not severity:
        return None
    message = _field(chunk, "message", indent=2) or ""
    if message == "6-1 scan statistics":
        return {"kind": "stats", "severity": severity, "message": message}

    ev = {
        "category": _field(chunk, "category"),
        "rule_id": _field(chunk, "rule_id"),
        "hint": _field(chunk, "hint"),
        "url": _field(chunk, "url"),
        "base_url": _field(chunk, "base_url"),
        "method": _field(chunk, "method"),
        "engine": _field(chunk, "engine") or _field(chunk, "source"),
        "source": _field(chunk, "source"),
        "trigger_family": _field(chunk, "trigger_family"),
        "trigger": _field(chunk, "trigger"),
        "trigger_label": _field(chunk, "trigger_label"),
        "plugin_id": _field(chunk, "plugin_id"),
        "sk_class": _field(chunk, "sk_class") or _field(chunk, "kisa_class"),
        "status_code": _field(chunk, "status_code"),
        "remediation": _field(chunk, "remediation"),
        "body_snippet": _field(chunk, "body_snippet"),
    }
    return {
        "kind": "issue",
        "severity": severity,
        "message": message,
        "evidence": {k: v for k, v in ev.items() if v is not None},
    }


def _iter_finding_chunks(text: str):
    m = re.search(r"\nfindings:\n", text)
    if not m:
        return
    body = text[m.end() :]
    for chunk in re.split(r"\n(?=- severity:)", body):
        chunk = chunk.strip()
        if chunk:
            yield chunk if chunk.startswith("- severity:") else f"- severity: {chunk}"


def _group_key(severity: str, sk: str, category: str, rule_id: str, origin: str) -> str:
    return "|".join([severity, sk, category, rule_id, origin])


def _issue_label(category: str, rule_id: str, hint: str | None) -> str:
    if rule_id in RULE_LABELS:
        return RULE_LABELS[rule_id]
    if hint:
        return hint[:120]
    return CATEGORY_LABELS.get(category, category or rule_id or "정보 노출")


def _normalize_engine(engine: str) -> str:
    e = (engine or "httpx").lower()
    if e.startswith("zap"):
        return "zap"
    return "httpx"


def _legacy_finding_include(ev: dict[str, Any]) -> bool:
    """Minimal filters when re-aggregating saved reports (legacy rule_ids only)."""
    rule_id = str(ev.get("rule_id") or "")
    try:
        status = int(ev.get("status_code") or 0)
    except (TypeError, ValueError):
        status = 0
    snippet = str(ev.get("body_snippet") or "")
    is_json = snippet.lstrip().startswith("{")

    if rule_id.startswith("php_") and is_json:
        return False

    if rule_id in {"verbose_500", "verbose_500_body", "web_server_banner"} and status < 400:
        return False

    return True


def _aggregate_issue_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    by_sk: Counter[str] = Counter()
    by_trigger: Counter[str] = Counter()
    groups: dict[str, dict[str, Any]] = {}

    for row in rows:
        if row.get("kind") != "issue":
            continue
        ev = row.get("evidence") or {}
        if not _legacy_finding_include(ev):
            continue
        sev = str(row.get("severity") or "info")
        category = str(ev.get("category") or "unknown")
        rule_id = str(ev.get("rule_id") or "unknown")
        sk = _sk_class(ev)
        engine = _normalize_engine(str(ev.get("engine") or ev.get("source") or "httpx"))
        origin = _origin_label(str(ev.get("base_url") or ev.get("url") or ""))
        by_severity[sev] += 1
        by_category[category] += 1
        by_sk[sk] += 1
        if ev.get("trigger_family"):
            by_trigger[str(ev["trigger_family"])] += 1

        key = _group_key(sev, sk, category, rule_id, origin)
        g = groups.get(key)
        if not g:
            groups[key] = {
                "group_key": key,
                "severity": sev,
                "sk_class": sk,
                "sk_label": SK_LABELS.get(sk, sk),
                "category": category,
                "rule_id": rule_id,
                "category_label": CATEGORY_LABELS.get(category, category),
                "rule_label": _issue_label(category, rule_id, ev.get("hint")),
                "explanation": SK_EXPLAIN.get(sk, ""),
                "origin": origin,
                "engines": {engine},
                "count": 1,
                "sample_urls": [u for u in [ev.get("url")] if u][:5],
                "sample_methods": [m for m in [ev.get("method")] if m][:5],
                "sample_snippets": [s for s in [ev.get("body_snippet")] if s][:3],
                "remediation": ev.get("remediation"),
                "trigger_families": Counter([str(ev.get("trigger_family"))]) if ev.get("trigger_family") else Counter(),
                "status_codes": Counter([str(ev.get("status_code"))]) if ev.get("status_code") else Counter(),
            }
            continue
        g["count"] += 1
        g["engines"].add(engine)
        url = ev.get("url")
        if url and url not in g["sample_urls"] and len(g["sample_urls"]) < 5:
            g["sample_urls"].append(url)
        method = ev.get("method")
        if method and method not in g["sample_methods"] and len(g["sample_methods"]) < 5:
            g["sample_methods"].append(method)
        snippet = ev.get("body_snippet")
        if snippet and snippet not in g["sample_snippets"] and len(g["sample_snippets"]) < 3:
            g["sample_snippets"].append(snippet[:240])
        if ev.get("trigger_family"):
            g["trigger_families"][str(ev["trigger_family"])] += 1
        if ev.get("status_code"):
            g["status_codes"][str(ev.get("status_code"))] += 1

    origin_map: dict[str, dict[str, Any]] = {}
    for g in groups.values():
        origin = g["origin"]
        slot = origin_map.setdefault(
            origin,
            {"origin": origin, "count": 0, "sk": Counter(), "categories": Counter()},
        )
        slot["count"] += g["count"]
        slot["sk"][g["sk_class"]] += g["count"]
        slot["categories"][g["category"]] += g["count"]

    group_list = []
    for g in groups.values():
        tf = g.pop("trigger_families")
        sc = g.pop("status_codes")
        engines = sorted(g.pop("engines"))
        g["engines"] = engines
        g["engine"] = "httpx+zap" if len(engines) > 1 else (engines[0] if engines else "httpx")
        g["trigger_families"] = [
            {"family": k, "count": v} for k, v in tf.most_common(6)
        ]
        g["top_status_codes"] = [k for k, _ in sc.most_common(4)]
        group_list.append(g)

    group_list.sort(
        key=lambda x: (
            -_SEVERITY_RANK.get(str(x.get("severity")), 0),
            -int(x.get("count") or 0),
            str(x.get("origin") or ""),
        )
    )

    by_origin = []
    for origin, slot in sorted(origin_map.items(), key=lambda kv: -kv[1]["count"]):
        by_origin.append(
            {
                "origin": origin,
                "count": slot["count"],
                "sk": dict(slot["sk"].most_common()),
                "categories": dict(slot["categories"].most_common()),
            }
        )

    return {
        "summary_version": SUMMARY_VERSION,
        "total_issues": sum(by_severity.values()),
        "by_severity": dict(by_severity),
        "by_sk": dict(by_sk),
        "by_category": dict(by_category),
        "by_trigger_family": dict(by_trigger.most_common()),
        "by_origin": by_origin,
        "groups": group_list,
    }


def build_g61_summary_from_findings(findings: list[DiagnosisFinding]) -> dict[str, Any]:
    stats: dict[str, Any] | None = None
    rows: list[dict[str, Any]] = []
    for f in findings:
        if f.message == "6-1 scan statistics":
            stats = dict((f.evidence or {}).get("stats") or {})
            continue
        rows.append(
            {
                "kind": "issue",
                "severity": f.severity,
                "message": f.message,
                "evidence": dict(f.evidence or {}),
            }
        )
    agg = _aggregate_issue_rows(rows)
    return {"stats": stats, **agg}


def build_g61_summary_from_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    header = text.split("\nfindings:\n", 1)[0]
    stats: dict[str, Any] | None = None
    rows: list[dict[str, Any]] = []
    for chunk in _iter_finding_chunks(text):
        parsed = _parse_finding_chunk(chunk)
        if not parsed:
            continue
        if parsed.get("kind") == "stats":
            if stats is None:
                stats = _extract_stats_from_chunk(chunk)
            continue
        rows.append(parsed)

    meta: dict[str, Any] = {}
    for key in ("section_id", "title", "status", "message", "checked_at"):
        m = re.search(rf"^{key}: (.+)$", header, re.M)
        if m:
            val = m.group(1).strip()
            if val.startswith("'") and val.endswith("'"):
                val = val[1:-1]
            meta[key] = val
    if stats is None:
        stats = _extract_stats_from_header(header)

    agg = _aggregate_issue_rows(rows)
    return {"meta": meta, "stats": stats, **agg}


def _extract_stats_from_chunk(chunk: str) -> dict[str, Any] | None:
    m = re.search(r"\n    stats:\n(.*?)(?=\n- severity:|\Z)", chunk, re.S)
    if not m:
        return None
    block = m.group(1)
    stats: dict[str, Any] = {}
    for line in block.splitlines():
        mm = re.match(r"      ([\w_]+): (.+)$", line)
        if not mm:
            continue
        key, raw = mm.group(1), mm.group(2).strip()
        if raw in ("true", "false"):
            stats[key] = raw == "true"
        elif raw == "null":
            stats[key] = None
        elif re.match(r"^-?\d+$", raw):
            stats[key] = int(raw)
        else:
            stats[key] = raw.strip("'\"")
    return stats or None


def _extract_stats_from_header(header: str) -> dict[str, Any] | None:
    return None


def summary_cache_path(report_path: Path) -> Path:
    return report_path.with_name("latest-summary.json")


def load_cached_summary(report_path: Path) -> dict[str, Any] | None:
    cache = summary_cache_path(report_path)
    if not cache.is_file() or not report_path.is_file():
        return None
    if cache.stat().st_mtime < report_path.stat().st_mtime:
        return None
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        if data.get("summary_version") != SUMMARY_VERSION:
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def save_summary_cache(report_path: Path, summary: dict[str, Any]) -> Path:
    cache = summary_cache_path(report_path)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
    return cache


def load_or_build_summary(report_path: Path) -> dict[str, Any]:
    cached = load_cached_summary(report_path)
    if cached is not None:
        return cached
    summary = build_g61_summary_from_yaml(report_path)
    save_summary_cache(report_path, summary)
    return summary
