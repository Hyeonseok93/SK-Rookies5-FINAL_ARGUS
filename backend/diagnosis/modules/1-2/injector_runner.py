"""Direct injection verification (ported from feature/injection-scan v2 main.py)."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any, Iterable
from urllib.parse import urlencode, urlsplit, urlunsplit

from app.services.zap_util import probe_url
from models import DetectionResult, InjectionType, ScanTarget, VerificationStatus

UNSAFE_METHODS = {"DELETE", "PATCH"}
DEFAULT_TYPES = (
    InjectionType.SQL,
    InjectionType.NOSQL,
    InjectionType.SSTI,
    InjectionType.COMMAND,
    InjectionType.XPATH,
)


def parse_injection_types(raw: Iterable[str] | None) -> list[InjectionType]:
    if not raw:
        return list(DEFAULT_TYPES)
    selected: list[InjectionType] = []
    for value in raw:
        key = str(value).strip().upper()
        if not key:
            continue
        if key == "ALL":
            return list(InjectionType)
        try:
            selected.append(InjectionType[key])
        except KeyError:
            continue
    return selected or list(DEFAULT_TYPES)


def injector_map(jwt_token: str, verification_mode: str, injectors_mod: Any) -> dict[InjectionType, Any]:
    return {
        InjectionType.SQL: injectors_mod.SqliInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.COMMAND: injectors_mod.CommandInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.NOSQL: injectors_mod.NoSqlInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.SSTI: injectors_mod.SstiInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.XPATH: injectors_mod.XmlXPathInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.XML: injectors_mod.XmlXPathInjector(jwt_token=jwt_token, verification_mode=verification_mode),
        InjectionType.GENERIC: injectors_mod.GenericInjectionInjector(
            jwt_token=jwt_token, verification_mode=verification_mode
        ),
    }


def target_request(
    target: ScanTarget,
    active_param_name: str = "",
    *,
    session_headers: dict[str, str] | None = None,
) -> tuple[str, str, dict[str, str]]:
    path = target.path
    query_params: list[tuple[str, str]] = []
    body_params: dict[str, Any] = {}
    headers = {"Content-Type": target.content_type or "application/json"}
    if session_headers:
        headers.update(session_headers)

    for param in target.params:
        sample = param.sample_value if param.sample_value is not None else "argus-test"
        if param.location.value == "path":
            placeholder = "{" + param.name + "}"
            if param.name != active_param_name and placeholder in path:
                path = path.replace(placeholder, str(sample))
        elif param.location.value == "query":
            query_params.append((param.name, str(sample)))
        elif param.location.value == "body":
            body_params[param.name] = sample
        elif param.location.value == "header":
            headers[param.name] = str(sample)

    url = probe_url(f"{target.base_url.rstrip('/')}{path}")
    if query_params:
        parsed = urlsplit(url)
        extra_query = urlencode(query_params, doseq=True)
        query = "&".join(part for part in [parsed.query, extra_query] if part)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))

    body = ""
    content_type = (target.content_type or "").lower()
    if body_params:
        if "x-www-form-urlencoded" in content_type:
            body = urlencode(body_params, doseq=True)
        else:
            headers["Content-Type"] = target.content_type or "application/json"
            body = json.dumps(body_params, ensure_ascii=False, separators=(",", ":"))

    return url, body, headers


def _method_status(result: DetectionResult, name: str) -> str:
    return (result.verification_methods.get(name) or {}).get("status", "")


def _matched_patterns(result: DetectionResult) -> list[str]:
    return (result.verification_methods.get("error_based") or {}).get("matched_patterns", []) or []


def annotate_result(result: DetectionResult) -> DetectionResult:
    time_verified = _method_status(result, "time_based") == VerificationStatus.VERIFIED.value
    boolean_verified = _method_status(result, "boolean_based") == VerificationStatus.VERIFIED.value
    error_verified = _method_status(result, "error_based") == VerificationStatus.VERIFIED.value
    error_suspected = _method_status(result, "error_based") == VerificationStatus.SUSPECTED.value
    matched_patterns = _matched_patterns(result)
    zap_confirmed = result.has_zap and result.verification_status == VerificationStatus.VERIFIED

    if result.verification_status == VerificationStatus.VERIFIED and time_verified:
        result.classification = "CONFIRMED_INJECTION_TIME_BASED"
        result.confidence = "HIGH"
        result.argus_risk = "HIGH"
        result.related_issue = "SQL Injection / Time-based Blind SQL Injection"
        result.why_injection = "Time delay reproduced after payload — suggests DB function execution."
        result.risk_comment = "Time-based evidence is stronger than generic input validation errors."
        result.reporting_guidance = "Report as confirmed; verify parameterized queries in code."
    elif result.verification_status == VerificationStatus.VERIFIED and boolean_verified:
        result.classification = "CONFIRMED_INJECTION_BOOLEAN_BASED"
        result.confidence = "HIGH"
        result.argus_risk = "HIGH"
        result.related_issue = "SQL Injection / Boolean-based Blind SQL Injection"
        result.why_injection = "True/false payloads produced stable response differences."
        result.risk_comment = "Reproducible response delta — higher confidence than isolated 500 errors."
        result.reporting_guidance = "Report as confirmed; trace user input into query conditions."
    elif result.verification_status == VerificationStatus.VERIFIED and error_verified and matched_patterns:
        result.classification = "CONFIRMED_INJECTION_ERROR_PATTERN"
        result.confidence = "HIGH"
        result.argus_risk = "HIGH"
        result.related_issue = "SQL Injection / Error-based Injection"
        result.why_injection = "SQL/command/XML parser error patterns appeared in the response."
        result.risk_comment = "DB/parser errors increase injection and information disclosure risk."
        result.reporting_guidance = "Report as confirmed; fix binding and suppress verbose errors."
    elif result.verification_status == VerificationStatus.VERIFIED and error_verified:
        result.classification = "WEAK_SERVER_ERROR_CONFIRMED_LEGACY"
        result.confidence = "MEDIUM"
        result.argus_risk = "MEDIUM"
        result.related_issue = "Potential Injection / Server Error Handling"
        result.why_injection = "5xx reproduced on payload but no DB-specific error pattern."
        result.risk_comment = "Safer to classify as server error trigger than confirmed SQLi."
        result.reporting_guidance = "Review server logs for SQL vs validation exceptions."
    elif result.verification_status == VerificationStatus.SUSPECTED and error_suspected:
        result.classification = "SUSPECTED_SERVER_ERROR_SIGNAL"
        result.confidence = "LOW"
        result.argus_risk = "MEDIUM"
        result.related_issue = "Potential Injection / Input Validation / Server Error Handling"
        result.why_injection = "5xx on payload without SQL/boolean/time confirmation."
        result.risk_comment = "May be parsing/validation errors rather than SQLi."
        result.reporting_guidance = "Report as suspected input-handling issue; verify in logs."
    elif result.verification_status == VerificationStatus.SUSPECTED:
        result.classification = "SUSPECTED_INJECTION"
        result.confidence = "LOW"
        result.argus_risk = "MEDIUM" if result.has_zap else "LOW"
        result.related_issue = "Potential Injection"
        result.why_injection = "ZAP or direct probe left inconclusive injection signals."
        result.risk_comment = "Manual follow-up recommended before confirming."
        result.reporting_guidance = "Reproduce with logs and query tracing."
    elif result.verification_status == VerificationStatus.FALSE_POSITIVE:
        result.classification = "NOT_REPRODUCED"
        result.confidence = "LOW"
        result.argus_risk = "INFO"
        result.related_issue = "Not Reproduced"
        result.why_injection = "No reproducible injection evidence in error/boolean/time checks."
        result.risk_comment = "Insufficient evidence for injection reporting."
        result.reporting_guidance = "Exclude from main report or list as false positive."
    elif result.verification_status == VerificationStatus.UNVERIFIABLE:
        result.classification = "UNVERIFIABLE"
        result.confidence = "UNKNOWN"
        result.argus_risk = "INFO"
        result.related_issue = "Verification Gap"
        result.why_injection = "Could not rebuild baseline request for verification."
        result.risk_comment = "Manual reproduction required."
        result.reporting_guidance = "Note scanner/sample-value limitation."
    else:
        result.classification = "VERIFICATION_ERROR"
        result.confidence = "UNKNOWN"
        result.argus_risk = "INFO"
        result.related_issue = "Scanner Error"
        result.why_injection = "Verification exception — injection status unknown."
        result.risk_comment = "Likely tooling error rather than target vulnerability."
        result.reporting_guidance = "Fix scanner error and re-run."

    if zap_confirmed:
        result.reporting_guidance += " ZAP detection plus ARGUS re-verification — prioritize."
    return result


def verify_zap_alerts(
    zap_results: list[DetectionResult],
    *,
    jwt_token: str,
    injectors_mod: Any,
    verification_mode: str = "balanced",
    session_headers: dict[str, str] | None = None,
    progress_cb: Any | None = None,
) -> tuple[list[DetectionResult], dict[str, Any]]:
    injectors = injector_map(jwt_token, verification_mode, injectors_mod)
    verified: list[DetectionResult] = []
    for idx, result in enumerate(zap_results):
        if progress_cb:
            progress_cb(idx + 1, len(zap_results), f"ZAP verify {result.url}")
        if session_headers:
            merged = dict(session_headers)
            merged.update(result.raw_request_headers or {})
            result.raw_request_headers = merged
            result.url = probe_url(result.url)
            if result.raw_request_url:
                result.raw_request_url = probe_url(result.raw_request_url)
        injector = injectors.get(result.injection_type)
        if injector:
            verified.append(injector.verify_zap_alert(result))
        else:
            result.verification_status = VerificationStatus.UNVERIFIABLE
            result.verification_reason = f"Unsupported injection type: {result.injection_type}"
            verified.append(result)
    return verified, {"zap_verified": len(verified)}


def dedupe_results(results: list[DetectionResult]) -> list[DetectionResult]:
    merged: list[DetectionResult] = []
    seen: set[tuple[Any, ...]] = set()
    for result in results:
        key = (result.method, result.url, result.param, result.injection_type, result.plugin_id)
        if key in seen:
            continue
        seen.add(key)
        merged.append(result)
    return merged


def run_direct_verification(
    targets: list[ScanTarget],
    *,
    jwt_token: str,
    injectors_mod: Any,
    injection_types: list[InjectionType],
    verification_mode: str = "balanced",
    include_unsafe: bool = False,
    keep_all: bool = False,
    session_headers: dict[str, str] | None = None,
    progress_cb: Any | None = None,
) -> tuple[list[DetectionResult], dict[str, Any]]:
    injectors = injector_map(jwt_token, verification_mode, injectors_mod)
    results: list[DetectionResult] = []
    skipped_methods = 0
    skipped_params = 0
    probes = 0

    keep_statuses = {
        VerificationStatus.VERIFIED,
        VerificationStatus.SUSPECTED,
        VerificationStatus.ERROR,
    }

    for target in targets:
        method = target.method.upper()
        if method in UNSAFE_METHODS and not include_unsafe:
            skipped_methods += 1
            continue

        for param in target.params:
            if param.location.value not in {"query", "path", "body", "header"}:
                skipped_params += 1
                continue

            raw_url, raw_body, raw_headers = target_request(
                target,
                active_param_name=param.name,
                session_headers=session_headers,
            )
            for injection_type in injection_types:
                probes += 1
                if progress_cb:
                    progress_cb(probes, len(targets), f"{method} {raw_url} ({param.name})")

                injector = injectors.get(injection_type)
                if injector is None:
                    continue

                result = injector.verify_zap_alert(
                    DetectionResult(
                        method=method,
                        url=raw_url,
                        param=param.name,
                        risk="UNKNOWN",
                        plugin_id="ARGUS_DIRECT",
                        plugin_name=f"ARGUS Direct {injection_type.value}",
                        injection_type=injection_type,
                        has_zap=False,
                        raw_request_body=raw_body,
                        raw_request_url=raw_url,
                        raw_request_headers=raw_headers,
                    )
                )
                if keep_all or result.verification_status in keep_statuses:
                    results.append(result)

    status_counts = Counter(
        r.verification_status.value if isinstance(r.verification_status, VerificationStatus) else str(r.verification_status)
        for r in results
    )
    stats = {
        "probes_run": probes,
        "skipped_methods": skipped_methods,
        "skipped_params": skipped_params,
        "results_before_dedupe": len(results),
        "status_counts": dict(status_counts),
    }
    return dedupe_results(results), stats


def severity_for_result(result: DetectionResult) -> str:
    status = result.verification_status
    if status == VerificationStatus.VERIFIED:
        risk = (result.argus_risk or result.risk or "").upper()
        if risk == "HIGH":
            return "high"
        if risk == "MEDIUM":
            return "medium"
        return "high"
    if status == VerificationStatus.SUSPECTED:
        return "medium"
    if status == VerificationStatus.ERROR:
        return "low"
    return "info"
