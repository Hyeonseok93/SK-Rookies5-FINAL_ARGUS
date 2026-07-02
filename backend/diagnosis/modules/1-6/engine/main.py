# =============================================================================
# main.py - ARGUS W-1-6 diagnostic engine entry point
#
# Example:
#   python main.py \
#     --target https://any-site.com \
#     --api-spec swagger.json \
#     --roles admin:pass123 user:pass456 seller:pass789
#
# Without Swagger, ARGUS can fall back to Selenium-discovered endpoints:
#   python main.py --target https://any-site.com --roles admin:pass123
#
# Run only against authorized development or staging systems.
# =============================================================================
import argparse
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime

from config import Config
from parsers.swagger_parser import SwaggerParser
from core.role_manager import RoleManager
from core.session_manager import SessionManager
from core.zap_engine import ZAPEngine
from core.fuzzer import MassiveDataFuzzer
from core.collector import VulnerabilityCollector
from core.screenshot import ScreenshotCapture

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ARGUS_MAIN")


# =============================================================================
# CLI argument parsing
# =============================================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="ARGUS W-1-6 diagnostic engine for Swagger/OpenAPI and URL targets."
    )
    parser.add_argument("--target",     required=True,
                        help="Target API base URL, e.g. http://localhost:8080")
    parser.add_argument("--ui-target",  default="",
                        help="UI URL for Selenium login and screenshot capture")
    parser.add_argument("--api-spec",   default="",
                        help="Swagger/OpenAPI JSON file path or URL")
    parser.add_argument("--login-spec", default="",
                        help="Separate Swagger/OpenAPI JSON used to detect the login endpoint")
    parser.add_argument("--login-target", default="",
                        help="Login API base URL, e.g. http://localhost:8080")
    parser.add_argument("--login-path", default="",
                        help="Login API path, e.g. /api/v1/auth/login")
    parser.add_argument("--roles",      nargs="+", default=[],
                        help="Credentials in name:password format, e.g. admin:pass123 user:pass456")
    parser.add_argument("--zap-host",   default="localhost")
    parser.add_argument("--zap-port",   default=8090, type=int)
    parser.add_argument("--zap-key",    default="changeme")
    parser.add_argument("--output",     default="./output")
    parser.add_argument("--skip-zap",   action="store_true",  help="Skip ZAP scanning")
    parser.add_argument("--skip-spider",action="store_true",  help="Skip ZAP spidering")
    parser.add_argument("--skip-selenium", action="store_true", help="Skip Selenium login/CDP collection")
    parser.add_argument("--zap-timeout",default=60, type=int, help="ZAP active scan timeout in minutes")
    parser.add_argument("--max-workers", default=None, type=int,
                        help="Fuzzer worker count; defaults to MAX_WORKERS or 2")
    parser.add_argument("--max-requests", default=None, type=int,
                        help="Maximum total fuzzer requests; 0 means unlimited")
    parser.add_argument("--max-requests-per-endpoint", default=None, type=int,
                        help="Maximum requests per role/method/endpoint/payload stage; 0 means unlimited")
    parser.add_argument("--circuit-breaker-failures", default=None, type=int,
                        help="Consecutive timeout/5xx count before blocking an endpoint")
    return parser.parse_args()


def parse_roles(roles_list: list) -> dict:
    """
    Convert ["admin:pass123", "user:pass456"] to {"admin": "pass123", "user": "pass456"}.
    """
    result = {}
    for item in roles_list:
        if ":" in item:
            role, pw = item.split(":", 1)
            result[role.strip()] = pw.strip()
        else:
            logger.warning(f"Invalid role format; expected name:password: {item}")
    return result


# =============================================================================
# Main pipeline
# =============================================================================
def main():
    args = parse_args()

    # -------------------------------------------------------------------------
    # 0. Initialize runtime config
    # -------------------------------------------------------------------------
    cfg = Config()
    cfg.TARGET_URL = args.target
    cfg.UI_TARGET_URL = args.ui_target or args.target
    cfg.API_SPEC = args.api_spec
    cfg.LOGIN_SPEC = args.login_spec
    cfg.LOGIN_TARGET = args.login_target
    cfg.LOGIN_PATH = args.login_path
    cfg.ZAP_HOST = args.zap_host
    cfg.ZAP_PORT = args.zap_port
    cfg.ZAP_API_KEY = args.zap_key
    cfg.USE_ZAP_PROXY = not args.skip_zap
    cfg.OUTPUT_DIR = args.output
    cfg.ACTIVE_SCAN_TIMEOUT_MIN = args.zap_timeout
    if args.max_workers is not None:
        cfg.MAX_WORKERS = max(1, args.max_workers)
    if args.max_requests is not None:
        cfg.MAX_TOTAL_REQUESTS = max(0, args.max_requests)
    if args.max_requests_per_endpoint is not None:
        cfg.MAX_REQUESTS_PER_ENDPOINT = max(0, args.max_requests_per_endpoint)
    if args.circuit_breaker_failures is not None:
        cfg.CIRCUIT_BREAKER_FAILURES = max(1, args.circuit_breaker_failures)

    roles = parse_roles(args.roles)
    cfg.ROLES = roles
    cfg.ROLE_PASSWORDS = roles  # Used for JWT refresh/re-login.
    cfg.validate()

    output_base_dir = cfg.OUTPUT_DIR
    os.makedirs(output_base_dir, exist_ok=True)
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(uuid.uuid4())[:8]
    run_output_dir = os.path.join(output_base_dir, f"W16_{run_id}")
    os.makedirs(run_output_dir, exist_ok=True)
    cfg.OUTPUT_BASE_DIR = output_base_dir
    cfg.OUTPUT_DIR = run_output_dir
    logger.info(f"[MAIN] ARGUS W-1-6 v3 started - run_id: {run_id}")
    logger.info(f"[MAIN] output dir: {cfg.OUTPUT_DIR}")
    logger.info(f"[MAIN] target: {cfg.TARGET_URL}")
    logger.info(f"[MAIN] roles: {list(roles.keys())}")

    # -------------------------------------------------------------------------
    # Step 1: Parse Swagger/OpenAPI specification
    # -------------------------------------------------------------------------
    fuzz_targets = []
    login_info = {}
    swagger_endpoints = []

    if cfg.API_SPEC:
        logger.info("[MAIN] === Step 1: Parse Swagger/OpenAPI spec ===")
        try:
            parser = SwaggerParser(cfg.API_SPEC)
            fuzz_targets = parser.get_fuzz_targets()
            login_info = parser.get_login_info()
            auth_type = parser.get_auth_type()
            swagger_endpoints = [t["path"] for t in fuzz_targets]
            logger.info(f"[MAIN] Swagger parsed: endpoints={len(fuzz_targets)}, auth={auth_type}")
        except Exception as e:
            logger.error(f"[MAIN] Swagger parse failed: {e}")
            logger.warning("[MAIN] Falling back to Selenium-discovered endpoints.")
    else:
        logger.info("[MAIN] === Step 1: --api-spec not provided; Selenium fallback may be used ===")

    if cfg.LOGIN_SPEC:
        try:
            login_parser = SwaggerParser(cfg.LOGIN_SPEC)
            login_info = login_parser.get_login_info()
            logger.info(f"[MAIN] login spec parsed: {cfg.LOGIN_SPEC}")
        except Exception as e:
            logger.error(f"[MAIN] login spec parse failed: {e}")

    if cfg.LOGIN_PATH:
        login_info = dict(login_info or {})
        login_info["path"] = cfg.LOGIN_PATH
        login_info.setdefault("method", "post")
        login_info.setdefault("id_field", "username")
        login_info.setdefault("pw_field", "password")
        login_info.setdefault("token_path", ["access_token"])
        logger.info(f"[MAIN] login path override: {cfg.LOGIN_PATH}")

    # -------------------------------------------------------------------------
    # Step 2: API login per role (RoleManager)
    # -------------------------------------------------------------------------
    role_manager = None
    if roles and login_info:
        logger.info("[MAIN] === Step 2: API login per role ===")
        role_manager = RoleManager(cfg, login_info)
        role_manager.login_all(roles)
        logger.info(f"[MAIN] login status: {role_manager.summary()}")

    # -------------------------------------------------------------------------
    # Step 3: Selenium login and CDP collection (optional)
    # -------------------------------------------------------------------------
    session = None
    selenium_endpoints = []

    if not args.skip_selenium and roles:
        logger.info("[MAIN] === Step 3: Selenium login + CDP collection ===")
        try:
            first_role = list(roles.keys())[0]
            first_pw = roles[first_role]
            session = SessionManager(cfg)
            session.login(cfg.UI_TARGET_URL, first_role, first_pw)
            selenium_endpoints = session.get_captured_endpoints()
            logger.info(f"[MAIN] Selenium captured endpoints: {len(selenium_endpoints)}")
        except Exception as e:
            logger.error(f"[MAIN] Selenium failed: {e}; continuing without Selenium")
            session = None
    else:
        logger.info("[MAIN] === Step 3: Selenium skipped ===")

    # Merge endpoint sources (Swagger + Selenium fallback).
    if not fuzz_targets:
        # If Swagger parsing failed, build fallback targets from Selenium/CDP paths.
        all_paths = list(dict.fromkeys(selenium_endpoints + cfg.CRAWL_PATHS))
        fuzz_targets = [
            {"path": p, "method": "post", "body_schema": {}, "requires_auth": True, "summary": ""}
            for p in all_paths
        ]
        logger.info(f"[MAIN] Using fallback endpoints: {len(fuzz_targets)}")

    # -------------------------------------------------------------------------
    # Step 4: Initialize ZAP, spider, and active scan
    # -------------------------------------------------------------------------
    zap = None
    primary_token = role_manager.get_primary_token() if role_manager else ""

    if not args.skip_zap:
        logger.info("[MAIN] === Step 4: Initialize ZAP and wait for proxy ===")
        
        # Wait until the ZAP proxy port is reachable.
        import socket
        zap_ready = False
        for wait_sec in range(1, 31):
            try:
                with socket.create_connection((cfg.ZAP_HOST, cfg.ZAP_PORT), timeout=1.0):
                    zap_ready = True
                    logger.info(f"[MAIN] ZAP proxy connection succeeded after {wait_sec}s")
                    break
            except (socket.timeout, ConnectionRefusedError):
                if wait_sec % 5 == 0:
                    logger.info(f"[MAIN] ZAP proxy is not ready yet; waiting... ({wait_sec}/30s)")
                time.sleep(1.0)
                
        if not zap_ready:
            cfg.USE_ZAP_PROXY = False
            logger.error("[MAIN] ZAP proxy did not respond within 30s; skipping ZAP scan")
        else:
            try:
                zap = ZAPEngine(cfg)
                zap.setup_context(cfg.TARGET_URL, primary_token)

                if not args.skip_spider:
                    logger.info("[MAIN] === Run ZAP Spider ===")
                    spider_urls = zap.run_spider(cfg.TARGET_URL)
                    logger.info(f"[MAIN] Spider discovered URLs: {len(spider_urls)}")

                logger.info("[MAIN] === Run ZAP Active Scan ===")
                zap.run_active_scan(cfg.TARGET_URL)
            except Exception as e:
                logger.error(f"[MAIN] ZAP failed: {e}; continuing with fuzzer only")
                zap = None
                cfg.USE_ZAP_PROXY = False
    else:
        logger.info("[MAIN] === Step 4: ZAP skipped ===")

    # -------------------------------------------------------------------------
    # Step 5: Run fuzzer across roles, endpoints, and payloads
    # -------------------------------------------------------------------------
    logger.info("[MAIN] === Step 5: Run fuzzer ===")
    fuzzer = MassiveDataFuzzer(cfg, role_manager=role_manager, zap_engine=zap)
    
    # Restore previous checkpoint findings if a prior run was interrupted.
    temp_jsonl_path = os.path.join(cfg.OUTPUT_DIR, "temp_findings.jsonl")
    recovered_count = 0
    if os.path.exists(temp_jsonl_path):
        logger.info(f"[MAIN] Restoring checkpoint findings from: {temp_jsonl_path}")
        try:
            with open(temp_jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        finding = json.loads(line)
                        fuzzer.findings.append(finding)
                        recovered_count += 1
            logger.info(f"[MAIN] Restored checkpoint findings: {recovered_count}")
        except Exception as e:
            logger.error(f"[MAIN] Failed to restore checkpoint findings: {e}")

    fuzzer_results = fuzzer.run_all(cfg.TARGET_URL, fuzz_targets)

    # -------------------------------------------------------------------------
    # Step 6: Merge results and write JSON artifacts
    # -------------------------------------------------------------------------
    logger.info("[MAIN] === Step 6: Merge and save results ===")
    collector = VulnerabilityCollector(zap=zap, session=session)
    merged = collector.merge(fuzzer_results, cfg.TARGET_URL)
    _annotate_findings(merged, list(roles.keys()))

    raw_path     = os.path.join(cfg.OUTPUT_DIR, "raw_findings.json")
    summary_path = os.path.join(cfg.OUTPUT_DIR, "summary.json")
    cdp_path     = os.path.join(cfg.OUTPUT_DIR, "cdp_network_log.json")

    # Final merge completed, so remove temporary jsonl checkpoint if present.
    if os.path.exists(temp_jsonl_path):
        try:
            os.remove(temp_jsonl_path)
            logger.info("[MAIN] Final merge complete; temporary checkpoint file removed")
        except Exception as e:
            logger.warning(f"[MAIN] Failed to remove temporary checkpoint file: {e}")

    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)

    role_login_summary = role_manager.summary() if role_manager else {}
    summary = _build_summary(merged, run_id, cfg.TARGET_URL, list(roles.keys()))
    summary["schema_version"] = "1.0"
    summary["module"] = "W16"
    summary["output_dir"] = cfg.OUTPUT_DIR
    summary["execution"] = {
        "api_base_url": cfg.TARGET_URL,
        "ui_target": cfg.UI_TARGET_URL,
        "api_spec": cfg.API_SPEC,
        "login_spec": getattr(cfg, "LOGIN_SPEC", ""),
        "login_target": getattr(cfg, "LOGIN_TARGET", ""),
        "login_path": getattr(cfg, "LOGIN_PATH", ""),
        "zap_host": cfg.ZAP_HOST,
        "zap_port": cfg.ZAP_PORT,
        "skip_zap": bool(args.skip_zap),
        "skip_selenium": bool(args.skip_selenium),
    }
    summary["auth"] = {
        "authenticated": any(v.get("logged_in") for v in role_login_summary.values()),
        "roles": role_login_summary,
        "login_success_roles": [
            role for role, data in role_login_summary.items() if data.get("logged_in")
        ],
        "login_failed_roles": [
            role for role in roles.keys()
            if not role_login_summary.get(role, {}).get("logged_in")
        ],
    }
    summary["artifacts"] = {
        "raw_findings": os.path.basename(raw_path),
        "summary": os.path.basename(summary_path),
        "cdp_network_log": os.path.basename(cdp_path),
        "screenshots": "screenshots.json",
        "screenshot_dir": "screenshots",
        "temp_progress": "temp_progress.txt",
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    cdp_log = session.get_cdp_network_log() if session else []
    with open(cdp_path, "w", encoding="utf-8") as f:
        json.dump(cdp_log, f, ensure_ascii=False, indent=2)

    logger.info(f"[MAIN] complete - total findings: {len(merged)}")
    logger.info(f"  raw findings: {raw_path}")
    logger.info(f"  summary:      {summary_path}")

    # -------------------------------------------------------------------------
    # Step 7: Selenium screenshot capture (CAP-04 800x450 / CAP-05 PIL overlay)
    # -------------------------------------------------------------------------
    screenshot_results = []
    sc_path = os.path.join(cfg.OUTPUT_DIR, "screenshots.json")
    if session and hasattr(session, "driver") and session.driver:
        logger.info("[MAIN] === Step 7: Screenshot capture (CAP-04/05) ===")
        try:
            screenshot_dir = os.path.join(cfg.OUTPUT_DIR, "screenshots")
            sc = ScreenshotCapture(
                driver      = session.driver,
                output_dir  = screenshot_dir,
                page_wait   = 2.0,
                max_per_type= 5,
            )
            screenshot_results = sc.capture_all(merged, cfg.UI_TARGET_URL)
            logger.info(f"[MAIN] screenshot capture completed for {len(screenshot_results)} findings")

            # Attach screenshot reproduction metadata to matching findings.
            sc_map = {r["finding_id"]: r for r in screenshot_results if r}
            for finding in merged:
                fid = finding.get("id")
                if fid and fid in sc_map:
                    finding["reproduction_flow"] = sc_map[fid]["steps"]
                    finding["overlay_applied"] = sc_map[fid]["overlay_applied"]
                    if len(sc_map[fid]["steps"]) >= 2:
                        finding["screenshot_path"] = sc_map[fid]["steps"][1]["path"]

            with open(sc_path, "w", encoding="utf-8") as f:
                json.dump(screenshot_results, f, ensure_ascii=False, indent=2)
            logger.info(f"  screenshot metadata: {sc_path}")

            # Re-save raw findings after attaching screenshot metadata.
            with open(raw_path, "w", encoding="utf-8") as f:
                json.dump(merged, f, ensure_ascii=False, indent=2)
            logger.info(f"  [Step 7 final] raw findings updated with screenshot metadata: {raw_path}")
        except Exception as e:
            logger.error(f"[MAIN] screenshot capture failed: {e}")
    else:
        logger.info("[MAIN] === Step 7: Selenium unavailable; screenshot capture skipped ===")

    if not os.path.exists(sc_path):
        with open(sc_path, "w", encoding="utf-8") as f:
            json.dump(screenshot_results, f, ensure_ascii=False, indent=2)
        logger.info(f"  screenshots metadata: {sc_path}")

    if session:
        session.close()


# =============================================================================
# Helpers
# =============================================================================
def _build_summary(findings, run_id, target, roles):
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    source_counts = {}
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    triage_counts = {"confirmed": 0, "suspected": 0, "noise": 0}
    status_counts = {}
    exception_counts = {}
    final_status_counts = {}
    review_counts = {}
    total_duplicate_evidence = 0
    for f in findings:
        r = f.get("risk", "INFO")
        if r in risk_counts:
            risk_counts[r] += 1
        src = f.get("source") or "unknown"
        source_counts[src] = source_counts.get(src, 0) + 1
        confidence = f.get("confidence", "medium")
        if confidence in confidence_counts:
            confidence_counts[confidence] += 1
        triage = f.get("triage_status", "suspected")
        if triage in triage_counts:
            triage_counts[triage] += 1
        status = str(f.get("status_code", ""))
        status_counts[status] = status_counts.get(status, 0) + 1
        exception_type = f.get("response_analysis", {}).get("exception_type", "")
        if exception_type:
            exception_counts[exception_type] = exception_counts.get(exception_type, 0) + 1
        final_status = f.get("classification", {}).get("final_status", "unclassified")
        final_status_counts[final_status] = final_status_counts.get(final_status, 0) + 1
        review_bucket = f.get("review_bucket", "unclassified")
        review_counts[review_bucket] = review_counts.get(review_bucket, 0) + 1
        total_duplicate_evidence += max(0, int(f.get("duplicate_count", 1)) - 1)

    fuzzer_sources = {"kisa", "sk_shielders", "cwe", "owasp", "fuzzer"}

    return {
        "run_id": run_id, "target": target,
        "scan_time": datetime.now().isoformat(),
        "roles_tested": roles,
        "total_findings": len(findings),
        "deduplicated_extra_evidence": total_duplicate_evidence,
        "risk_breakdown": risk_counts,
        "confidence_breakdown": confidence_counts,
        "triage_breakdown": triage_counts,
        "counts": {
            "by_status": status_counts,
            "by_exception": exception_counts,
            "by_final_status": final_status_counts,
            "by_review_bucket": review_counts,
        },
        "findings_by_source": {
            "zap":    source_counts.get("zap", 0),
            "fuzzer": sum(source_counts.get(src, 0) for src in fuzzer_sources),
            "cdp":    source_counts.get("cdp", 0),
            "by_payload_source": source_counts,
        },
        "findings_by_role": {
            role: sum(1 for f in findings if f.get("role") == role)
            for role in roles
        },
        "top_findings": [
            {
                "risk": f.get("risk", "INFO"),
                "confidence": f.get("confidence", "medium"),
                "triage_status": f.get("triage_status", "suspected"),
                "source": f.get("source", ""),
                "kisa_code": f.get("kisa_code", ""),
                "url": f.get("normalized_url", f.get("url", "")),
                "status_code": f.get("status_code", ""),
                "duplicate_count": f.get("duplicate_count", 1),
                "evidence_reason": f.get("evidence_reason", ""),
            }
            for f in findings[:10]
        ],
    }


def _annotate_findings(findings, roles):
    for finding in findings:
        exception_type = _extract_exception_type(finding)
        system_message = _extract_system_message(finding)
        status_code = finding.get("status_code")
        source = finding.get("source", "")
        role = finding.get("role", "")
        classification = _classify_finding(finding, exception_type, system_message)

        finding.setdefault("module", "W16")
        finding["authenticated"] = bool(role and role in roles)
        finding["response_analysis"] = {
            "status_code": status_code,
            "exception_type": exception_type,
            "system_message_exposed": bool(system_message),
            "system_message": system_message,
        }
        finding["classification"] = classification
        finding.setdefault("report_candidate", classification["final_status"] in {
            "vulnerable",
            "potential_vulnerable",
        })
        finding.setdefault("payload_source", source)
        finding.update(_review_finding(finding))


def _extract_system_message(finding):
    response_json = finding.get("response_json")
    if isinstance(response_json, dict):
        error = response_json.get("error")
        if isinstance(error, dict):
            return error.get("systemMessage") or ""
    return ""


def _extract_exception_type(finding):
    message = _extract_system_message(finding) or finding.get("response_text_snippet", "")
    if not message:
        return ""
    for token in message.replace(":", " ").replace(";", " ").split():
        cleaned = token.strip("\"'(),[]{}")
        if cleaned.endswith("Exception"):
            return cleaned.split(".")[-1]
    if message.startswith("No static resource"):
        return "NoStaticResource"
    if "Request method" in message and "not supported" in message:
        return "HttpRequestMethodNotSupported"
    if "Required request parameter" in message and "not present" in message:
        return "MissingServletRequestParameter"
    if "Failed to convert value" in message:
        return "MethodArgumentTypeMismatch"
    return ""


def _classify_finding(finding, exception_type, system_message):
    status_code = str(finding.get("status_code", ""))
    source = finding.get("source", "")
    url = finding.get("url", "")
    evidence_flags = []
    noise_flags = []
    final_status = "potential_vulnerable"
    confidence = finding.get("confidence", "medium")
    vuln_type = "input_validation_exception_handling"

    if status_code.startswith("5"):
        evidence_flags.append("http_500")
    if status_code == "TIMEOUT":
        evidence_flags.append("timeout")
        vuln_type = "dos_potential"
    if system_message:
        evidence_flags.append("internal_error_message_exposed")
    if exception_type:
        evidence_flags.append(exception_type)

    if source == "cdp" and status_code == "200":
        final_status = "not_vulnerable"
        confidence = "low"
        noise_flags.append("frontend_static_asset")
    elif exception_type == "HttpRequestMethodNotSupported":
        final_status = "not_vulnerable"
        confidence = "medium"
        noise_flags.append("http_method_mismatch")
        vuln_type = "scanner_noise"
    elif status_code == "TIMEOUT":
        final_status = "potential_vulnerable"
        confidence = "low"
    elif exception_type in {
        "MethodArgumentTypeMismatchException",
        "MethodArgumentTypeMismatch",
        "MissingServletRequestParameterException",
        "MissingServletRequestParameter",
        "HttpMessageNotReadableException",
        "HttpMediaTypeNotSupportedException",
    }:
        final_status = "vulnerable"
        confidence = "high" if status_code.startswith("5") else "medium"
    elif exception_type in {"NoStaticResource", "NoResourceFoundException"}:
        final_status = "potential_vulnerable"
        confidence = "medium" if status_code.startswith("5") else "low"
    elif status_code.startswith("5"):
        final_status = "potential_vulnerable"
    elif status_code.startswith("4"):
        final_status = "not_vulnerable"
        noise_flags.append("client_error_response")

    if "/assets/" in url:
        final_status = "not_vulnerable"
        noise_flags.append("frontend_static_asset")

    return {
        "final_status": final_status,
        "confidence": confidence,
        "vuln_type": vuln_type,
        "evidence_flags": evidence_flags,
        "noise_flags": noise_flags,
    }


def _review_finding(finding):
    """Add human-review fields used to separate report items from scanner noise."""
    url = finding.get("url", "") or ""
    normalized_url = finding.get("normalized_url", "") or url
    status_code = str(finding.get("status_code", ""))
    source = finding.get("source", "")
    evidence_reason = finding.get("evidence_reason", "")
    classification = finding.get("classification", {})

    tags = []
    bucket = "manual_review"
    action = "review_before_report"
    priority = "C"
    reason = "Needs manual validation before it is used as report evidence."
    report_group = "manual_review"

    has_unresolved_placeholder = "{" in url or "}" in url or "%7B" in url.upper() or "%7D" in url.upper()
    exploratory_paths = (
        "/update", "/upgrade", "/deploy", "/reload", "/patch",
        "/api/update", "/api/upgrade", "/api/deploy", "/api/reload",
        "/api/config/reload", "/api/v1/update", "/api/v2/update",
    )
    is_exploratory = any(
        normalized_url.endswith(path) or url.endswith(path)
        for path in exploratory_paths
    )

    if has_unresolved_placeholder:
        tags.append("unresolved_path_placeholder")
        bucket = "noise"
        action = "exclude_from_report"
        priority = "EXCLUDE"
        reason = "Swagger path parameter was not replaced with a real value."
        report_group = "path_placeholder_noise"
    elif is_exploratory:
        tags.append("exploratory_path")
        bucket = "noise"
        action = "exclude_from_report"
        priority = "EXCLUDE"
        reason = "Endpoint is an exploratory scanner path, not a confirmed Swagger operation."
        report_group = "exploratory_path_noise"
    elif source == "zap" and status_code.startswith("4"):
        tags.extend(["zap", "client_error"])
        bucket = "noise"
        action = "exclude_from_report"
        priority = "EXCLUDE"
        reason = "Server returned a normal 4xx rejection for the ZAP request."
        report_group = "zap_4xx_noise"
    elif status_code.startswith("4"):
        tags.append("client_error")
        bucket = "noise"
        action = "exclude_from_report"
        priority = "EXCLUDE"
        reason = "Server rejected the request with a 4xx response."
        report_group = "client_error_noise"
    elif status_code == "200" or evidence_reason == "successful response requires manual review":
        tags.append("successful_response_manual_review")
        bucket = "manual_review"
        action = "manual_validate_only"
        priority = "C"
        reason = "Successful response needs proof of sensitive data exposure or authorization bypass."
        report_group = "successful_response_manual_review"
        if "/admin/" in url:
            tags.append("admin_endpoint")
            report_group = "admin_authorization_manual_check"
    elif status_code == "TIMEOUT":
        tags.append("timeout")
        bucket = "report_candidate"
        action = "reproduce_then_report"
        priority = "B"
        reason = "Timeout may indicate a denial-of-service or resource exhaustion issue."
        report_group = "timeout_dos_candidate"
    elif status_code.startswith("5"):
        tags.append("server_error")
        bucket = "report_candidate"
        action = "reproduce_then_report"
        priority = "B"
        reason = "Server returned 5xx for malformed input; validate reproducibility before reporting."
        report_group = "input_validation_exception_handling"
        if "/api/projects" in url:
            priority = "A"
            report_group = "project_api_5xx_dos_candidate"
        elif "/api/auth/" in url:
            priority = "A"
            report_group = "auth_api_5xx_candidate"
        elif "/api/users/me" in url:
            report_group = "user_api_5xx_candidate"
        elif "/api/users/profile-image" in url:
            report_group = "profile_image_upload_candidate"
    elif classification.get("final_status") in {"vulnerable", "potential_vulnerable"}:
        bucket = "manual_review"
        action = "review_before_report"
        priority = "C"
        reason = "Automatic classifier marked this as a candidate, but report evidence is incomplete."
        report_group = "classifier_candidate_manual_review"

    return {
        "review_bucket": bucket,
        "review_action": action,
        "review_priority": priority,
        "review_reason": reason,
        "review_tags": tags,
        "review_group": report_group,
        "review_include_in_report": bucket == "report_candidate",
    }


if __name__ == "__main__":
    main()
