"""HTTP probes for 2-2 — traversal injection and forced browse (transport-agnostic)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from collections.abc import Callable
from typing import Any

from app.services.zap_util import probe_url
from diagnosis.g22_replay import G22ReplaySession as ReplaySession
from diagnosis.result import DiagnosisFinding
from inventory.net import probe_base_url
from inventory.probe_build import build_probe_request
from inventory.schema import Endpoint

_DIR = Path(__file__).resolve().parent


def _load_traversal_fuzz():
    spec = importlib.util.spec_from_file_location("diag_g22_traversal_fuzz", _DIR / "traversal_fuzz.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load traversal_fuzz")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_tf = _load_traversal_fuzz()


def _tag_evidence(evidence: dict[str, Any], engine: str) -> dict[str, Any]:
    return {
        **evidence,
        "source": engine,
        "engine": engine,
        "analysis_mode": "unified",
    }


def run_traversal_probes(
    candidates: list[Endpoint],
    payloads: list[str],
    *,
    transport: Any,
    engine: str,
    auth: dict[str, Any] | None = None,
    timeout: float = 12.0,
    replay_session: ReplaySession | None = None,
    auth_pool: Any | None = None,
    login_report: dict[str, Any] | None = None,
    on_progress: Callable[..., None] | None = None,
) -> list[DiagnosisFinding]:
    from diagnosis.endpoint_auth_passes import primary_session_for_endpoint

    _ = timeout
    findings: list[DiagnosisFinding] = []
    tf = _tf
    session_list: list[dict[str, Any]] = []
    if auth_pool is not None:
        auth_pool.ensure_valid()
        session_list = auth_pool.sessions()
    elif auth:
        session_list = [auth]

    for idx, ep in enumerate(candidates, 1):
        current_auth = primary_session_for_endpoint(ep, session_list, login_report) if session_list else auth
        if on_progress:
            on_progress(
                endpoints_done=idx,
                endpoints_total=len(candidates),
                endpoint_id=ep.path[:80] if ep.path else ep.id,
            )
        probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=current_auth)
        url = probe["url"]
        method = probe["method"]
        headers = dict(probe.get("headers") or {})

        baseline_status: int | None = None
        baseline_body: bytes = b""
        baseline_headers: dict[str, str] = {}
        targets = tf.traversal_targets(ep)
        baseline_body_obj = tf.build_body_object(ep) if targets else {}
        baseline_path_defaults = tf.path_param_defaults(ep) if targets else {}
        if targets:
            baseline_probe = build_probe_request(
                ep,
                probe_base_fn=probe_url,
                account_auth=current_auth,
                path_param_defaults=baseline_path_defaults or None,
            )
            if baseline_body_obj and ep.method.upper() in ("POST", "PUT", "PATCH"):
                baseline_probe = dict(baseline_probe)
                baseline_probe["body"] = json.dumps(baseline_body_obj, ensure_ascii=False)
            baseline_bytes = (baseline_probe.get("body") or "").encode("utf-8") or None
            baseline_resp = transport.request(
                baseline_probe["method"],
                baseline_probe["url"],
                dict(baseline_probe.get("headers") or {}),
                baseline_bytes,
                follow_redirects=True,
            )
            if not baseline_resp.error and baseline_resp.status is not None:
                baseline_status = baseline_resp.status
                baseline_body = baseline_resp.body
                baseline_headers = baseline_resp.headers

        for param_in, pname in targets:
            payloads_tried: list[dict[str, Any]] = []
            path_traversal_hits: list[dict[str, Any]] = []
            input_validation_hits: list[dict[str, Any]] = []

            for payload in payloads:
                injected = tf.build_traversal_probe(
                    ep,
                    param_in=param_in,
                    param_name=pname,
                    payload=payload,
                    auth=current_auth,
                    baseline_body=baseline_body_obj,
                    baseline_path_defaults=baseline_path_defaults,
                )
                req_url = injected["url"]
                req_method = str(injected.get("method") or method)
                req_headers = dict(injected.get("headers") or headers)
                req_body = injected.get("body") or ""
                req_body_bytes = req_body.encode("utf-8") if req_body else None

                resp = transport.request(
                    req_method, req_url, req_headers, req_body_bytes, follow_redirects=True
                )
                if resp.error or resp.status is None:
                    continue
                resp_body = resp.body

                category, trigger, meta = tf.compare_to_baseline(
                    path=ep.path,
                    baseline_status=baseline_status,
                    baseline_body=baseline_body,
                    baseline_headers=baseline_headers,
                    payload_status=resp.status,
                    payload_body=resp_body,
                    payload_headers=resp.headers,
                    payload=payload,
                )
                pf = tf.body_fingerprint(resp_body)
                entry = {
                    "payload": payload,
                    "category": category or "none",
                    "trigger": trigger,
                    "http_status": resp.status,
                    "sha256": pf["sha256"],
                    "size": pf["size"],
                }
                if meta.get("analysis"):
                    entry["pdf_text_overlap"] = meta["analysis"].get("pdf_text_overlap")
                    if meta["analysis"].get("payload_leak_markers"):
                        entry["payload_leak_markers"] = meta["analysis"]["payload_leak_markers"]
                payloads_tried.append(entry)

                if category == "path_traversal":
                    path_traversal_hits.append(
                        {
                            **entry,
                            "url": req_url,
                            "body": resp_body,
                            "headers": resp.headers,
                            "meta": meta,
                        }
                    )
                elif category == "input_validation":
                    input_validation_hits.append(
                        {
                            **entry,
                            "url": req_url,
                            "body": resp_body,
                            "headers": resp.headers,
                            "meta": meta,
                        }
                    )

            if path_traversal_hits:
                def _b_rank(hit: dict[str, Any]) -> int:
                    t = hit.get("trigger") or ""
                    if t == "payload_target_leak_confirmed":
                        p = str(hit.get("payload") or "").lower()
                        if "passwd" in p:
                            return 0
                        return 1
                    return 2

                primary = min(path_traversal_hits, key=_b_rank)
                finding = DiagnosisFinding(
                    severity="high",
                    message=(
                        f"[B] Path traversal signal via `{pname}` on {ep.method} {ep.path} "
                        f"(HTTP {primary['http_status']}) — response differs from baseline or "
                        f"contains sensitive content"
                    ),
                    evidence=_tag_evidence(
                        tf.build_probe_result_evidence(
                            ep=ep,
                            param_in=param_in,
                            param_name=pname,
                            classification="path_traversal",
                            trigger=primary["trigger"],
                            primary=primary,
                            payloads_tried=payloads_tried,
                            baseline_status=baseline_status,
                            baseline_body=baseline_body,
                            baseline_headers=baseline_headers,
                        ),
                        engine,
                    ),
                )
                if replay_session:
                    rec = replay_session.recorder(
                        rule_id="2-2-path-traversal",
                        path=ep.path,
                        trigger=str(primary["trigger"]),
                    )
                    auth_mode = "authenticated" if auth else "anonymous"
                    email = str(auth.get("email") or "") if auth else None
                    rec.set_auth(auth_mode, account_email=email)
                    rec.append_ui_flow(method=ep.method, path=ep.path)
                    baseline_probe = build_probe_request(
                        ep,
                        probe_base_fn=probe_url,
                        account_auth=current_auth,
                        path_param_defaults=baseline_path_defaults or None,
                    )
                    if baseline_body_obj:
                        baseline_probe = dict(baseline_probe)
                        baseline_probe["body"] = json.dumps(baseline_body_obj, ensure_ascii=False)
                    s_base = rec.record_http_from_probe(
                        "baseline",
                        label="Baseline request",
                        probe=baseline_probe,
                        response_status=baseline_status,
                        response_headers=baseline_headers,
                        response_body=baseline_body,
                        auth_mode=auth_mode,
                        account_email=email,
                    )
                    injected = tf.build_traversal_probe(
                        ep,
                        param_in=param_in,
                        param_name=pname,
                        payload=str(primary.get("payload") or ""),
                        auth=current_auth,
                        baseline_body=baseline_body_obj,
                        baseline_path_defaults=baseline_path_defaults,
                    )
                    leak_markers: list[str] = []
                    meta = primary.get("meta") or {}
                    analysis = meta.get("analysis") or {}
                    for item in analysis.get("payload_leak_markers") or []:
                        if isinstance(item, dict) and item.get("marker"):
                            leak_markers.append(str(item["marker"]).split("←")[0].strip())
                        elif isinstance(item, str):
                            leak_markers.append(item.split("←")[0].strip())
                    s_payload = rec.record_http_from_probe(
                        "payload",
                        label=f"Exploit payload: {primary.get('payload')} (only `{pname}` changed)",
                        probe=injected,
                        response_status=int(primary["http_status"]),
                        response_headers=dict(primary.get("headers") or {}),
                        response_body=bytes(primary.get("body") or b""),
                        auth_mode=auth_mode,
                        account_email=email,
                        body_contains=leak_markers[:8] or None,
                        manipulated_param=pname,
                    )
                    rec.record_compare(s_base, s_payload, label="Baseline vs exploit response")
                    finding = rec.attach_to(finding)
                findings.append(finding)
            elif input_validation_hits:
                primary = input_validation_hits[0]
                finding = DiagnosisFinding(
                    severity="medium",
                    message=(
                        f"[A] Input validation weakness: `{pname}` accepts malicious payload on "
                        f"{ep.method} {ep.path} (HTTP {primary['http_status']}) — "
                        f"response identical to baseline ({len(input_validation_hits)} payload(s))"
                    ),
                    evidence=_tag_evidence(
                        tf.build_probe_result_evidence(
                            ep=ep,
                            param_in=param_in,
                            param_name=pname,
                            classification="input_validation",
                            trigger=primary["trigger"],
                            primary=primary,
                            payloads_tried=payloads_tried,
                            baseline_status=baseline_status,
                            baseline_body=baseline_body,
                            baseline_headers=baseline_headers,
                        ),
                        engine,
                    ),
                )
                if replay_session:
                    rec = replay_session.recorder(
                        rule_id="2-2-input-validation",
                        path=ep.path,
                        trigger=str(primary["trigger"]),
                    )
                    auth_mode = "authenticated" if auth else "anonymous"
                    email = str(auth.get("email") or "") if auth else None
                    rec.set_auth(auth_mode, account_email=email)
                    rec.append_ui_flow(method=ep.method, path=ep.path)
                    baseline_probe = build_probe_request(
                        ep,
                        probe_base_fn=probe_url,
                        account_auth=current_auth,
                        path_param_defaults=baseline_path_defaults or None,
                    )
                    s_base = rec.record_http_from_probe(
                        "baseline",
                        label="Baseline request",
                        probe=baseline_probe,
                        response_status=baseline_status,
                        response_headers=baseline_headers,
                        response_body=baseline_body,
                        auth_mode=auth_mode,
                        account_email=email,
                    )
                    injected = tf.build_traversal_probe(
                        ep,
                        param_in=param_in,
                        param_name=pname,
                        payload=str(primary.get("payload") or ""),
                        auth=current_auth,
                        baseline_body=baseline_body_obj,
                        baseline_path_defaults=baseline_path_defaults,
                    )
                    s_payload = rec.record_http_from_probe(
                        "payload",
                        label=f"Payload accepted: {primary.get('payload')}",
                        probe=injected,
                        response_status=int(primary["http_status"]),
                        response_headers=dict(primary.get("headers") or {}),
                        response_body=bytes(primary.get("body") or b""),
                        auth_mode=auth_mode,
                        account_email=email,
                    )
                    rec.record_compare(s_base, s_payload, label="Baseline vs malicious payload")
                    finding = rec.attach_to(finding)
                findings.append(finding)

    return findings


def run_forced_browse(
    base_urls: list[str],
    paths: list[str],
    *,
    transport: Any,
    engine: str,
    auth: dict[str, Any] | None = None,
    timeout: float = 10.0,
    replay_session: ReplaySession | None = None,
    auth_pool: Any | None = None,
) -> list[DiagnosisFinding]:
    _ = timeout
    findings: list[DiagnosisFinding] = []
    tf = _tf
    if auth_pool is not None:
        auth_pool.ensure_valid()
        auth = auth_pool.primary()
    headers: dict[str, str] = {}
    if auth:
        if auth.get("delivery") == "cookie" and auth.get("token"):
            name = auth.get("cookie_name") or "accessToken"
            headers["Cookie"] = f"{name}={auth['token']}"
        elif auth.get("token"):
            tok = auth["token"]
            headers["Authorization"] = tok if str(tok).startswith("Bearer ") else f"Bearer {tok}"

    for base in base_urls:
        root = probe_url(base.rstrip("/"))
        for rel in paths:
            rel_path = rel if rel.startswith("/") else f"/{rel}"
            url = f"{root.rstrip('/')}{rel_path}"
            resp = transport.request("GET", url, headers, None, follow_redirects=False)
            if resp.error or resp.status is None:
                continue
            body_text = resp.body.decode("utf-8", errors="replace")[:120_000]
            suspicious, trigger = tf.response_suspicious(
                rel_path, resp.status, body_text, resp.headers
            )
            if suspicious:
                finding = DiagnosisFinding(
                    severity="high",
                    message=f"Sensitive path reachable: GET {rel_path} on {base} (HTTP {resp.status})",
                    evidence=_tag_evidence(
                        {
                            "rule_id": "2-2-forced-browse",
                            "classification": "B",
                            "url": url,
                            "http_status": resp.status,
                            "path": rel_path,
                            "base_url": probe_base_url(base),
                            "trigger": trigger,
                            "trigger_label": tf.trigger_label(trigger),
                            **tf.evidence_snippet(resp.headers, body_text),
                        },
                        engine,
                    ),
                )
                if replay_session:
                    rec = replay_session.recorder(
                        rule_id="2-2-forced-browse",
                        path=rel_path,
                        trigger=trigger,
                    )
                    auth_mode = "authenticated" if auth else "anonymous"
                    email = str(auth.get("email") or "") if auth else None
                    rec.set_auth(auth_mode, account_email=email)
                    rec.record_http(
                        "browse",
                        label=f"Forced browse GET {rel_path}",
                        method="GET",
                        url=url,
                        headers=headers,
                        body=None,
                        response_status=resp.status,
                        response_headers=resp.headers,
                        response_body=resp.body,
                        auth_mode=auth_mode,
                        account_email=email,
                    )
                    finding = rec.attach_to(finding)
                findings.append(finding)
    return findings


def seed_urls_from_candidates(candidates: list[Endpoint], auth: dict[str, Any] | None = None) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for ep in candidates:
        probe = build_probe_request(ep, probe_base_fn=probe_url, account_auth=auth)
        url = probe["url"]
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls
