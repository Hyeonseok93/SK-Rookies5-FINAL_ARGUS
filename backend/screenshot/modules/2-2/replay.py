"""HTTP replay for selected 2-2 findings (httpx + probe_url + verify auth)."""

from __future__ import annotations

import json
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx

_MODULE_DIR = Path(__file__).resolve().parent
_BACKEND_ROOT = _MODULE_DIR.parents[2]
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from auth_context import (  # noqa: E402
    account_auth_for_evidence,
    authenticated_auth_for_evidence,
    create_auth_pool,
    is_unauth_download,
)
from models import EvidenceCase, HttpExchange  # noqa: E402
from redaction import redact_headers, redact_text  # noqa: E402

_BLOCKED_METHODS = {"DELETE", "PATCH"}
_MAX_BODY_CHARS = 12_000
_MAX_RAW_BYTES = 2_000_000
_REQUEST_TIMEOUT = httpx.Timeout(20.0, connect=5.0)


def display_url(url: str) -> str:
    return str(url or "").replace("host.docker.internal", "localhost")


def _runtime_url(url: str) -> str:
    from inventory.net import probe_url

    return probe_url(str(url or ""))


def replay_allowed(method: str, url: str) -> tuple[bool, str]:
    from urllib.parse import urlsplit

    normalized_method = str(method or "GET").upper()
    path = urlsplit(str(url or "")).path.lower()
    if normalized_method in _BLOCKED_METHODS:
        return False, f"{normalized_method} replay is blocked"
    if normalized_method == "PUT":
        return False, "PUT replay is blocked"
    if any(token in path for token in ("logout", "password", "payment", "refund", "withdraw")):
        return False, "destructive endpoint replay is blocked"
    return True, ""


def _endpoint_from_evidence(data_dir: Path, evidence: dict[str, Any]) -> Any | None:
    from inventory.load import load_api_tree

    tree = load_api_tree(data_dir)
    if tree is None:
        return None
    endpoint_id = str(evidence.get("endpoint_id") or "")
    method = str(evidence.get("method") or "GET").upper()
    path = str(evidence.get("path") or "")
    base_url = str(evidence.get("base_url") or "").rstrip("/")
    for ep in tree.endpoints:
        if endpoint_id and ep.endpoint_id == endpoint_id:
            return ep
        if ep.method.upper() == method and ep.path == path and ep.base_url.rstrip("/") == base_url:
            return ep
    return None


def _probe_exchange(probe: dict[str, Any]) -> HttpExchange:
    url = _runtime_url(str(probe.get("url") or ""))
    return HttpExchange(
        method=str(probe.get("method") or "GET"),
        url=url,
        display_url=display_url(url),
        request_headers=dict(probe.get("headers") or {}),
        request_body=str(probe.get("body") or ""),
    )


def _load_traversal_fuzz():
    import importlib.util
    from pathlib import Path as P

    path = P(__file__).resolve().parents[3] / "diagnosis" / "modules" / "2-2" / "traversal_fuzz.py"
    spec = importlib.util.spec_from_file_location("g22_traversal_fuzz_capture", path)
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load traversal_fuzz for 2-2 replay")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_probe(
    evidence: dict[str, Any],
    *,
    data_dir: Path,
    account_auth: dict[str, Any] | None,
    inject_payload: bool = True,
) -> dict[str, Any]:
    from inventory.net import probe_url
    from inventory.probe_build import build_body_object, build_probe_request

    rule_id = str(evidence.get("rule_id") or "")
    ep = _endpoint_from_evidence(data_dir, evidence)
    if ep is not None:
        traversal_mod = _load_traversal_fuzz()
        param_in = str(evidence.get("param_in") or "query")
        param_name = str(evidence.get("param") or "")
        payload = str(evidence.get("payload") or "")
        baseline_body = build_body_object(ep)
        baseline_path_defaults = traversal_mod.path_param_defaults(ep)

        probe = build_probe_request(
            ep,
            probe_base_fn=probe_url,
            account_auth=account_auth,
            path_param_defaults=baseline_path_defaults or None,
        )
        if baseline_body and ep.method.upper() in ("POST", "PUT", "PATCH"):
            probe = dict(probe)
            probe["body"] = json.dumps(baseline_body, ensure_ascii=False)

        if (
            inject_payload
            and payload
            and param_name
            and rule_id
            in {
                "2-2-path-traversal",
                "2-2-input-validation",
                "2-2-forced-browse",
                "2-2-idor",
            }
        ):
            return traversal_mod.build_traversal_probe(
                ep,
                param_in=param_in,
                param_name=param_name,
                payload=payload,
                auth=account_auth,
                baseline_body=baseline_body,
                baseline_path_defaults=baseline_path_defaults,
            )
        return probe

    url = str(evidence.get("url") or evidence.get("anonymous_url") or evidence.get("authenticated_url") or "")
    if not url:
        base = str(evidence.get("base_url") or "").rstrip("/")
        path = str(evidence.get("path") or "/")
        url = f"{base}{path}" if base else path
    method = str(evidence.get("method") or "GET")
    return {"method": method, "url": _runtime_url(url), "headers": {}, "body": ""}


def build_probes(
    evidence: dict[str, Any],
    *,
    data_dir: Path,
    account_auth: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    baseline = build_probe(
        evidence,
        data_dir=data_dir,
        account_auth=account_auth,
        inject_payload=False,
    )
    attack = build_probe(
        evidence,
        data_dir=data_dir,
        account_auth=account_auth,
        inject_payload=True,
    )
    return baseline, attack


def build_case_exchanges(
    evidence: dict[str, Any],
    *,
    data_dir: Path,
    account_auth: dict[str, Any] | None = None,
    authenticated_auth: dict[str, Any] | None = None,
) -> tuple[HttpExchange, HttpExchange]:
    if is_unauth_download(evidence):
        auth_probe = build_probe(
            evidence,
            data_dir=data_dir,
            account_auth=authenticated_auth,
            inject_payload=False,
        )
        anon_probe = build_probe(
            evidence,
            data_dir=data_dir,
            account_auth=None,
            inject_payload=False,
        )
        return _probe_exchange(auth_probe), _probe_exchange(anon_probe)

    baseline_probe, attack_probe = build_probes(
        evidence,
        data_dir=data_dir,
        account_auth=account_auth,
    )
    return _probe_exchange(baseline_probe), _probe_exchange(attack_probe)


def _perform(client: httpx.Client, exchange: HttpExchange) -> HttpExchange:
    headers = dict(exchange.request_headers or {})
    body_bytes = (exchange.request_body or "").encode("utf-8") if exchange.request_body else None
    started = time.perf_counter()
    response = client.request(
        exchange.method.upper(),
        exchange.url,
        headers=headers,
        content=body_bytes,
        timeout=_REQUEST_TIMEOUT,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    raw = bytes(response.content or b"")[:_MAX_RAW_BYTES]
    response_headers = {str(k): str(v) for k, v in response.headers.items()}
    # Keep printable text bodies; leave binary/PDF out of response_body to avoid mojibake.
    ctype = ""
    for key, value in response_headers.items():
        if key.lower() == "content-type":
            ctype = value.lower()
            break
    if raw.startswith(b"%PDF") or raw[:2] == b"PK" or any(
        token in ctype for token in ("pdf", "octet-stream", "zip", "msword", "spreadsheet", "excel")
    ):
        text = ""
    else:
        text = (response.text or "")[:_MAX_BODY_CHARS]
    return replace(
        exchange,
        display_url=display_url(exchange.url),
        request_headers=redact_headers(headers),
        request_body=redact_text(exchange.request_body),
        status_code=response.status_code,
        response_headers=redact_headers(response_headers),
        response_body=redact_text(text),
        response_body_raw=raw,
        elapsed_ms=elapsed_ms,
    )


def replay_case(
    case: EvidenceCase,
    *,
    raw_config: dict[str, Any],
    data_dir: Path,
    auth_pool: Any | None = None,
) -> EvidenceCase:
    evidence = dict(case.metadata.get("source_evidence") or {})
    allowed, reason = replay_allowed(case.baseline.method, case.baseline.url)
    if not allowed:
        raise RuntimeError(reason)

    pool = auth_pool or create_auth_pool(raw_config, data_dir=data_dir)
    authenticated_auth = authenticated_auth_for_evidence(evidence, auth_pool=pool)
    account_auth = account_auth_for_evidence(evidence, auth_pool=pool)

    if is_unauth_download(evidence):
        baseline_probe = build_probe(
            evidence,
            data_dir=data_dir,
            account_auth=authenticated_auth,
            inject_payload=False,
        )
        attack_probe = build_probe(
            evidence,
            data_dir=data_dir,
            account_auth=None,
            inject_payload=False,
        )
        auth_mode = "authenticated+anonymous"
        auth_email = (authenticated_auth or {}).get("email")
    else:
        baseline_probe, attack_probe = build_probes(
            evidence,
            data_dir=data_dir,
            account_auth=account_auth,
        )
        auth_mode = "anonymous" if account_auth is None else "authenticated"
        auth_email = (account_auth or {}).get("email")

    baseline_exchange = _probe_exchange(baseline_probe)
    attack_exchange = _probe_exchange(attack_probe)

    allowed, reason = replay_allowed(baseline_exchange.method, baseline_exchange.url)
    if not allowed:
        raise RuntimeError(reason)
    allowed, reason = replay_allowed(attack_exchange.method, attack_exchange.url)
    if not allowed:
        raise RuntimeError(reason)

    metadata = dict(case.metadata)
    metadata["auth"] = {
        "mode": auth_mode,
        "email": auth_email,
        "source": pool.meta.get("source"),
    }

    with httpx.Client(follow_redirects=True, timeout=_REQUEST_TIMEOUT) as client:
        baseline = _perform(client, baseline_exchange)
        attack = _perform(client, attack_exchange)

    from file_compare import build_file_compare, looks_like_download

    file_compare = None
    if looks_like_download(baseline) or looks_like_download(attack):
        compare_mode = (
            "auth_vs_anon" if is_unauth_download(evidence) else "baseline_vs_attack"
        )
        file_compare = build_file_compare(baseline, attack, mode=compare_mode)
        left = file_compare.get("left") or {}
        right = file_compare.get("right") or {}
        metadata["file_compare"] = {
            "enabled": True,
            "mode": compare_mode,
            "identical": file_compare.get("identical"),
            "left_filename": left.get("filename"),
            "right_filename": right.get("filename"),
            "left_size": left.get("size"),
            "right_size": right.get("size"),
            # Legacy keys (unauth manifests).
            "auth_filename": left.get("filename"),
            "anon_filename": right.get("filename"),
            "auth_size": left.get("size"),
            "anon_size": right.get("size"),
        }

    metadata["replay"] = {
        "performed": True,
        "baseline_status": baseline.status_code,
        "attack_status": attack.status_code,
        "payload": case.payload,
        "probe_url": True,
        "unauth_download": is_unauth_download(evidence),
        "file_download_compare": bool(file_compare),
    }
    if file_compare is not None:
        metadata["file_compare_detail"] = file_compare
    return replace(case, baseline=baseline, attack=attack, metadata=metadata)
