from __future__ import annotations

import os
import uuid
import json
import yaml
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile

from app.config import BACKEND_ROOT, load_config
from app.schemas import (
    BuildInventoryResponse,
    DiscoverProgressResponse,
    EndpointDetailResponse,
    EndpointListResponse,
    EndpointSummary,
    HeaderFieldSummary,
    InputParamSummary,
    AccountAccessSummary,
    LoginEntryReportResponse,
    LoginEntryPointSummary,
    LoginAccountEntrySummary,
    InventoryStats,
    SourceOption,
    SourceOptionsResponse,
    VerifyInventoryResponse,
    VerifyReportResponse,
    VerifyReportSummary,
    VerifyResultSummary,
)
from app.services.auth_probe_service import account_access_for_endpoint
from app.services.probe_report import filter_deduped_by_outcome, summarize_probe_results
from app.services.base_urls_service import resolved_base_url_strings
from app.services.inventory_service import (
    build_inventory,
    compute_stats,
    persist_inventory,
)
from app.services.verify_service import (
    merge_verification_payloads,
    persist_verification,
    verify_inventory_async,
)
from app.services.discover_service import discover_inventory_async
from app.services.zap_util import ZapNotAvailableError
from app.services import discover_progress
from inventory.load import load_cached_tree
from inventory.schema import ApiTree

router = APIRouter(prefix="/inventory", tags=["inventory"])

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
API_TREE_PATH = DATA_DIR / "api-tree.json"
API_TREE_READY_PATH = DATA_DIR / "api-tree-ready.json"
API_TREE_VERIFIED_PATH = DATA_DIR / "api-tree-verified.json"
VERIFY_REPORT_PATH = DATA_DIR / "verify-report.json"
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", str(BACKEND_ROOT / "config.yaml")))

SOURCE_DEFS = [
    SourceOption(id="url_list", label="URL List"),
    SourceOption(id="api_list", label="API List"),
    SourceOption(id="openapi", label="Swagger"),
]


def _load_cached_tree(inventory: str = "ready") -> ApiTree | None:
    return load_cached_tree(DATA_DIR, inventory=inventory)


def _find_endpoint_tree(endpoint_id: str) -> ApiTree | None:
    for path in (API_TREE_VERIFIED_PATH, API_TREE_READY_PATH, API_TREE_PATH):
        if not path.is_file():
            continue
        tree = ApiTree.load(path)
        if any(ep.endpoint_id == endpoint_id for ep in tree.endpoints):
            return tree
    return None


async def _save_upload(upload: UploadFile, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(await upload.read())


def _ext_ok(filename: str, allowed: set[str]) -> bool:
    suffix = Path(filename or "").suffix.lower()
    return suffix in allowed


@router.get("/stats", response_model=InventoryStats)
def get_stats(
    inventory: str = Query("ready", description="ready (built) or verified (after verify)"),
) -> InventoryStats:
    tree = _load_cached_tree(inventory)
    if not tree:
        missing = ["no_build_yet"] if inventory == "ready" else ["not_verified_yet"]
        return InventoryStats(sources_missing=missing)
    return InventoryStats(**compute_stats(tree))


@router.get("/tree")
def get_tree(
    inventory: str = Query("ready", description="ready or verified"),
) -> dict:
    tree = _load_cached_tree(inventory)
    if not tree:
        detail = "No api-tree built yet. POST /api/inventory/build first."
        if inventory == "verified":
            detail = "No verified inventory yet. Run Verify first."
        raise HTTPException(status_code=404, detail=detail)
    return tree.to_dict()


@router.get("/endpoints", response_model=EndpointListResponse)
def list_endpoints(
    q: str | None = Query(None, description="Filter by path/method/base_url"),
    source: str | None = Query(None, description="Filter by source id (url_list, api_list, openapi)"),
    inventory: str = Query("ready", description="ready (built) or verified (after verify)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> EndpointListResponse:
    tree = _load_cached_tree(inventory)
    if not tree:
        return EndpointListResponse(total=0, items=[])

    items = tree.endpoints
    if q:
        needle = q.lower()
        items = [
            e
            for e in items
            if needle in e.path.lower()
            or needle in e.method.lower()
            or needle in e.base_url.lower()
        ]
    if source:
        items = [e for e in items if source in e.sources]

    items = sorted(
        items,
        key=lambda e: (
            e.base_url,
            0 if e.kind == "frontend" else 1,
            e.path,
            e.method,
        ),
    )

    total = len(items)
    page = items[offset : offset + limit]
    summaries = [
        EndpointSummary(
            id=ep.endpoint_id,
            method=ep.method,
            path=ep.path,
            base_url=ep.base_url,
            kind=ep.kind,
            tags=ep.tags,
            sources=ep.sources,
            input_count=len(ep.request_params) + len(ep.response_params),
            inputs_preview=[
                f"{i.in_}.{i.name}" for i in (ep.request_params + ep.response_params)
            ][:8],
        )
        for ep in page
    ]
    return EndpointListResponse(total=total, items=summaries)


def _param_summaries(params) -> list[InputParamSummary]:
    return [
        InputParamSummary(
            in_=inp.in_,
            name=inp.name,
            type=inp.type,
            required=inp.required,
            sample=inp.sample,
            role=inp.role,
            sources=sorted(set(inp.sources)),
        )
        for inp in params
    ]


@router.get("/endpoints/detail", response_model=EndpointDetailResponse)
def get_endpoint_detail(
    endpoint_id: str = Query(..., description="Endpoint id from list (base:METHOD:path)"),
    inventory: str | None = Query(None, description="ready or verified; searches all if omitted"),
) -> EndpointDetailResponse:
    if inventory in ("ready", "verified"):
        tree = _load_cached_tree(inventory)
    else:
        tree = _find_endpoint_tree(endpoint_id)
    if not tree:
        return EndpointDetailResponse(found=False)

    ep = next((e for e in tree.endpoints if e.endpoint_id == endpoint_id), None)
    if not ep:
        return EndpointDetailResponse(found=False)

    request_params = _param_summaries(ep.request_params)
    response_params = _param_summaries(ep.response_params)
    request_headers = [
        HeaderFieldSummary(
            name=hdr.name,
            sample=hdr.sample,
            role=hdr.role,
            required=hdr.required,
            sources=sorted(set(hdr.sources)),
        )
        for hdr in ep.request_headers
    ]
    response_headers = [
        HeaderFieldSummary(
            name=hdr.name,
            sample=hdr.sample,
            role=hdr.role,
            required=hdr.required,
            sources=sorted(set(hdr.sources)),
        )
        for hdr in ep.response_headers
    ]

    account_access: list[AccountAccessSummary] = []
    if VERIFY_REPORT_PATH.is_file():
        report = json.loads(VERIFY_REPORT_PATH.read_text(encoding="utf-8"))
        for row in account_access_for_endpoint(report.get("results") or [], ep.endpoint_id):
            account_access.append(AccountAccessSummary(**row))

    return EndpointDetailResponse(
        found=True,
        id=ep.endpoint_id,
        method=ep.method.upper(),
        path=ep.path,
        base_url=ep.base_url,
        kind=ep.kind,
        tags=sorted(set(ep.tags)),
        auth=sorted(set(ep.auth)),
        sources=sorted(set(ep.sources)),
        request_params=request_params,
        response_params=response_params,
        request_headers=request_headers,
        response_headers=response_headers,
        account_access=account_access,
    )


@router.get("/login-entry-report", response_model=LoginEntryReportResponse)
def get_login_entry_report() -> LoginEntryReportResponse:
    if not VERIFY_REPORT_PATH.is_file():
        return LoginEntryReportResponse(available=False)

    raw = json.loads(VERIFY_REPORT_PATH.read_text(encoding="utf-8"))
    report = raw.get("login_entry_report")
    if not report:
        return LoginEntryReportResponse(available=False, checked_at=raw.get("checked_at"))

    return LoginEntryReportResponse(
        available=True,
        checked_at=raw.get("checked_at"),
        session_count=int(report.get("session_count", 0)),
        login_entries=[LoginEntryPointSummary(**e) for e in report.get("login_entries", [])],
        accounts=[LoginAccountEntrySummary(**a) for a in report.get("accounts", [])],
        entry_specific_accounts=list(report.get("entry_specific_accounts") or []),
    )


@router.get("/source-options", response_model=SourceOptionsResponse)
def get_source_options() -> SourceOptionsResponse:
    return SourceOptionsResponse(sources=SOURCE_DEFS)


@router.get("/verify-report", response_model=VerifyReportResponse)
def get_verify_report(
    outcome: str | None = Query(
        None,
        description="Filter by outcome: final, discovered, or rejected",
    ),
    q: str | None = Query(None, description="Filter by path/method/base_url/status"),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> VerifyReportResponse:
    if not VERIFY_REPORT_PATH.is_file():
        return VerifyReportResponse(available=False)

    raw = json.loads(VERIFY_REPORT_PATH.read_text(encoding="utf-8"))
    summary_raw = raw.get("summary") or {}
    all_results = raw.get("results") or []
    computed = summarize_probe_results(all_results) if all_results else {}

    summary = VerifyReportSummary(
        total_checked=int(summary_raw.get("endpoints_probed", summary_raw.get("total_checked", computed.get("endpoints_probed", 0)))),
        confirmed=int(summary_raw.get("confirmed", computed.get("confirmed", 0))),
        params_issues=int(summary_raw.get("params_issues", computed.get("params_issues", 0))),
        rejected=int(summary_raw.get("rejected", computed.get("rejected", 0))),
        verified_count=int(summary_raw.get("verified_count", computed.get("verified_count", 0))),
        final_count=int(summary_raw.get("final_count", summary_raw.get("verified_count", computed.get("final_count", 0)))),
        discovered_count=int(summary_raw.get("discovered_count", computed.get("discovered_count", 0))),
        probe_runs=int(summary_raw.get("probe_runs", computed.get("probe_runs", len(all_results)))),
        accounts_logged_in=int(summary_raw.get("accounts_logged_in", 0)),
    )

    results = filter_deduped_by_outcome(all_results, outcome)

    if q:
        needle = q.lower()
        results = [
            r
            for r in results
            if needle in str(r.get("path", "")).lower()
            or needle in str(r.get("method", "")).lower()
            or needle in str(r.get("base_url", "")).lower()
            or needle in str(r.get("status", "")).lower()
        ]

    results = sorted(
        results,
        key=lambda r: (
            str(r.get("base_url", "")),
            str(r.get("path", "")),
            str(r.get("method", "")),
        ),
    )

    total = len(results)
    page = results[offset : offset + limit]
    items = [
        VerifyResultSummary(
            endpoint_id=str(r.get("endpoint_id", "")),
            method=str(r.get("method", "")),
            path=str(r.get("path", "")),
            base_url=str(r.get("base_url", "")),
            url=str(r.get("url", "")),
            http_status=r.get("http_status"),
            status=str(r.get("status", "")),
            note=str(r.get("note", "")),
            include_in_final=bool(r.get("include_in_final")),
            discovered=bool(r.get("discovered")),
        )
        for r in page
    ]

    return VerifyReportResponse(
        available=True,
        checked_at=raw.get("checked_at"),
        summary=summary,
        total=total,
        items=items,
    )


@router.post("/build", response_model=BuildInventoryResponse)
async def build_attack_surface(
    url_list_enabled: bool = Form(False),
    api_list_enabled: bool = Form(False),
    openapi_enabled: bool = Form(False),
    url_list_file: UploadFile | None = File(None),
    api_list_file: UploadFile | None = File(None),
    openapi_file: UploadFile | None = File(None),
) -> BuildInventoryResponse:
    if not any([url_list_enabled, api_list_enabled, openapi_enabled]):
        return BuildInventoryResponse(
            ok=False,
            stats=InventoryStats(),
            message="Select at least one data source and upload a file.",
        )

    batch_dir = UPLOAD_DIR / uuid.uuid4().hex
    url_list_path: Path | None = None
    api_list_path: Path | None = None
    openapi_path: Path | None = None

    if url_list_enabled:
        if not url_list_file or not url_list_file.filename:
            return BuildInventoryResponse(ok=False, stats=InventoryStats(), message="URL List file required.")
        if not _ext_ok(url_list_file.filename, {".txt"}):
            return BuildInventoryResponse(ok=False, stats=InventoryStats(), message="URL List: use .txt (one URL per line)")
        url_list_path = batch_dir / "url-list.txt"
        await _save_upload(url_list_file, url_list_path)

    if api_list_enabled:
        if not api_list_file or not api_list_file.filename:
            return BuildInventoryResponse(ok=False, stats=InventoryStats(), message="API List file required.")
        if not _ext_ok(api_list_file.filename, {".txt"}):
            return BuildInventoryResponse(ok=False, stats=InventoryStats(), message="API List: use .txt (METHOD /path per line)")
        api_list_path = batch_dir / "api-list.txt"
        await _save_upload(api_list_file, api_list_path)

    if openapi_enabled:
        if not openapi_file or not openapi_file.filename:
            return BuildInventoryResponse(ok=False, stats=InventoryStats(), message="Swagger file required.")
        if not _ext_ok(openapi_file.filename, {".json", ".yaml", ".yml"}):
            return BuildInventoryResponse(ok=False, stats=InventoryStats(), message="Swagger file: use .json or .yaml")
        openapi_path = batch_dir / f"openapi{Path(openapi_file.filename).suffix.lower()}"
        await _save_upload(openapi_file, openapi_path)

    cfg = load_config()
    saved_bases = resolved_base_url_strings()
    if saved_bases:
        build_bases = saved_bases
    else:
        cfg_dict = cfg.model_dump()
        inv = cfg_dict.get("inventory") or {}
        md = inv.get("markdown") or {}
        build_bases = []
        if md.get("frontend_base_url"):
            build_bases.append(str(md["frontend_base_url"]).rstrip("/"))
        for t in cfg_dict.get("targets") or []:
            u = str(t.get("base_url", "")).rstrip("/")
            if u and u not in build_bases:
                build_bases.append(u)

    tree = build_inventory(
        cfg,
        url_list=url_list_enabled,
        api_list=api_list_enabled,
        openapi=openapi_enabled,
        url_list_path=url_list_path,
        api_list_path=api_list_path,
        openapi_path=openapi_path,
        base_urls=build_bases or None,
    )

    if not tree.endpoints:
        return BuildInventoryResponse(
            ok=False,
            stats=InventoryStats(**compute_stats(tree)),
            message="No endpoints collected from uploaded files.",
        )

    artifacts = persist_inventory(tree, DATA_DIR, openapi_path)
    stats = InventoryStats(**compute_stats(tree))
    return BuildInventoryResponse(
        ok=True,
        stats=stats,
        artifacts=artifacts,
        message=f"Built attack surface map with {stats.api_endpoints} API endpoints.",
    )


def _config_path() -> Path:
    return CONFIG_PATH if CONFIG_PATH.is_file() else BACKEND_ROOT / "config.yaml"


def _build_verify_response(
    tree: ApiTree,
    payload: dict,
    artifacts: dict[str, str],
) -> VerifyInventoryResponse:
    verified_count = int(payload["verified_count"])
    unreachable = sum(1 for r in payload["results"] if r["status"] == "unreachable")
    summary: dict[str, int | str] = {
        "total_checked": payload["total_checked"],
        "confirmed": payload["confirmed"],
        "params_issues": payload["params_issues"],
        "rejected": payload["rejected"],
        "verified_count": verified_count,
        "mode": str(payload.get("mode", "probe")),
    }
    if payload.get("newly_discovered") is not None:
        summary["newly_discovered"] = int(payload["newly_discovered"])
    if payload.get("zap_urls_collected") is not None:
        summary["zap_urls_collected"] = int(payload["zap_urls_collected"])

    if verified_count == 0:
        stats = InventoryStats(**compute_stats(tree))
        no_status = sum(1 for r in payload["results"] if r.get("http_status") is None)
        hint = ""
        if no_status == len(payload["results"]):
            hint = (
                " No HTTP responses recorded — is Onde running? "
                f"(Docker probes via {os.environ.get('ARGUS_PROBE_HOST', 'host.docker.internal')})."
            )
        elif unreachable == len(payload["results"]):
            hint = (
                " All targets were unreachable — is Onde running? "
                f"(Docker probes via {os.environ.get('ARGUS_PROBE_HOST', 'host.docker.internal')})."
            )
        return VerifyInventoryResponse(
            ok=False,
            stats=stats,
            summary=summary,
            artifacts=artifacts,
            message=(
                f"Verified 0/{payload['total_checked']} endpoints.{hint} "
                "Original inventory was kept (not wiped)."
            ),
        )

    verified_tree: ApiTree = payload["verified_tree"]
    stats = InventoryStats(**compute_stats(verified_tree))
    mode = payload.get("mode", "probe")
    extra = ""
    if mode == "zap_discover" and payload.get("newly_discovered"):
        extra = f" +{payload['newly_discovered']} newly discovered via ZAP."
    return VerifyInventoryResponse(
        ok=True,
        stats=stats,
        summary=summary,
        artifacts=artifacts,
        message=(
            f"Verified {verified_count}/{payload['total_checked']} endpoints "
            f"({mode}). Rejected {payload['rejected']}.{extra} Final inventory saved."
        ),
    )


@router.get("/discover/progress", response_model=DiscoverProgressResponse)
def get_discover_progress() -> DiscoverProgressResponse:
    snap = discover_progress.snapshot()
    return DiscoverProgressResponse(**snap)


@router.post("/verify", response_model=VerifyInventoryResponse)
async def verify_attack_surface(
    use_httpx: bool = Query(True, description="Run httpx probe (direct HTTP, no ZAP)"),
    use_spider: bool = Query(False, description="Run ZAP traditional spider"),
    use_ajax_spider: bool = Query(False, description="Run ZAP ajax spider"),
) -> VerifyInventoryResponse:
    tree = _load_cached_tree("ready")
    if not tree or not tree.endpoints:
        tree = _load_cached_tree("verified")
    if not tree or not tree.endpoints:
        return VerifyInventoryResponse(
            ok=False,
            stats=InventoryStats(sources_missing=["no_build_yet"]),
            message='Build attack surface first, then click "Verify".',
        )

    if not use_httpx and not use_spider and not use_ajax_spider:
        return VerifyInventoryResponse(
            ok=False,
            stats=InventoryStats(**compute_stats(tree)),
            message="Select at least one verify option: httpx probe, Spider, or Ajax Spider.",
        )

    discover_progress.reset(total_steps=6)
    discover_progress.persist(DATA_DIR)

    raw_cfg = yaml.safe_load(_config_path().read_text(encoding="utf-8")) or {}
    auth_cfg = raw_cfg.get("auth") or {}

    payload: dict | None = None
    working_tree = tree
    need_zap = use_spider or use_ajax_spider

    if need_zap:
        try:
            payload = await discover_inventory_async(
                tree,
                data_dir=DATA_DIR,
                config_path=_config_path(),
                spider_enabled=use_spider,
                ajax_spider_enabled=use_ajax_spider,
            )
            working_tree = payload["verified_tree"]
        except ZapNotAvailableError as exc:
            if not use_httpx:
                return VerifyInventoryResponse(
                    ok=False,
                    stats=InventoryStats(**compute_stats(tree)),
                    message=(
                        f"ZAP discover failed: {exc} "
                        "Start ZAP on port 8090 or enable httpx probe."
                    ),
                )

    if use_httpx:
        discover_progress.update(
            phase="probe",
            message="httpx probe (params + validation errors)…",
            step=1,
        )
        discover_progress.persist(DATA_DIR)
        httpx_payload = await verify_inventory_async(working_tree, auth_cfg=auth_cfg)
        if payload is None:
            payload = httpx_payload
            payload["mode"] = "probe"
        else:
            payload = merge_verification_payloads(payload, httpx_payload)
        discover_progress.finish("Verify complete.")
        discover_progress.persist(DATA_DIR)
    elif payload is None:
        discover_progress.update(
            phase="probe",
            message="ZAP not ready — httpx probe fallback…",
            step=1,
        )
        discover_progress.persist(DATA_DIR)
        payload = await verify_inventory_async(tree, auth_cfg=auth_cfg)
        payload["mode"] = "probe"
        discover_progress.finish("Probe complete.")
        discover_progress.persist(DATA_DIR)

    artifacts = persist_verification(DATA_DIR, payload, original_tree=tree)
    return _build_verify_response(tree, payload, artifacts)
