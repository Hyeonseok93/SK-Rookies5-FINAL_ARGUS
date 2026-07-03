from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from app.schemas import (
    DiagnosisCatalogModule,
    DiagnosisCatalogResponse,
    DiagnosisProgressResponse,
    DiagnosisRunAllResponse,
    DiagnosisRunSectionRequest,
    DiagnosisRunSectionResponse,
    DiagnosisSectionReportResponse,
    DiagnosisFindingSummary,
    ReplayListResponse,
    ReplayFindingSummary,
    ReplayRunRequest,
    ReplayRunSectionResponse,
    ReplayRunResultResponse,
    ReplayStepResult,
)
from app.services import diagnosis_service

router = APIRouter(prefix="/diagnosis", tags=["diagnosis"])


@router.get("/catalog", response_model=DiagnosisCatalogResponse)
def get_catalog() -> DiagnosisCatalogResponse:
    items = [
        DiagnosisCatalogModule.model_validate(row)
        for row in diagnosis_service.catalog()
    ]
    return DiagnosisCatalogResponse(modules=items, total=len(items))


def _report_to_response(report) -> DiagnosisSectionReportResponse:
    return DiagnosisSectionReportResponse(
        section_id=report.section_id,
        title=report.title,
        chapter=report.chapter,
        status=report.status,
        implemented=report.implemented,
        message=report.message,
        checked_at=report.checked_at,
        findings=[
            DiagnosisFindingSummary(
                severity=f.severity,
                message=f.message,
                evidence=f.evidence,
            )
            for f in report.findings
        ],
    )


@router.post("/cancel")
def cancel_diagnosis_run() -> dict[str, object]:
    section_id = diagnosis_service.request_cancel_run()
    if not section_id:
        raise HTTPException(status_code=409, detail="No diagnosis run in progress")
    return {"ok": True, "section_id": section_id}


@router.get("/progress", response_model=DiagnosisProgressResponse)
def get_diagnosis_progress() -> DiagnosisProgressResponse:
    from app.services import diagnosis_progress

    return DiagnosisProgressResponse(**diagnosis_progress.snapshot())


@router.get("/modules/{section_id}/report", response_model=DiagnosisSectionReportResponse)
def get_module_report(section_id: str) -> DiagnosisSectionReportResponse:
    report = diagnosis_service.get_report(section_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"No report for module {section_id}")
    return _report_to_response(report)


@router.post("/modules/{section_id}/run", response_model=DiagnosisRunSectionResponse)
def run_module(
    section_id: str,
    body: DiagnosisRunSectionRequest | None = None,
) -> DiagnosisRunSectionResponse:
    g22_opts = None
    g71_opts = None
    g72_opts = None
    g73_opts = None
    g74_opts = None
    g52_opts = None
    g61_opts = None
    g62_opts = None
    g36_opts = None
    g35_opts = None
    g32_opts = None
    g34_opts = None
    g12_opts = None
    g15_opts = None
    g16_opts = None
    g41_opts = None
    g42_opts = None
    if body and body.g12 is not None:
        g12_opts = body.g12.model_dump(exclude_none=True)
    if body and body.g15 is not None:
        g15_opts = body.g15.model_dump(exclude_none=True)
    if body and body.g16 is not None:
        g16_opts = body.g16.model_dump(exclude_none=True)
    if body and body.g41 is not None:
        g41_opts = body.g41.model_dump(exclude_none=True)
    if body and body.g22 is not None:
        g22_opts = body.g22.model_dump(exclude_none=True)
    if body and body.g71 is not None:
        g71_opts = body.g71.model_dump(exclude_none=True)
    if body and body.g72 is not None:
        g72_opts = body.g72.model_dump(exclude_none=True)
    if body and body.g73 is not None:
        g73_opts = body.g73.model_dump(exclude_none=True)
    if body and body.g74 is not None:
        g74_opts = body.g74.model_dump(exclude_none=True)
    if body and body.g52 is not None:
        g52_opts = body.g52.model_dump(exclude_none=True)
    if body and body.g61 is not None:
        g61_opts = body.g61.model_dump(exclude_none=True)
    if body and body.g62 is not None:
        g62_opts = body.g62.model_dump(exclude_none=True)
    if body and body.g36 is not None:
        g36_opts = body.g36.model_dump(exclude_none=True)
    if body and body.g35 is not None:
        g35_opts = body.g35.model_dump(exclude_none=True)
    if body and body.g32 is not None:
        g32_opts = body.g32.model_dump(exclude_none=True)
    if body and body.g34 is not None:
        g34_opts = body.g34.model_dump(exclude_none=True)
    if body and body.g42 is not None:
        g42_opts = body.g42.model_dump(exclude_none=True)
    run_kwargs = dict(
        g12_options=g12_opts,
        g15_options=g15_opts,
        g41_options=g41_opts,
        g22_options=g22_opts,
        g71_options=g71_opts,
        g72_options=g72_opts,
        g73_options=g73_opts,
        g74_options=g74_opts,
        g52_options=g52_opts,
        g61_options=g61_opts,
        g62_options=g62_opts,
        g36_options=g36_opts,
        g35_options=g35_opts,
        g32_options=g32_opts,
        g34_options=g34_opts,
        g42_options=g42_opts,
        g16_options=g16_opts,
    )
    if section_id == "6-1":
        try:
            diagnosis_service.start_section_run_background(section_id, **run_kwargs)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        payload = DiagnosisRunSectionResponse(
            ok=True,
            accepted=True,
            async_run=True,
            report=None,
        )
        return JSONResponse(
            status_code=202,
            content=payload.model_dump(),
        )
    try:
        report = diagnosis_service.run_section(section_id, **run_kwargs)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DiagnosisRunSectionResponse(ok=True, report=_report_to_response(report))


@router.post("/run-all", response_model=DiagnosisRunAllResponse)
def run_all() -> DiagnosisRunAllResponse:
    reports = diagnosis_service.run_all()
    return DiagnosisRunAllResponse(
        ok=True,
        total=len(reports),
        reports=[_report_to_response(r) for r in reports],
    )


@router.get("/modules/{section_id}/replay", response_model=ReplayListResponse)
def list_replay(section_id: str) -> ReplayListResponse:
    try:
        rows = diagnosis_service.list_replay_findings(section_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return ReplayListResponse(
        section_id=section_id,
        total=len(rows),
        findings=[ReplayFindingSummary.model_validate(r) for r in rows],
    )


@router.post("/modules/{section_id}/replay", response_model=ReplayRunSectionResponse)
def run_replay(
    section_id: str,
    body: ReplayRunRequest | None = None,
) -> ReplayRunSectionResponse:
    req = body or ReplayRunRequest()
    try:
        results = diagnosis_service.run_replay(
            section_id,
            finding_id=req.finding_id,
            use_playwright=req.use_playwright,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    mapped = [
        ReplayRunResultResponse(
            finding_id=r.finding_id,
            ok=r.ok,
            output_dir=r.output_dir,
            message=r.message,
            steps=[
                ReplayStepResult(
                    step_id=s.step_id,
                    action=s.action,
                    ok=s.ok,
                    message=s.message,
                    artifacts=s.artifacts,
                )
                for s in r.steps
            ],
        )
        for r in results
    ]
    return ReplayRunSectionResponse(
        ok=all(r.ok for r in mapped) if mapped else True,
        section_id=section_id,
        results=mapped,
    )
