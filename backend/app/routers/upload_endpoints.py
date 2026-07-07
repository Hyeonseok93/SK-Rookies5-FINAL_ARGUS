from __future__ import annotations

from fastapi import APIRouter

from app.schemas import (
    SaveTransferEndpointsRequest,
    SaveTransferEndpointsResponse,
    TransferEndpointResolved,
    TransferEndpointsResponse,
)
from app.services.transfer_endpoints_service import (
    dashboard_transfer_entries,
    load_transfer_endpoints,
    save_transfer_endpoints,
)

router = APIRouter(prefix="/upload-endpoints", tags=["upload-endpoints"])


def _resolved_payload() -> list[dict[str, str]]:
    return dashboard_transfer_entries("upload")


@router.get("", response_model=TransferEndpointsResponse)
def get_upload_endpoints() -> TransferEndpointsResponse:
    data = load_transfer_endpoints("upload")
    resolved = [TransferEndpointResolved(**row) for row in _resolved_payload()]
    return TransferEndpointsResponse(endpoints=data["endpoints"], resolved=resolved)


@router.put("", response_model=SaveTransferEndpointsResponse)
def put_upload_endpoints(body: SaveTransferEndpointsRequest) -> SaveTransferEndpointsResponse:
    data = save_transfer_endpoints("upload", [e.model_dump() for e in body.endpoints])
    resolved = [TransferEndpointResolved(**row) for row in _resolved_payload()]
    count = len(data["endpoints"])
    return SaveTransferEndpointsResponse(
        ok=True,
        endpoints=data["endpoints"],
        resolved=resolved,
        message=f"Saved {count} upload endpoint(s).",
    )
