from __future__ import annotations

from fastapi import APIRouter

from app.deps import UserDataDir
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


@router.get("", response_model=TransferEndpointsResponse)
def get_upload_endpoints(data_dir: UserDataDir) -> TransferEndpointsResponse:
    data = load_transfer_endpoints("upload", data_dir)
    resolved = [
        TransferEndpointResolved(**row) for row in dashboard_transfer_entries("upload", data_dir=data_dir)
    ]
    return TransferEndpointsResponse(endpoints=data["endpoints"], resolved=resolved)


@router.put("", response_model=SaveTransferEndpointsResponse)
def put_upload_endpoints(
    body: SaveTransferEndpointsRequest,
    data_dir: UserDataDir,
) -> SaveTransferEndpointsResponse:
    data = save_transfer_endpoints("upload", [e.model_dump() for e in body.endpoints], data_dir)
    resolved = [
        TransferEndpointResolved(**row) for row in dashboard_transfer_entries("upload", data_dir=data_dir)
    ]
    count = len(data["endpoints"])
    return SaveTransferEndpointsResponse(
        ok=True,
        endpoints=data["endpoints"],
        resolved=resolved,
        message=f"Saved {count} upload endpoint(s).",
    )
