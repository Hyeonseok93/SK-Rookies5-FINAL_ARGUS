from __future__ import annotations

from fastapi import APIRouter

from app.schemas import BaseUrlsResponse, SaveBaseUrlsRequest, SaveBaseUrlsResponse
from app.services.base_urls_service import load_base_urls, save_base_urls

router = APIRouter(prefix="/base-urls", tags=["base-urls"])


@router.get("", response_model=BaseUrlsResponse)
def get_base_urls() -> BaseUrlsResponse:
    data = load_base_urls()
    return BaseUrlsResponse(**data)


@router.put("", response_model=SaveBaseUrlsResponse)
def put_base_urls(body: SaveBaseUrlsRequest) -> SaveBaseUrlsResponse:
    data = save_base_urls([u.model_dump() for u in body.urls])
    count = len(data["urls"])
    return SaveBaseUrlsResponse(
        ok=True,
        urls=data["urls"],
        message=f"Saved {count} base URL(s).",
    )
