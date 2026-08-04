from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth_users import bootstrap_admin_if_needed
from app.routers import (
    auth,
    base_urls,
    diagnosis,
    download_endpoints,
    inventory,
    login_endpoints,
    redirect_sink,
    test_accounts,
    upload_endpoints,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap_admin_if_needed()
    yield


app = FastAPI(
    title="ARGUS API",
    description="Attack surface inventory & security assessment backend",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(inventory.router, prefix="/api")
app.include_router(test_accounts.router, prefix="/api")
app.include_router(base_urls.router, prefix="/api")
app.include_router(login_endpoints.router, prefix="/api")
app.include_router(upload_endpoints.router, prefix="/api")
app.include_router(download_endpoints.router, prefix="/api")
app.include_router(diagnosis.router, prefix="/api")
app.include_router(redirect_sink.router)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "argus-backend"}
