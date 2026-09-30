from fastapi import FastAPI

from sentinel.api.exception_handlers import register_exception_handlers
from sentinel.api.routers.applications import router as applications_router
from sentinel.api.routers.auth import router as auth_router
from sentinel.api.routers.dashboard import router as dashboard_router
from sentinel.api.routers.repository import router as repository_router
from sentinel.api.routers.scans import router as scans_router

app = FastAPI(
    title="Sentinel API",
    version="0.1.0",
)


register_exception_handlers(
    app,
)


app.include_router(
    auth_router,
)

app.include_router(
    dashboard_router,
)

app.include_router(
    applications_router,
)

app.include_router(
    repository_router,
)

app.include_router(
    scans_router,
)
