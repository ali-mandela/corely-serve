"""
Corely Enterprise System — Main application.

Assembles all packages: config, middleware, auth, organization, users.
"""

import time
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from base.config import settings, db_manager
from base.middleware import AuthPermissionMiddleware
from base.utils import Logger

# ── Route imports ────────────────────────────────────────────────
from base.auth import auth_router
from base.organization import org_router
from base.users import users_router
from base.items import items_router
from base.inventory import inventory_router
from base.customers import customers_router
from base.vendors import vendors_router
from base.pos import pos_router
from base.invoices import invoices_router
from base.audit import audit_router
from base.profile import profile_router

logger = Logger("request")


# ── Request Logging Middleware ───────────────────────────────────
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs every request: method, path, status code, and duration."""

    async def dispatch(self, request: Request, call_next):
        start = time.time()
        method = request.method
        path = request.url.path
        client = request.client.host if request.client else "unknown"

        logger.info(f"--> {method} {path} (from {client})")

        try:
            response = await call_next(request)
        except Exception as exc:
            duration = round((time.time() - start) * 1000, 2)
            logger.error(f"<-- {method} {path} | 500 | {duration}ms")
            logger.error(f"    Exception: {exc}")
            logger.error(traceback.format_exc())
            raise

        duration = round((time.time() - start) * 1000, 2)
        status = response.status_code

        if status >= 500:
            logger.error(f"<-- {method} {path} | {status} | {duration}ms")
        elif status >= 400:
            logger.warning(f"<-- {method} {path} | {status} | {duration}ms")
        else:
            logger.info(f"<-- {method} {path} | {status} | {duration}ms")

        return response


# ── Lifespan ─────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await db_manager.connect()
    yield
    db_manager.close()


# ── App factory ──────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Multi-tenant RBAC enterprise system",
        docs_url="/api/docs",
        lifespan=lifespan,
    ) 

    # ── CORS (must be first) ─────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allowed_methods,
        allow_headers=settings.cors_allowed_headers,
    )

    # ── Request logging (runs on every request) ──────────────
    app.add_middleware(RequestLoggingMiddleware)

    # ── Auth + RBAC middleware ───────────────────────────────
    app.add_middleware(AuthPermissionMiddleware)

    # ── Global exception handler ─────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception on {request.method} {request.url.path}:")
        logger.error(traceback.format_exc())
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": {
                    "code": 500,
                    "message": str(exc) if settings.debug else "Internal server error",
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    # ── Routes ───────────────────────────────────────────────
    v = settings.api_version  # "v1"

    app.include_router(
        auth_router,
        prefix=f"/api/{v}/auth",
        tags=["Authentication"],
    )
    app.include_router(
        org_router,
        prefix=f"/base/api/{v}",
        tags=["Organization Setup"],
    )
    app.include_router(
        users_router,
        prefix=f"/api/{v}/users",
        tags=["Users"],
    )
    app.include_router(
        items_router,
        prefix=f"/api/{v}/items",
        tags=["Items / Products"],
    )
    app.include_router(
        inventory_router,
        prefix=f"/api/{v}/inventory",
        tags=["Inventory"],
    )
    app.include_router(
        customers_router,
        prefix=f"/api/{v}/customers",
        tags=["Customers"],
    )
    app.include_router(
        vendors_router,
        prefix=f"/api/{v}/vendors",
        tags=["Vendors / Suppliers"],
    )
    app.include_router(
        pos_router,
        prefix=f"/api/{v}/pos",
        tags=["POS (Point of Sale)"],
    )
    app.include_router(
        invoices_router,
        prefix=f"/api/{v}/invoices",
        tags=["Invoicing"],
    )
    app.include_router(
        audit_router,
        prefix=f"/api/{v}/audit-logs",
        tags=["Audit Logs"],
    )
    app.include_router(
        profile_router,
        prefix=f"/api/{v}/profile",
        tags=["Profile & Password"],
    )

    # ── Health check ─────────────────────────────────────────
    @app.get("/health")
    async def health():
        return {
            "status": "healthy",
            "app": settings.app_name,
            "version": settings.app_version,
            "database": db_manager.is_connected,
        }

    return app


# ── Create the app instance ──────────────────────────────────────
app = create_app()