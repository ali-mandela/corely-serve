"""
Corely Enterprise System — Main application.

Assembles all packages: config, middleware, auth, organization, users.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from base.config import settings, db_manager
from base.middleware import AuthPermissionMiddleware

# ── Route imports ────────────────────────────────────────────────
from base.auth import auth_router
from base.organization import org_router
from base.users import users_router


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

    # ── Auth + RBAC middleware ───────────────────────────────
    app.add_middleware(AuthPermissionMiddleware)

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