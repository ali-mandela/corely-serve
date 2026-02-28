"""
Tenant + Permission middleware.

Runs on every request (except DISABLED_ROUTES):
  1. Decode JWT → extract org_slug, role, permissions
  2. Set request.state.org_slug, request.state.user, etc.
  3. Check RBAC permission for the target route
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from base.auth.helpers import decode_access_token
from base.rbac.permissions import (
    check_permission,
    resolve_permission_from_request,
)
from base.rbac.roles import get_role_permissions


# Routes that skip all auth / permission checks
DISABLED_ROUTES = [
    "/login",
    "/set-up",
    "/check-slug",
    "/health",
    "/openapi.json",
    "/api/docs",
    "/redoc",
]


class AuthPermissionMiddleware(BaseHTTPMiddleware):
    """Single middleware that handles JWT verification + RBAC enforcement."""

    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin", "*")

        # ── Preflight ────────────────────────────────────────────
        if request.method == "OPTIONS":
            return JSONResponse(
                status_code=200,
                content={"message": "CORS preflight ok"},
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
                    "Access-Control-Allow-Headers": "Authorization,Content-Type,organization",
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        path = request.url.path

        # ── Skip disabled routes ─────────────────────────────────
        if any(path.endswith(route) for route in DISABLED_ROUTES):
            return await call_next(request)

        # ── Extract & decode JWT ─────────────────────────────────
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing Authorization header"},
            )

        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid token format. Expected 'Bearer <token>'"},
            )

        token = auth_header.split(" ", 1)[1].strip()

        try:
            payload = decode_access_token(token)
        except Exception as e:
            return JSONResponse(
                status_code=401,
                content={"detail": f"Invalid or expired token: {e}"},
            )

        # ── Populate request.state ───────────────────────────────
        org_slug = payload.get("org_slug")
        role = payload.get("role", "employee")
        permissions = payload.get("permissions") or get_role_permissions(role)

        request.state.user = payload
        request.state.org_slug = org_slug
        request.state.user_role = role
        request.state.user_permissions = permissions

        # ── RBAC check ───────────────────────────────────────────
        required_perm = resolve_permission_from_request(request)
        if required_perm and not check_permission(permissions, required_perm):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": f"Permission denied. Requires: {required_perm}",
                },
            )

        return await call_next(request)
