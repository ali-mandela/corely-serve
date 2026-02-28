from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from fastapi import HTTPException, status
from app.core.config.database import get_database
from app.core.auth.helpers import verify_access_token

DISABLED_ROUTES = [
    "/login",
    "/set-up",
    "/openapi.json",
    "/api/docs",
    "/redoc",
]


# class OrganizationMiddleware(BaseHTTPMiddleware):
#     """Validate organization header except for disabled routes."""

#     async def dispatch(self, request: Request, call_next):
#         path = request.url.path

#         # ✅ Skip org validation for disabled routes
#         if any(path.endswith(route) for route in DISABLED_ROUTES):
#             return await call_next(request)

#         org_header = request.headers.get("organization")
#         if not org_header:
#             return JSONResponse(
#                 status_code=400,
#                 content={"detail": "Organization header missing"},
#             )

#         try:
#             db = await get_database()
#             org_doc = await db.organizations.find_one({"slug": org_header})

#             if not org_doc:
#                 return JSONResponse(
#                     status_code=404, content={"detail": "Organization not found"}
#                 )

#             if not org_doc.get("is_active", False):
#                 return JSONResponse(
#                     status_code=403, content={"detail": "Organization inactive"}
#                 )

#             request.state.organization = org_doc
#             response = await call_next(request)
#             return response

#         except Exception as e:
#             print("OrganizationMiddleware error:", e)
#             return JSONResponse(
#                 status_code=500, content={"detail": "Internal server error"}
#             )


# as of now handkers only owner (wildcard permission)


MODULE_MAP = {
    "users": "A",
    "stores": "B",
    "products": "C",
    "inventory": "D",
}

OPERATION_MAP = {
    "GET": "1",  # read
    "PUT": "2",  # update
    "PATCH": "2",
    "DELETE": "3",  # delete
    "POST": "4",  # create
}


def check_operation_permission(
    permissions: list[str], module_code: str, operation_code: str
) -> bool:
    """Check if user has permission for specific module + operation"""
    return f"{module_code}{operation_code}" in permissions


def has_permission(decoded_data: dict, request: Request) -> bool:
    """
    Validate if a user has permission for the current request.
    Supports '*' for full access.
    """
    permissions = decoded_data.get("permissions", [])
    if isinstance(permissions, list) and "*" in permissions:
        return True  # superuser

    # Extract module from path, e.g. /api/v1/users/ → "users"
    path_parts = request.url.path.strip("/").split("/")
    module = path_parts[2] if len(path_parts) > 2 else None
    module_code = MODULE_MAP.get(module)
    if not module_code:
        return False  # Unknown module

    # Map HTTP method to operation
    operation_code = OPERATION_MAP.get(request.method)
    if not operation_code:
        return False  # Unsupported method

    # Check permission
    return check_operation_permission(permissions, module_code, operation_code)


class PermissionMiddleware(BaseHTTPMiddleware):
    """JWT verification and permission attachment."""

    async def dispatch(self, request: Request, call_next):

        origin = request.headers.get("origin") or "*"

        # Handle preflight
        if request.method == "OPTIONS":
            return JSONResponse(
                status_code=200,
                content={"message": "CORS preflight ok"},
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
                    "Access-Control-Allow-Headers": "Authorization,Content-Type",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        
        path = request.url.path

        # ✅ Skip auth for disabled routes
        if any(path.endswith(route) for route in DISABLED_ROUTES):
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing Authorization header"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid token format. Expected 'Bearer <token>'"},
            )

        token = auth_header.split(" ", 1)[1].strip()

        try:
            payload = verify_access_token(token)
            print("PP", payload)

            request.state.user = payload
            is_permitted = has_permission(payload, path)

            if not is_permitted:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Insufficient permissions"},
                )
        except Exception as e:
            return JSONResponse(
                status_code=401, content={"detail": f"Invalid or expired token: {e}"}
            )

        response = await call_next(request)
        return response
