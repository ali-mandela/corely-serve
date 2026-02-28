"""
Declarative permission decorators for route handlers.

Usage:
    @router.get("/")
    @require_permission("users:read")
    async def list_users(request: Request):
        ...
"""

from functools import wraps
from fastapi import HTTPException, status
from starlette.requests import Request

from .permissions import check_permission


def require_permission(permission: str):
    """
    Decorator that checks the current user (set by middleware on
    request.state) has the required permission.

    Must be applied AFTER the route decorator.
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the Request object from args/kwargs
            request: Request | None = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found in handler",
                )

            user_permissions: list[str] = getattr(
                request.state, "user_permissions", []
            )

            if not check_permission(user_permissions, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied. Requires: {permission}",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator
