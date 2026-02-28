from typing import Dict, Any, Optional, Callable, List
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from .engine import policy_engine
from .attributes import AttributeManager
from .models import ABACContext, PolicyEffect
import json
from app.core.config.database import DatabaseManager


class ABACMiddleware(BaseHTTPMiddleware):
    """ABAC middleware for FastAPI applications"""

    def __init__(self, app, excluded_paths: Optional[List[str]] = None):
        super().__init__(app)
        self.attribute_manager = AttributeManager()
        self.excluded_paths = excluded_paths or [
            "/api/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/metrics",
            "/base",
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through ABAC evaluation"""

        # Skip ABAC for excluded paths
        if self._is_excluded_path(request.url.path):
            return await call_next(request)

        try:
            # Extract user context from request (customize based on your auth system)
            user_context = await self._extract_user_context(request)

            # Extract resource context from request
            resource_context = await self._extract_resource_context(request)

            # Build ABAC context
            abac_context = await self.attribute_manager.build_abac_context(
                user=user_context, resource=resource_context, request=request
            )

            # Evaluate access
            decision = await policy_engine.evaluate(abac_context)

            # Check decision
            if decision.decision == PolicyEffect.DENY:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Access Denied",
                        "message": "Insufficient permissions to access this resource",
                        "reasons": decision.reasons,
                        "request_id": getattr(request.state, "request_id", "unknown"),
                    },
                )

            # Store ABAC decision in request state for potential use by endpoints
            request.state.abac_decision = decision
            request.state.abac_context = abac_context

            # Continue with request
            return await call_next(request)

        except Exception as e:
            # Log error and deny access for security
            print(f"ABAC middleware error: {e}")
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Access Control Error",
                    "message": "Unable to evaluate access permissions",
                },
            )

    def _is_excluded_path(self, path: str) -> bool:
        """Check if path should be excluded from ABAC evaluation"""
        return any(path.startswith(excluded) for excluded in self.excluded_paths)

    async def _extract_user_context(self, request: Request) -> Optional[Dict[str, Any]]:
        """Extract user context from request - customize based on your auth system"""

        # Example: Extract from JWT token in Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        # This is a placeholder - replace with your actual JWT/auth extraction logic
        token = auth_header.split(" ", 1)[1]

    async def _extract_resource_context(
        self, request: Request
    ) -> Optional[Dict[str, Any]]:
        """Extract resource context from request"""
        path = request.url.path
        path_params = getattr(request, "path_params", {})

        resource_context = {"type": self._infer_resource_type(path), "endpoint": path}

        # Extract resource ID from path parameters
        if "id" in path_params:
            resource_context["id"] = path_params["id"]
        elif "user_id" in path_params:
            resource_context["id"] = path_params["user_id"]
            resource_context["type"] = "user"
        elif "org_id" in path_params:
            resource_context["id"] = path_params["org_id"]
            resource_context["type"] = "organization"

        return resource_context

    def _infer_resource_type(self, path: str) -> str:
        """Infer resource type from URL path"""
        if "/users" in path:
            return "user"
        elif "/organizations" in path:
            return "organization"
        elif "/admin" in path:
            return "admin"
        elif "/reports" in path:
            return "report"
        else:
            return "unknown"


def abac_required(
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    require_ownership: bool = False,
):
    """Decorator for additional ABAC checks on specific endpoints"""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # This would be implemented as a FastAPI dependency
            # For now, it's a placeholder for endpoint-specific ABAC logic
            return await func(*args, **kwargs)

        return wrapper

    return decorator


# Dependency for FastAPI endpoints to get ABAC context
async def get_abac_context(request: Request) -> ABACContext:
    """FastAPI dependency to get ABAC context from request state"""
    context = getattr(request.state, "abac_context", None)
    if context is None:
        raise HTTPException(
            status_code=500,
            detail="ABAC context not available - ensure ABACMiddleware is properly configured",
        )
    return context


# Dependency to get ABAC decision
async def get_abac_decision(request: Request):
    """FastAPI dependency to get ABAC decision from request state"""
    decision = getattr(request.state, "abac_decision", None)
    if decision is None:
        raise HTTPException(
            status_code=500,
            detail="ABAC decision not available - ensure ABACMiddleware is properly configured",
        )
    return decision
