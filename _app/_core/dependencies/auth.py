"""
Authentication dependencies for FastAPI
"""
import logging
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

from ..auth import get_auth_manager, AuthManager
from ..audit import audit_login_attempt, audit_permission_check

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_manager: AuthManager = Depends(get_auth_manager)
) -> Dict[str, Any]:
    """
    Validate JWT token and return current user information
    """
    try:
        # Decode JWT token
        payload = jwt.decode(
            credentials.credentials,
            auth_manager.secret_key,
            algorithms=[auth_manager.algorithm]
        )

        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user from database/cache
        user = await auth_manager.get_user_by_id(user_id)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if user is active
        if not user.get("is_active", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return user

    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal authentication error"
        )


async def get_current_active_user(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Ensure user is active
    """
    if not current_user.get("is_active", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_current_superuser(
    current_user: Dict[str, Any] = Depends(get_current_active_user)
) -> Dict[str, Any]:
    """
    Ensure user is a superuser
    """
    if not current_user.get("is_superuser", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user


def require_roles(*required_roles: str):
    """
    Dependency factory to require specific roles

    Usage:
        @app.get("/admin")
        async def admin_endpoint(user: dict = Depends(require_roles("admin", "moderator"))):
            pass
    """
    async def check_roles(current_user: Dict[str, Any] = Depends(get_current_active_user)) -> Dict[str, Any]:
        user_roles = current_user.get("roles", [])

        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required roles: {', '.join(required_roles)}"
            )

        return current_user

    return check_roles


def require_permissions(*required_permissions: str):
    """
    Dependency factory to require specific permissions

    Usage:
        @app.get("/users")
        async def list_users(user: dict = Depends(require_permissions("users:read"))):
            pass
    """
    async def check_permissions(current_user: Dict[str, Any] = Depends(get_current_active_user)) -> Dict[str, Any]:
        user_permissions = current_user.get("permissions", [])

        missing_permissions = [perm for perm in required_permissions if perm not in user_permissions]

        if missing_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permissions: {', '.join(missing_permissions)}"
            )

        return current_user

    return check_permissions


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    auth_manager: AuthManager = Depends(get_auth_manager)
) -> Optional[Dict[str, Any]]:
    """
    Optional authentication - returns user if authenticated, None otherwise
    """
    if not credentials:
        return None

    try:
        payload = jwt.decode(
            credentials.credentials,
            auth_manager.secret_key,
            algorithms=[auth_manager.algorithm]
        )

        user_id = payload.get("sub")
        if user_id:
            user = await auth_manager.get_user_by_id(user_id)
            if user and user.get("is_active", False):
                return user

    except JWTError:
        pass

    return None


class TenantRequired:
    """
    Dependency class to ensure user belongs to specific tenant
    """

    def __init__(self, tenant_param: str = "tenant_id"):
        self.tenant_param = tenant_param

    async def __call__(
        self,
        tenant_id: str,
        current_user: Dict[str, Any] = Depends(get_current_active_user)
    ) -> Dict[str, Any]:
        user_tenant_id = current_user.get("tenant_id")

        if user_tenant_id != tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this tenant"
            )

        return current_user


class RateLimitRequired:
    """
    Dependency class for rate limiting
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    async def __call__(
        self,
        current_user: Dict[str, Any] = Depends(get_current_active_user)
    ) -> Dict[str, Any]:
        # This would integrate with your rate limiting system
        # For now, we'll just pass through
        return current_user


# Convenience instances
tenant_required = TenantRequired()
rate_limit_standard = RateLimitRequired(max_requests=1000, window_seconds=3600)
rate_limit_strict = RateLimitRequired(max_requests=100, window_seconds=3600)


# Admin role dependency
require_admin = require_roles("admin")
require_moderator = require_roles("admin", "moderator")

# Common permission dependencies
require_user_read = require_permissions("users:read")
require_user_write = require_permissions("users:write")
require_tenant_admin = require_permissions("tenant:admin")
require_system_admin = require_permissions("system:admin")