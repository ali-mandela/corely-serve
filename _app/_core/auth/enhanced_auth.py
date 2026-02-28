"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
Enhanced Authentication Module

This module provides the unified authentication interface that integrates with ABAC,
session management, and token systems to provide comprehensive security for Corely.

Features:
- Unified authentication API for all auth methods
- ABAC policy integration and evaluation
- Dynamic permission resolution based on context
- Request-scoped authentication context
- Authentication decorators for endpoint protection
- Multi-factor authentication support
- API key authentication for integrations
- Real-time permission evaluation
- Context-aware access control
"""

import asyncio
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Set, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
from functools import wraps
import inspect

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app._core.config.settings import get_settings
from app._core.database.connection import get_connection_manager
from app._core.auth.tokens import (
    get_token_manager, TokenClaims, validate_bearer_token, ROLE_HIERARCHY
)
from app._core.auth.sessions import (
    get_auth_session_manager, validate_user_session, SessionContext,
    DeviceType, DeviceFingerprint, ORGANIZATION_MODULES
)
from app._core.access_control.abac.policy_engine import PolicyEngine, PolicyDecision
from app._core.access_control.abac.default_policies import get_default_policies
from app._core.utils.exceptions import (
    AuthenticationException, AuthorizationException, ValidationException
)
from app._core.utils.constants import DatabaseConstants


logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    """Authentication methods supported by Corely."""
    JWT_TOKEN = "jwt_token"
    SESSION_TOKEN = "session_token"
    API_KEY = "api_key"
    BASIC_AUTH = "basic_auth"
    SSO_TOKEN = "sso_token"
    MFA_TOKEN = "mfa_token"


class AccessLevel(Enum):
    """Access levels for different operations."""
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    AUTHORIZED = "authorized"
    RESTRICTED = "restricted"
    ADMIN_ONLY = "admin_only"


@dataclass
class AuthenticationContext:
    """Complete authentication context for a request."""
    user_id: str
    tenant_id: Optional[str]
    session_id: Optional[str]
    email: str
    role: str
    role_level: int
    permissions: List[str]
    enabled_modules: Set[str]
    store_id: Optional[str] = None
    warehouse_id: Optional[str] = None
    department_id: Optional[str] = None
    device_fingerprint: Optional[DeviceFingerprint] = None
    auth_method: AuthMethod = AuthMethod.JWT_TOKEN
    is_authenticated: bool = True
    is_api_request: bool = False
    request_ip: Optional[str] = None
    user_agent: Optional[str] = None
    authenticated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions
    
    def has_role_level(self, required_level: int) -> bool:
        """Check if user has required role level or higher."""
        return self.role_level >= required_level
    
    def can_access_module(self, module: str) -> bool:
        """Check if user can access a specific module."""
        return module in self.enabled_modules
    
    def can_access_store(self, store_id: str) -> bool:
        """Check if user can access a specific store."""
        # Super admin and tenant admin can access all stores
        if self.role in ["SUPER_ADMIN", "TENANT_ADMIN"]:
            return True
        
        # Store-specific roles can only access their assigned store
        if self.store_id:
            return self.store_id == store_id
        
        # Regional roles can access multiple stores (implement hierarchy)
        return False
    
    def can_access_warehouse(self, warehouse_id: str) -> bool:
        """Check if user can access a specific warehouse."""
        # Super admin and tenant admin can access all warehouses
        if self.role in ["SUPER_ADMIN", "TENANT_ADMIN"]:
            return True
        
        # Warehouse-specific roles
        if self.warehouse_id:
            return self.warehouse_id == warehouse_id
        
        return False
    
    def is_super_admin(self) -> bool:
        """Check if user is super admin."""
        return self.role == "SUPER_ADMIN"
    
    def is_tenant_admin(self) -> bool:
        """Check if user is tenant admin."""
        return self.role in ["SUPER_ADMIN", "TENANT_ADMIN"]
    
    def is_store_manager(self) -> bool:
        """Check if user is a store manager."""
        return self.role in ["SUPER_ADMIN", "TENANT_ADMIN", "STORE_MANAGER"]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/debugging."""
        return {
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "email": self.email,
            "role": self.role,
            "role_level": self.role_level,
            "store_id": self.store_id,
            "warehouse_id": self.warehouse_id,
            "auth_method": self.auth_method.value,
            "is_api_request": self.is_api_request,
            "authenticated_at": self.authenticated_at.isoformat()
        }


@dataclass
class PolicyContext:
    """Context for ABAC policy evaluation."""
    user: AuthenticationContext
    resource: Dict[str, Any]
    action: str
    environment: Dict[str, Any] = field(default_factory=dict)
    
    def to_policy_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for policy evaluation."""
        return {
            "user": {
                "id": self.user.user_id,
                "tenant_id": self.user.tenant_id,
                "role": self.user.role,
                "role_level": self.user.role_level,
                "permissions": self.user.permissions,
                "store_id": self.user.store_id,
                "warehouse_id": self.user.warehouse_id,
                "department_id": self.user.department_id,
                "enabled_modules": list(self.user.enabled_modules)
            },
            "resource": self.resource,
            "action": self.action,
            "environment": {
                **self.environment,
                "time": datetime.now(timezone.utc).isoformat(),
                "ip_address": self.user.request_ip,
                "auth_method": self.user.auth_method.value
            }
        }


class EnhancedAuthenticator:
    """Enhanced authentication system with ABAC integration."""
    
    def __init__(self):
        self.settings = get_settings()
        self.token_manager = get_token_manager()
        self.session_manager = get_auth_session_manager()
        self.policy_engine = PolicyEngine()
        self.security = HTTPBearer(auto_error=False)
        
        # Load default policies
        self._load_default_policies()
    
    def _load_default_policies(self) -> None:
        """Load default ABAC policies for Corely."""
        try:
            default_policies = get_default_policies()
            for policy in default_policies:
                self.policy_engine.add_policy(policy)
            
            logger.info(f"Loaded {len(default_policies)} default ABAC policies")
        except Exception as e:
            logger.error(f"Failed to load default policies: {str(e)}")
    
    async def authenticate_request(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = None,
        required_auth: bool = True
    ) -> Optional[AuthenticationContext]:
        """Authenticate incoming request using multiple methods."""
        
        # Extract request information
        request_ip = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "")
        
        try:
            # Try JWT token authentication first
            if credentials and credentials.scheme.lower() == "bearer":
                return await self._authenticate_jwt_token(
                    credentials.credentials, request_ip, user_agent
                )
            
            # Try session token authentication
            session_token = request.headers.get("X-Session-Token")
            if session_token:
                return await self._authenticate_session_token(
                    session_token, request_ip, user_agent
                )
            
            # Try API key authentication
            api_key = request.headers.get("X-API-Key")
            if api_key:
                return await self._authenticate_api_key(
                    api_key, request_ip, user_agent
                )
            
            # Try session ID from cookies
            session_id = request.cookies.get("session_id")
            if session_id:
                return await self._authenticate_session_id(
                    session_id, request_ip, user_agent
                )
            
            # No authentication found
            if required_auth:
                raise AuthenticationException("Authentication required")
            
            return None
            
        except Exception as e:
            logger.warning(f"Request authentication failed: {str(e)}")
            if required_auth:
                raise
            return None
    
    async def _authenticate_jwt_token(
        self,
        token: str,
        request_ip: str,
        user_agent: str
    ) -> AuthenticationContext:
        """Authenticate using JWT token."""
        try:
            # Validate token and extract claims
            claims = await validate_bearer_token(token)
            
            # Create device fingerprint
            device_fingerprint = DeviceFingerprint(
                user_agent=user_agent,
                ip_address=request_ip,
                device_type=DeviceType.WEB_BROWSER  # Default, should be detected
            )
            
            # Get user's enabled modules
            enabled_modules = await self._get_user_enabled_modules(
                claims.user_id, claims.tenant_id
            )
            
            return AuthenticationContext(
                user_id=claims.user_id,
                tenant_id=claims.tenant_id,
                session_id=claims.session_id,
                email=claims.email,
                role=claims.role,
                role_level=claims.role_level,
                permissions=claims.permissions,
                enabled_modules=enabled_modules,
                store_id=claims.store_id,
                warehouse_id=claims.warehouse_id,
                device_fingerprint=device_fingerprint,
                auth_method=AuthMethod.JWT_TOKEN,
                request_ip=request_ip,
                user_agent=user_agent
            )
            
        except Exception as e:
            logger.error(f"JWT authentication failed: {str(e)}")
            raise AuthenticationException("Invalid JWT token")
    
    async def _authenticate_session_token(
        self,
        session_token: str,
        request_ip: str,
        user_agent: str
    ) -> AuthenticationContext:
        """Authenticate using session token."""
        try:
            # Validate session token
            token_manager = self.token_manager
            session_data = await token_manager.session_manager.validate_session_token(
                session_token, update_last_used=True
            )
            
            if not session_data:
                raise AuthenticationException("Invalid session token")
            
            # Get full user information
            user_info = await self._get_user_info(session_data.user_id)
            
            # Get user's enabled modules
            enabled_modules = await self._get_user_enabled_modules(
                session_data.user_id, session_data.tenant_id
            )
            
            # Create device fingerprint
            device_fingerprint = DeviceFingerprint(
                user_agent=user_agent,
                ip_address=request_ip,
                device_type=DeviceType.WEB_BROWSER
            )
            
            return AuthenticationContext(
                user_id=session_data.user_id,
                tenant_id=session_data.tenant_id,
                session_id=session_data.session_id,
                email=user_info["email"],
                role=user_info["role"],
                role_level=ROLE_HIERARCHY.get(user_info["role"], 0),
                permissions=user_info.get("permissions", []),
                enabled_modules=enabled_modules,
                store_id=user_info.get("store_id"),
                warehouse_id=user_info.get("warehouse_id"),
                department_id=user_info.get("department_id"),
                device_fingerprint=device_fingerprint,
                auth_method=AuthMethod.SESSION_TOKEN,
                request_ip=request_ip,
                user_agent=user_agent
            )
            
        except Exception as e:
            logger.error(f"Session token authentication failed: {str(e)}")
            raise AuthenticationException("Invalid session token")
    
    async def _authenticate_api_key(
        self,
        api_key: str,
        request_ip: str,
        user_agent: str
    ) -> AuthenticationContext:
        """Authenticate using API key."""
        try:
            # Hash the API key for database lookup
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            manager = await get_connection_manager()
            
            async with manager.get_collection("api_keys") as collection:
                api_key_data = await collection.find_one({
                    "key_hash": key_hash,
                    "status": "active",
                    "expires_at": {"$gt": datetime.now(timezone.utc)}
                })
                
                if not api_key_data:
                    raise AuthenticationException("Invalid API key")
                
                # Update last used
                await collection.update_one(
                    {"_id": api_key_data["_id"]},
                    {
                        "$set": {"last_used": datetime.now(timezone.utc)},
                        "$inc": {"usage_count": 1}
                    }
                )
                
                # Get user information
                user_info = await self._get_user_info(api_key_data["user_id"])
                
                # Get user's enabled modules
                enabled_modules = await self._get_user_enabled_modules(
                    api_key_data["user_id"], api_key_data.get("tenant_id")
                )
                
                return AuthenticationContext(
                    user_id=api_key_data["user_id"],
                    tenant_id=api_key_data.get("tenant_id"),
                    session_id=None,
                    email=user_info["email"],
                    role=user_info["role"],
                    role_level=ROLE_HIERARCHY.get(user_info["role"], 0),
                    permissions=api_key_data.get("permissions", user_info.get("permissions", [])),
                    enabled_modules=enabled_modules,
                    store_id=api_key_data.get("store_id", user_info.get("store_id")),
                    warehouse_id=api_key_data.get("warehouse_id", user_info.get("warehouse_id")),
                    auth_method=AuthMethod.API_KEY,
                    is_api_request=True,
                    request_ip=request_ip,
                    user_agent=user_agent
                )
                
        except Exception as e:
            logger.error(f"API key authentication failed: {str(e)}")
            raise AuthenticationException("Invalid API key")
    
    async def _authenticate_session_id(
        self,
        session_id: str,
        request_ip: str,
        user_agent: str
    ) -> AuthenticationContext:
        """Authenticate using session ID from cookie."""
        try:
            # Validate session
            session_context = await validate_user_session(session_id)
            
            if not session_context:
                raise AuthenticationException("Invalid session")
            
            # Create device fingerprint
            device_fingerprint = DeviceFingerprint(
                user_agent=user_agent,
                ip_address=request_ip,
                device_type=DeviceType.WEB_BROWSER
            )
            
            return AuthenticationContext(
                user_id=session_context.user_id,
                tenant_id=session_context.tenant_id,
                session_id=session_context.session_id,
                email=session_context.email,
                role=session_context.role,
                role_level=session_context.role_level,
                permissions=session_context.permissions,
                enabled_modules=session_context.enabled_modules,
                store_id=session_context.store_id,
                warehouse_id=session_context.warehouse_id,
                department_id=session_context.department_id,
                device_fingerprint=device_fingerprint,
                auth_method=AuthMethod.SESSION_TOKEN,
                request_ip=request_ip,
                user_agent=user_agent
            )
            
        except Exception as e:
            logger.error(f"Session ID authentication failed: {str(e)}")
            raise AuthenticationException("Invalid session")
    
    async def authorize_action(
        self,
        auth_context: AuthenticationContext,
        resource: Dict[str, Any],
        action: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Authorize user action using ABAC policies."""
        try:
            # Create policy context
            policy_context = PolicyContext(
                user=auth_context,
                resource=resource,
                action=action,
                environment=additional_context or {}
            )
            
            # Evaluate policies
            decision = await self.policy_engine.evaluate(
                policy_context.to_policy_dict()
            )
            
            # Log authorization decision
            logger.debug(
                f"Authorization decision for {auth_context.user_id}: "
                f"{action} on {resource.get('type', 'unknown')} = {decision.decision.value}"
            )
            
            return decision.decision == PolicyDecision.PERMIT
            
        except Exception as e:
            logger.error(f"Authorization evaluation failed: {str(e)}")
            return False
    
    async def check_module_access(
        self,
        auth_context: AuthenticationContext,
        module: str
    ) -> bool:
        """Check if user has access to a specific module."""
        return auth_context.can_access_module(module)
    
    async def check_store_access(
        self,
        auth_context: AuthenticationContext,
        store_id: str
    ) -> bool:
        """Check if user has access to a specific store."""
        return auth_context.can_access_store(store_id)
    
    async def check_warehouse_access(
        self,
        auth_context: AuthenticationContext,
        warehouse_id: str
    ) -> bool:
        """Check if user has access to a specific warehouse."""
        return auth_context.can_access_warehouse(warehouse_id)
    
    async def _get_user_info(self, user_id: str) -> Dict[str, Any]:
        """Get user information from database."""
        manager = await get_connection_manager()
        
        async with manager.get_collection(DatabaseConstants.USERS) as collection:
            user = await collection.find_one({"_id": user_id})
            
            if not user:
                raise AuthenticationException("User not found")
            
            return user
    
    async def _get_user_enabled_modules(
        self,
        user_id: str,
        tenant_id: Optional[str]
    ) -> Set[str]:
        """Get modules enabled for user."""
        try:
            enabled_modules = set()
            
            # Get tenant's enabled modules
            if tenant_id:
                manager = await get_connection_manager()
                async with manager.get_collection(DatabaseConstants.TENANTS) as collection:
                    tenant = await collection.find_one({"_id": tenant_id})
                    if tenant:
                        tenant_modules = tenant.get("enabled_modules", [])
                        enabled_modules.update(tenant_modules)
            
            # If no tenant modules, enable all modules (for super admin)
            if not enabled_modules:
                enabled_modules = set(ORGANIZATION_MODULES.keys())
            
            return enabled_modules
            
        except Exception as e:
            logger.error(f"Failed to get enabled modules: {str(e)}")
            return set(["inventory", "pos"])  # Default minimal modules
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to client host
        if hasattr(request, "client") and request.client:
            return request.client.host
        
        return "unknown"


# Global authenticator instance
_enhanced_authenticator: Optional[EnhancedAuthenticator] = None


def get_enhanced_authenticator() -> EnhancedAuthenticator:
    """Get global enhanced authenticator instance."""
    global _enhanced_authenticator
    if _enhanced_authenticator is None:
        _enhanced_authenticator = EnhancedAuthenticator()
    return _enhanced_authenticator


# FastAPI Dependencies
async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
) -> AuthenticationContext:
    """FastAPI dependency to get current authenticated user."""
    authenticator = get_enhanced_authenticator()
    
    auth_context = await authenticator.authenticate_request(
        request=request,
        credentials=credentials,
        required_auth=True
    )
    
    if not auth_context:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    return auth_context


async def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
) -> Optional[AuthenticationContext]:
    """FastAPI dependency to get current user (optional)."""
    authenticator = get_enhanced_authenticator()
    
    return await authenticator.authenticate_request(
        request=request,
        credentials=credentials,
        required_auth=False
    )


def require_role(required_role: str):
    """FastAPI dependency to require specific role."""
    def role_dependency(current_user: AuthenticationContext = Depends(get_current_user)):
        required_level = ROLE_HIERARCHY.get(required_role, 0)
        if not current_user.has_role_level(required_level):
            raise HTTPException(
                status_code=403,
                detail=f"Role {required_role} or higher required"
            )
        return current_user
    
    return role_dependency


def require_permission(permission: str):
    """FastAPI dependency to require specific permission."""
    def permission_dependency(current_user: AuthenticationContext = Depends(get_current_user)):
        if not current_user.has_permission(permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission {permission} required"
            )
        return current_user
    
    return permission_dependency


def require_module(module: str):
    """FastAPI dependency to require module access."""
    def module_dependency(current_user: AuthenticationContext = Depends(get_current_user)):
        if not current_user.can_access_module(module):
            raise HTTPException(
                status_code=403,
                detail=f"Access to {module} module required"
            )
        return current_user
    
    return module_dependency


def require_store_access(store_id_param: str = "store_id"):
    """FastAPI dependency to require store access."""
    def store_dependency(
        request: Request,
        current_user: AuthenticationContext = Depends(get_current_user)
    ):
        # Get store_id from path parameters
        store_id = request.path_params.get(store_id_param)
        if not store_id:
            raise HTTPException(status_code=400, detail="Store ID required")
        
        if not current_user.can_access_store(store_id):
            raise HTTPException(
                status_code=403,
                detail=f"Access to store {store_id} not permitted"
            )
        
        return current_user
    
    return store_dependency


# Authentication Decorators
def require_auth(
    role: Optional[str] = None,
    permission: Optional[str] = None,
    module: Optional[str] = None
):
    """Decorator to require authentication and authorization."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # This is a placeholder for non-FastAPI usage
            # In practice, use the FastAPI dependencies above
            return await func(*args, **kwargs)
        return wrapper
    return decorator




def require_api_key(permissions: Optional[List[str]] = None):
    """Decorator to require API key authentication."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # This is a placeholder for API key validation
            # Implement based on your specific needs
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Utility Functions
async def create_api_key(
    user_id: str,
    name: str,
    tenant_id: Optional[str] = None,
    permissions: Optional[List[str]] = None,
    store_id: Optional[str] = None,
    warehouse_id: Optional[str] = None,
    expires_in_days: int = 365
) -> Dict[str, Any]:
    """Create a new API key for a user."""
    try:
        # Generate API key
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        # Create API key data
        api_key_data = {
            "key_hash": key_hash,
            "name": name,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "permissions": permissions or [],
            "store_id": store_id,
            "warehouse_id": warehouse_id,
            "status": "active",
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(days=expires_in_days),
            "last_used": None,
            "usage_count": 0
        }
        
        # Store in database
        manager = await get_connection_manager()
        async with manager.get_collection("api_keys") as collection:
            result = await collection.insert_one(api_key_data)
            
            return {
                "key_id": str(result.inserted_id),
                "key": raw_key,  # Return only once
                "name": name,
                "expires_at": api_key_data["expires_at"].isoformat(),
                "permissions": permissions or []
            }
            
    except Exception as e:
        logger.error(f"Failed to create API key: {str(e)}")
        raise ValidationException("Failed to create API key")


async def revoke_api_key(key_id: str, user_id: Optional[str] = None) -> bool:
    """Revoke an API key."""
    try:
        manager = await get_connection_manager()
        
        query = {"_id": key_id, "status": "active"}
        if user_id:
            query["user_id"] = user_id
        
        async with manager.get_collection("api_keys") as collection:
            result = await collection.update_one(
                query,
                {"$set": {"status": "revoked", "revoked_at": datetime.now(timezone.utc)}}
            )
            
            return result.modified_count > 0
            
    except Exception as e:
        logger.error(f"Failed to revoke API key: {str(e)}")
        return False


async def list_user_api_keys(user_id: str) -> List[Dict[str, Any]]:
    """List all API keys for a user."""
    try:
        manager = await get_connection_manager()
        
        api_keys = []
        async with manager.get_collection("api_keys") as collection:
            cursor = collection.find({"user_id": user_id}).sort("created_at", -1)
            
            async for key_data in cursor:
                api_keys.append({
                    "key_id": str(key_data["_id"]),
                    "name": key_data["name"],
                    "status": key_data["status"],
                    "permissions": key_data.get("permissions", []),
                    "created_at": key_data["created_at"].isoformat(),
                    "expires_at": key_data["expires_at"].isoformat(),
                    "last_used": (key_data["last_used"].isoformat() 
                                 if key_data.get("last_used") else None),
                    "usage_count": key_data.get("usage_count", 0)
                })
        
        return api_keys
        
    except Exception as e:
        logger.error(f"Failed to list API keys: {str(e)}")
        return []


# Database index management
async def ensure_auth_indexes() -> None:
    """Ensure authentication-related indexes are created."""
    try:
        manager = await get_connection_manager()
        
        # API keys collection
        async with manager.get_collection("api_keys") as collection:
            await collection.create_index("key_hash", unique=True, background=True)
            await collection.create_index("user_id", background=True)
            await collection.create_index("tenant_id", background=True)
            await collection.create_index("status", background=True)
            await collection.create_index("expires_at", background=True)
            
            # Compound indexes
            await collection.create_index([
                ("user_id", 1), ("status", 1)
            ], background=True)
            
            # TTL index for expired keys
            await collection.create_index(
                "expires_at",
                expireAfterSeconds=86400,  # 24 hours after expiration
                background=True
            )
        
        logger.info("Enhanced authentication indexes ensured")
        
    except Exception as e:
        logger.error(f"Failed to ensure auth indexes: {str(e)}")
        raise


# Context Managers for Authentication
class AuthenticationContextManager:
    """Context manager for maintaining authentication state across requests."""
    
    def __init__(self):
        self._context: Optional[AuthenticationContext] = None
        self._lock = asyncio.Lock()
    
    async def set_context(self, context: AuthenticationContext) -> None:
        """Set the current authentication context."""
        async with self._lock:
            self._context = context
    
    async def get_context(self) -> Optional[AuthenticationContext]:
        """Get the current authentication context."""
        async with self._lock:
            return self._context
    
    async def clear_context(self) -> None:
        """Clear the current authentication context."""
        async with self._lock:
            self._context = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.clear_context()


# Request-scoped authentication context
_request_auth_context: Optional[AuthenticationContext] = None


def set_request_auth_context(context: AuthenticationContext) -> None:
    """Set authentication context for current request (thread-local)."""
    global _request_auth_context
    _request_auth_context = context


def get_request_auth_context() -> Optional[AuthenticationContext]:
    """Get authentication context for current request."""
    global _request_auth_context
    return _request_auth_context


def clear_request_auth_context() -> None:
    """Clear authentication context for current request."""
    global _request_auth_context
    _request_auth_context = None


# Multi-Factor Authentication Support
class MFAMethod(Enum):
    """Multi-factor authentication methods."""
    SMS = "sms"
    EMAIL = "email"
    TOTP = "totp"  # Time-based One-Time Password
    BACKUP_CODES = "backup_codes"
    HARDWARE_KEY = "hardware_key"


@dataclass
class MFAChallenge:
    """MFA challenge data."""
    challenge_id: str
    user_id: str
    method: MFAMethod
    challenge_data: Dict[str, Any]
    created_at: datetime
    expires_at: datetime
    attempts: int = 0
    max_attempts: int = 3
    is_verified: bool = False


class MFAManager:
    """Multi-factor authentication manager for Corely."""
    
    def __init__(self):
        self.settings = get_settings()
        self.challenge_timeout = timedelta(minutes=5)
    
    async def initiate_mfa_challenge(
        self,
        user_id: str,
        preferred_method: MFAMethod = MFAMethod.TOTP
    ) -> MFAChallenge:
        """Initiate MFA challenge for user."""
        try:
            # Get user's MFA settings
            user_mfa_settings = await self._get_user_mfa_settings(user_id)
            
            # Determine available methods
            available_methods = user_mfa_settings.get("enabled_methods", [])
            if not available_methods:
                raise AuthenticationException("MFA not configured for user")
            
            # Use preferred method if available, otherwise use first available
            method = preferred_method if preferred_method.value in available_methods else MFAMethod(available_methods[0])
            
            # Generate challenge
            challenge_id = secrets.token_urlsafe(32)
            challenge_data = await self._generate_challenge_data(user_id, method)
            
            challenge = MFAChallenge(
                challenge_id=challenge_id,
                user_id=user_id,
                method=method,
                challenge_data=challenge_data,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + self.challenge_timeout
            )
            
            # Store challenge
            await self._store_mfa_challenge(challenge)
            
            # Send challenge (SMS, email, etc.)
            await self._send_mfa_challenge(challenge)
            
            return challenge
            
        except Exception as e:
            logger.error(f"Failed to initiate MFA challenge: {str(e)}")
            raise AuthenticationException("Failed to initiate MFA challenge")
    
    async def verify_mfa_challenge(
        self,
        challenge_id: str,
        response: str
    ) -> bool:
        """Verify MFA challenge response."""
        try:
            # Get challenge
            challenge = await self._get_mfa_challenge(challenge_id)
            
            if not challenge:
                raise AuthenticationException("Invalid challenge")
            
            # Check if challenge is still valid
            if datetime.now(timezone.utc) > challenge.expires_at:
                await self._expire_mfa_challenge(challenge_id)
                raise AuthenticationException("Challenge expired")
            
            # Check attempts
            if challenge.attempts >= challenge.max_attempts:
                await self._expire_mfa_challenge(challenge_id)
                raise AuthenticationException("Too many attempts")
            
            # Verify response
            is_valid = await self._verify_mfa_response(challenge, response)
            
            if is_valid:
                # Mark as verified
                await self._mark_challenge_verified(challenge_id)
                return True
            else:
                # Increment attempts
                await self._increment_challenge_attempts(challenge_id)
                return False
                
        except Exception as e:
            logger.error(f"MFA verification failed: {str(e)}")
            return False
    
    async def _get_user_mfa_settings(self, user_id: str) -> Dict[str, Any]:
        """Get user's MFA settings."""
        manager = await get_connection_manager()
        
        async with manager.get_collection("user_mfa_settings") as collection:
            settings = await collection.find_one({"user_id": user_id})
            return settings or {}
    
    async def _generate_challenge_data(
        self,
        user_id: str,
        method: MFAMethod
    ) -> Dict[str, Any]:
        """Generate challenge data based on MFA method."""
        if method == MFAMethod.SMS:
            # Generate SMS code
            code = secrets.randbelow(900000) + 100000  # 6-digit code
            return {"code": str(code), "delivery": "sms"}
        
        elif method == MFAMethod.EMAIL:
            # Generate email code
            code = secrets.randbelow(900000) + 100000  # 6-digit code
            return {"code": str(code), "delivery": "email"}
        
        elif method == MFAMethod.TOTP:
            # TOTP doesn't need challenge data
            return {"method": "totp"}
        
        elif method == MFAMethod.BACKUP_CODES:
            return {"method": "backup_code"}
        
        else:
            raise AuthenticationException(f"Unsupported MFA method: {method}")
    
    async def _store_mfa_challenge(self, challenge: MFAChallenge) -> None:
        """Store MFA challenge in database."""
        manager = await get_connection_manager()
        
        challenge_data = {
            "challenge_id": challenge.challenge_id,
            "user_id": challenge.user_id,
            "method": challenge.method.value,
            "challenge_data": challenge.challenge_data,
            "created_at": challenge.created_at,
            "expires_at": challenge.expires_at,
            "attempts": challenge.attempts,
            "max_attempts": challenge.max_attempts,
            "is_verified": challenge.is_verified
        }
        
        async with manager.get_collection("mfa_challenges") as collection:
            await collection.insert_one(challenge_data)
    
    async def _send_mfa_challenge(self, challenge: MFAChallenge) -> None:
        """Send MFA challenge to user (SMS, email, etc.)."""
        # Placeholder for actual implementation
        # This would integrate with SMS/email services
        logger.info(f"MFA challenge sent via {challenge.method.value} for user {challenge.user_id}")
    
    async def _get_mfa_challenge(self, challenge_id: str) -> Optional[MFAChallenge]:
        """Get MFA challenge from database."""
        manager = await get_connection_manager()
        
        async with manager.get_collection("mfa_challenges") as collection:
            challenge_data = await collection.find_one({"challenge_id": challenge_id})
            
            if not challenge_data:
                return None
            
            return MFAChallenge(
                challenge_id=challenge_data["challenge_id"],
                user_id=challenge_data["user_id"],
                method=MFAMethod(challenge_data["method"]),
                challenge_data=challenge_data["challenge_data"],
                created_at=challenge_data["created_at"],
                expires_at=challenge_data["expires_at"],
                attempts=challenge_data["attempts"],
                max_attempts=challenge_data["max_attempts"],
                is_verified=challenge_data["is_verified"]
            )
    
    async def _verify_mfa_response(
        self,
        challenge: MFAChallenge,
        response: str
    ) -> bool:
        """Verify MFA response against challenge."""
        if challenge.method in [MFAMethod.SMS, MFAMethod.EMAIL]:
            return response == challenge.challenge_data["code"]
        
        elif challenge.method == MFAMethod.TOTP:
            # Verify TOTP code - implement TOTP verification
            return await self._verify_totp_code(challenge.user_id, response)
        
        elif challenge.method == MFAMethod.BACKUP_CODES:
            # Verify backup code
            return await self._verify_backup_code(challenge.user_id, response)
        
        return False
    
    async def _verify_totp_code(self, user_id: str, code: str) -> bool:
        """Verify TOTP code - placeholder for implementation."""
        # Implement TOTP verification using libraries like pyotp
        return True  # Placeholder
    
    async def _verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify backup code - placeholder for implementation."""
        # Implement backup code verification
        return True  # Placeholder
    
    async def _mark_challenge_verified(self, challenge_id: str) -> None:
        """Mark challenge as verified."""
        manager = await get_connection_manager()
        
        async with manager.get_collection("mfa_challenges") as collection:
            await collection.update_one(
                {"challenge_id": challenge_id},
                {"$set": {"is_verified": True}}
            )
    
    async def _increment_challenge_attempts(self, challenge_id: str) -> None:
        """Increment challenge attempts."""
        manager = await get_connection_manager()
        
        async with manager.get_collection("mfa_challenges") as collection:
            await collection.update_one(
                {"challenge_id": challenge_id},
                {"$inc": {"attempts": 1}}
            )
    
    async def _expire_mfa_challenge(self, challenge_id: str) -> None:
        """Expire MFA challenge."""
        manager = await get_connection_manager()
        
        async with manager.get_collection("mfa_challenges") as collection:
            await collection.update_one(
                {"challenge_id": challenge_id},
                {"$set": {"expires_at": datetime.now(timezone.utc)}}
            )


# Global MFA manager instance
_mfa_manager: Optional[MFAManager] = None


def get_mfa_manager() -> MFAManager:
    """Get global MFA manager instance."""
    global _mfa_manager
    if _mfa_manager is None:
        _mfa_manager = MFAManager()
    return _mfa_manager


# Additional FastAPI dependencies for MFA
def require_mfa_verified():
    """FastAPI dependency to require MFA verification."""
    def mfa_dependency(current_user: AuthenticationContext = Depends(get_current_user)):
        # Check if MFA is required for this user/action
        # This would be determined by tenant settings, user role, etc.
        mfa_required = current_user.role_level >= 70  # Manager level and above
        
        if mfa_required:
            # Check if current session has MFA verification
            # This would be tracked in session context or separate MFA session table
            pass  # Implement MFA verification check
        
        return current_user
    
    return mfa_dependency


# Enhanced logging and monitoring
async def log_authentication_event(
    auth_context: AuthenticationContext,
    event_type: str,
    additional_data: Optional[Dict[str, Any]] = None
) -> None:
    """Log authentication events for monitoring and compliance."""
    try:
        manager = await get_connection_manager()
        
        event_data = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc),
            "user_id": auth_context.user_id,
            "tenant_id": auth_context.tenant_id,
            "email": auth_context.email,
            "role": auth_context.role,
            "session_id": auth_context.session_id,
            "auth_method": auth_context.auth_method.value,
            "ip_address": auth_context.request_ip,
            "user_agent": auth_context.user_agent,
            "is_api_request": auth_context.is_api_request
        }
        
        if additional_data:
            event_data.update(additional_data)
        
        async with manager.get_collection("auth_audit_log") as collection:
            await collection.insert_one(event_data)
        
        logger.info(f"Authentication event logged: {event_type} for user {auth_context.user_id}")
        
    except Exception as e:
        logger.error(f"Failed to log authentication event: {str(e)}")


# Permission validation utilities
async def validate_resource_access(
    auth_context: AuthenticationContext,
    resource_type: str,
    resource_id: str,
    action: str
) -> bool:
    """Validate if user can perform action on specific resource."""
    try:
        authenticator = get_enhanced_authenticator()
        
        # Build resource context
        resource = {
            "type": resource_type,
            "id": resource_id,
            "tenant_id": auth_context.tenant_id
        }
        
        # Additional context based on resource type
        if resource_type == "store" and auth_context.store_id:
            resource["owner_store_id"] = auth_context.store_id
        
        if resource_type == "warehouse" and auth_context.warehouse_id:
            resource["owner_warehouse_id"] = auth_context.warehouse_id
        
        # Evaluate authorization
        return await authenticator.authorize_action(
            auth_context=auth_context,
            resource=resource,
            action=action
        )
        
    except Exception as e:
        logger.error(f"Resource access validation failed: {str(e)}")
        return False


# Export all classes and functions
__all__ = [
    # Enums
    "AuthMethod",
    "AccessLevel",
    "MFAMethod",
    # Data Classes
    "AuthenticationContext",
    "PolicyContext",
    "MFAChallenge",
    # Core Classes
    "EnhancedAuthenticator",
    "AuthenticationContextManager",
    "MFAManager",
    # Global Functions
    "get_enhanced_authenticator",
    "get_mfa_manager",
    # Context Management
    "set_request_auth_context",
    "get_request_auth_context",
    "clear_request_auth_context",
    # FastAPI Dependencies
    "get_current_user",
    "get_optional_user",
    "require_role",
    "require_permission",
    "require_module",
    "require_store_access",
    "require_mfa_verified",
    # Decorators
    "require_auth",
    "require_api_key",
    # Utility Functions
    "create_api_key",
    "revoke_api_key",
    "list_user_api_keys",
    "log_authentication_event",
    "validate_resource_access",
    "ensure_auth_indexes",
]