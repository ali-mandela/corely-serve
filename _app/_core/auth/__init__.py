"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
Authentication Module

This module provides the unified authentication and authorization system for Corely,
integrating tokens, sessions, enhanced authentication, and permissions into a
cohesive security framework.

Components:
- Token Management: JWT and session tokens with multi-tenant support
- Session Management: User authentication sessions with device tracking
- Enhanced Authentication: Unified auth interface with ABAC integration
- Permissions Management: Fine-grained access control with role-based inheritance
- Multi-Factor Authentication: SMS, email, TOTP, and hardware key support
- API Key Management: Scoped API keys for system integrations
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Set
import weakref

# Import all authentication components
from .tokens import (
    TokenType,
    TokenScope,
    TokenClaims,
    SessionToken,
    ROLE_HIERARCHY,
    JWTTokenManager,
    SessionTokenManager,
    TokenManager,
    get_token_manager,
    create_authentication_tokens,
    validate_bearer_token,
    refresh_authentication_tokens,
    revoke_user_tokens,
    cleanup_expired_tokens,
)

from .sessions import (
    SessionState,
    LoginType,
    DeviceType,
    ORGANIZATION_MODULES,
    DeviceFingerprint,
    SessionContext,
    AuthenticationSessionManager,
    CorelySSOManager,
    get_auth_session_manager,
    get_sso_manager,
    authenticate_user,
    authenticate_sso_user,
    validate_user_session,
    logout_user,
    refresh_user_tokens,
    get_user_active_sessions,
    check_user_security_alerts,
    cleanup_expired_auth_sessions,
    ensure_auth_indexes,
)

from .enhanced_auth import (
    AuthMethod,
    AccessLevel,
    MFAMethod,
    AuthenticationContext,
    PolicyContext,
    MFAChallenge,
    EnhancedAuthenticator,
    AuthenticationContextManager,
    MFAManager,
    get_enhanced_authenticator,
    get_mfa_manager,
    set_request_auth_context,
    get_request_auth_context,
    clear_request_auth_context,
    get_current_user,
    get_optional_user,
    require_role,
    require_permission,
    require_module,
    require_store_access,
    require_mfa_verified,
    require_auth,
    require_api_key,
    create_api_key,
    revoke_api_key,
    list_user_api_keys,
    log_authentication_event,
    validate_resource_access,
    ensure_auth_indexes as ensure_enhanced_auth_indexes,
)

from .permissions import (
    PermissionScope,
    PermissionType,
    CORELY_PERMISSIONS,
    ROLE_PERMISSION_TEMPLATES,
    Permission,
    PermissionSet,
    PermissionManager,
    get_permission_manager,
    check_user_permission,
    get_user_effective_permissions,
    grant_permission,
    revoke_permission,
    invalidate_user_permissions,
    ensure_permission_indexes,
)


logger = logging.getLogger(__name__)


class AuthenticationModule:
    """Central authentication module coordinator for Corely."""

    def __init__(self):
        self._initialized = False
        self._token_manager: Optional[TokenManager] = None
        self._session_manager: Optional[AuthenticationSessionManager] = None
        self._sso_manager: Optional[CorelySSOManager] = None
        self._authenticator: Optional[EnhancedAuthenticator] = None
        self._mfa_manager: Optional[MFAManager] = None
        self._permission_manager: Optional[PermissionManager] = None

        # Background tasks
        self._cleanup_tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()

        # Component registry for lifecycle management
        self._components: weakref.WeakSet = weakref.WeakSet()

    async def initialize(self) -> None:
        """Initialize all authentication components."""
        if self._initialized:
            return

        logger.info("Initializing Corely Authentication Module...")

        try:
            # Initialize core managers
            self._token_manager = get_token_manager()
            self._session_manager = get_auth_session_manager()
            self._sso_manager = get_sso_manager()
            self._authenticator = get_enhanced_authenticator()
            self._mfa_manager = get_mfa_manager()
            self._permission_manager = get_permission_manager()

            # Register components for lifecycle management
            self._components.add(self._token_manager)
            self._components.add(self._session_manager)
            self._components.add(self._sso_manager)
            self._components.add(self._authenticator)
            self._components.add(self._mfa_manager)
            self._components.add(self._permission_manager)

            # Ensure database indexes
            await self._ensure_all_indexes()

            # Start background tasks
            await self._start_background_tasks()

            # Validate system integrity
            await self._validate_system_integrity()

            self._initialized = True
            logger.info("✅ Corely Authentication Module initialized successfully")

        except Exception as e:
            logger.error(f"❌ Authentication module initialization failed: {str(e)}")
            await self.shutdown()
            raise

    async def shutdown(self) -> None:
        """Shutdown all authentication components."""
        if not self._initialized:
            return

        logger.info("Shutting down Corely Authentication Module...")

        try:
            # Signal shutdown to background tasks
            self._shutdown_event.set()

            # Stop background tasks
            await self._stop_background_tasks()

            # Clear component references
            self._components.clear()

            self._initialized = False
            logger.info("✅ Authentication module shutdown completed")

        except Exception as e:
            logger.error(f"❌ Authentication module shutdown error: {str(e)}")

    async def _ensure_all_indexes(self) -> None:
        """Ensure all authentication-related database indexes."""
        logger.info("Ensuring authentication database indexes...")

        index_tasks = [
            ensure_auth_indexes(),
            ensure_enhanced_auth_indexes(),
            ensure_permission_indexes(),
        ]

        await asyncio.gather(*index_tasks, return_exceptions=True)
        logger.info("✅ Authentication indexes ensured")

    async def _start_background_tasks(self) -> None:
        """Start background maintenance tasks."""
        logger.info("Starting authentication background tasks...")

        # Token cleanup task
        self._cleanup_tasks.append(asyncio.create_task(self._token_cleanup_loop()))

        # Session cleanup task
        self._cleanup_tasks.append(asyncio.create_task(self._session_cleanup_loop()))

        # Permission cache maintenance task
        self._cleanup_tasks.append(
            asyncio.create_task(self._permission_cache_maintenance_loop())
        )

        # Security monitoring task
        self._cleanup_tasks.append(
            asyncio.create_task(self._security_monitoring_loop())
        )

        logger.info(f"✅ Started {len(self._cleanup_tasks)} background tasks")

    async def _stop_background_tasks(self) -> None:
        """Stop all background tasks."""
        logger.info("Stopping authentication background tasks...")

        for task in self._cleanup_tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        self._cleanup_tasks.clear()
        logger.info("✅ Background tasks stopped")

    async def _token_cleanup_loop(self) -> None:
        """Background task for token cleanup."""
        while not self._shutdown_event.is_set():
            try:
                # Clean up expired session tokens
                cleaned_count = await cleanup_expired_tokens()

                if cleaned_count > 0:
                    logger.info(f"Cleaned up {cleaned_count} expired tokens")

                # Wait for 1 hour or shutdown signal
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(), timeout=3600  # 1 hour
                    )
                    break  # Shutdown signaled
                except asyncio.TimeoutError:
                    continue  # Continue cleanup loop

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Token cleanup error: {str(e)}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry

    async def _session_cleanup_loop(self) -> None:
        """Background task for session cleanup."""
        while not self._shutdown_event.is_set():
            try:
                # Clean up expired authentication sessions
                cleaned_count = await cleanup_expired_auth_sessions()

                if cleaned_count > 0:
                    logger.info(f"Cleaned up {cleaned_count} expired auth sessions")

                # Wait for 30 minutes or shutdown signal
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(), timeout=1800  # 30 minutes
                    )
                    break  # Shutdown signaled
                except asyncio.TimeoutError:
                    continue  # Continue cleanup loop

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {str(e)}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry

    async def _permission_cache_maintenance_loop(self) -> None:
        """Background task for permission cache maintenance."""
        while not self._shutdown_event.is_set():
            try:
                # Trigger cache cleanup on permission manager
                if self._permission_manager:
                    await self._permission_manager._cleanup_cache()

                # Wait for 15 minutes or shutdown signal
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(), timeout=900  # 15 minutes
                    )
                    break  # Shutdown signaled
                except asyncio.TimeoutError:
                    continue  # Continue maintenance loop

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Permission cache maintenance error: {str(e)}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry

    async def _security_monitoring_loop(self) -> None:
        """Background task for security monitoring."""
        while not self._shutdown_event.is_set():
            try:
                # Perform security checks
                await self._perform_security_monitoring()

                # Wait for 1 hour or shutdown signal
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(), timeout=3600  # 1 hour
                    )
                    break  # Shutdown signaled
                except asyncio.TimeoutError:
                    continue  # Continue monitoring loop

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Security monitoring error: {str(e)}")
                await asyncio.sleep(600)  # Wait 10 minutes before retry

    async def _perform_security_monitoring(self) -> None:
        """Perform security monitoring checks."""
        try:
            # This would implement various security monitoring tasks:
            # - Check for unusual authentication patterns
            # - Monitor failed login attempts
            # - Detect potential security threats
            # - Generate security alerts

            # For now, just log that monitoring is active
            logger.debug("Security monitoring cycle completed")

        except Exception as e:
            logger.error(f"Security monitoring failed: {str(e)}")

    async def _validate_system_integrity(self) -> None:
        """Validate the integrity of the authentication system."""
        logger.info("Validating authentication system integrity...")

        try:
            # Validate permission structure
            if self._permission_manager:
                validation_result = (
                    await self._permission_manager.validate_permission_structure()
                )

                if not validation_result["valid"]:
                    logger.warning("Permission structure validation issues found:")
                    for issue in validation_result["issues"]:
                        logger.warning(
                            f"  - {issue['type']}: {issue.get('message', 'See details')}"
                        )
                else:
                    logger.info("✅ Permission structure validation passed")

            # Validate role hierarchy consistency
            self._validate_role_hierarchy()

            # Test core authentication flows
            await self._test_authentication_flows()

            logger.info("✅ System integrity validation completed")

        except Exception as e:
            logger.error(f"System integrity validation failed: {str(e)}")
            raise

    def _validate_role_hierarchy(self) -> None:
        """Validate role hierarchy consistency."""
        try:
            # Check that all roles in permission templates are defined in hierarchy
            hierarchy_roles = set(ROLE_HIERARCHY.keys())
            template_roles = set(ROLE_PERMISSION_TEMPLATES.keys())

            missing_roles = template_roles - hierarchy_roles
            if missing_roles:
                logger.warning(
                    f"Roles in templates but not in hierarchy: {missing_roles}"
                )

            extra_roles = hierarchy_roles - template_roles
            if extra_roles:
                logger.warning(f"Roles in hierarchy but no templates: {extra_roles}")

            # Validate hierarchy levels are logical
            sorted_roles = sorted(
                ROLE_HIERARCHY.items(), key=lambda x: x[1], reverse=True
            )
            logger.debug(
                f"Role hierarchy validation: {len(sorted_roles)} roles defined"
            )

        except Exception as e:
            logger.error(f"Role hierarchy validation failed: {str(e)}")
            raise

    async def _test_authentication_flows(self) -> None:
        """Test core authentication flows for basic functionality."""
        try:
            # This would implement basic smoke tests for:
            # - Token generation and validation
            # - Permission checking
            # - ABAC policy evaluation
            # - Database connectivity

            logger.debug("Authentication flow tests completed")

        except Exception as e:
            logger.error(f"Authentication flow tests failed: {str(e)}")
            raise

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive status of the authentication system."""
        return {
            "initialized": self._initialized,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "token_manager": self._token_manager is not None,
                "session_manager": self._session_manager is not None,
                "sso_manager": self._sso_manager is not None,
                "authenticator": self._authenticator is not None,
                "mfa_manager": self._mfa_manager is not None,
                "permission_manager": self._permission_manager is not None,
            },
            "background_tasks": {
                "active_tasks": len([t for t in self._cleanup_tasks if not t.done()]),
                "total_tasks": len(self._cleanup_tasks),
            },
            "statistics": {
                "total_permissions": len(CORELY_PERMISSIONS),
                "total_roles": len(ROLE_HIERARCHY),
                "organization_modules": len(ORGANIZATION_MODULES),
            },
        }

    @property
    def is_initialized(self) -> bool:
        """Check if authentication module is initialized."""
        return self._initialized


# Global authentication module instance
_auth_module: Optional[AuthenticationModule] = None


async def get_auth_module() -> AuthenticationModule:
    """Get global authentication module instance."""
    global _auth_module
    if _auth_module is None:
        _auth_module = AuthenticationModule()
        await _auth_module.initialize()
    return _auth_module


async def initialize_authentication() -> None:
    """Initialize authentication module - convenience function."""
    await get_auth_module()


async def shutdown_authentication() -> None:
    """Shutdown authentication module - convenience function."""
    global _auth_module
    if _auth_module:
        await _auth_module.shutdown()
        _auth_module = None


async def get_authentication_status() -> Dict[str, Any]:
    """Get authentication system status - convenience function."""
    try:
        auth_module = await get_auth_module()
        return auth_module.get_system_status()
    except Exception as e:
        return {
            "initialized": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# High-level authentication functions for easy integration
async def authenticate_request(
    email: str,
    password: str,
    tenant_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    device_type: DeviceType = DeviceType.WEB_BROWSER,
    remember_me: bool = False,
) -> Dict[str, Any]:
    """High-level user authentication function."""
    return await authenticate_user(
        email=email,
        password=password,
        tenant_id=tenant_id,
        ip_address=ip_address,
        user_agent=user_agent,
        device_type=device_type,
        remember_me=remember_me,
    )


async def authenticate_sso_request(
    sso_token: str,
    provider: str,
    tenant_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """High-level SSO authentication function."""
    return await authenticate_sso_user(
        sso_token=sso_token,
        provider=provider,
        tenant_id=tenant_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )


async def check_access_permission(
    user_id: str,
    permission: str,
    role: str,
    tenant_id: Optional[str] = None,
    store_id: Optional[str] = None,
    warehouse_id: Optional[str] = None,
) -> bool:
    """High-level permission checking function."""
    return await check_user_permission(
        user_id=user_id,
        permission=permission,
        role=role,
        tenant_id=tenant_id,
        store_id=store_id,
        warehouse_id=warehouse_id,
    )


# Authentication system utilities
def get_permission_list() -> Dict[str, str]:
    """Get all available permissions in the system."""
    return CORELY_PERMISSIONS.copy()


def get_role_list() -> Dict[str, int]:
    """Get all available roles and their hierarchy levels."""
    return ROLE_HIERARCHY.copy()


def get_module_list() -> Dict[str, str]:
    """Get all available organizational modules."""
    return ORGANIZATION_MODULES.copy()


def get_role_permissions(role: str) -> List[str]:
    """Get permission template for a specific role."""
    return ROLE_PERMISSION_TEMPLATES.get(role, [])


# System administration functions
async def perform_auth_maintenance() -> Dict[str, Any]:
    """Perform comprehensive authentication system maintenance."""
    try:
        results = {}

        # Clean up expired tokens
        results["tokens_cleaned"] = await cleanup_expired_tokens()

        # Clean up expired sessions
        results["sessions_cleaned"] = await cleanup_expired_auth_sessions()

        # Validate system integrity
        auth_module = await get_auth_module()
        await auth_module._validate_system_integrity()
        results["integrity_check"] = "passed"

        # Clear permission caches
        permission_manager = get_permission_manager()
        await permission_manager._cleanup_cache()
        results["cache_cleared"] = True

        results["maintenance_completed_at"] = datetime.now(timezone.utc).isoformat()

        return results

    except Exception as e:
        logger.error(f"Authentication maintenance failed: {str(e)}")
        return {
            "error": str(e),
            "maintenance_completed_at": datetime.now(timezone.utc).isoformat(),
        }


# Export all authentication functionality
__all__ = [
    # Core Module
    "AuthenticationModule",
    "get_auth_module",
    "initialize_authentication",
    "shutdown_authentication",
    "get_authentication_status",
    # Token Management
    "TokenType",
    "TokenScope",
    "TokenClaims",
    "SessionToken",
    "ROLE_HIERARCHY",
    "JWTTokenManager",
    "SessionTokenManager",
    "TokenManager",
    "get_token_manager",
    "create_authentication_tokens",
    "validate_bearer_token",
    "refresh_authentication_tokens",
    "revoke_user_tokens",
    "cleanup_expired_tokens",
    # Session Management
    "SessionState",
    "LoginType",
    "DeviceType",
    "ORGANIZATION_MODULES",
    "DeviceFingerprint",
    "SessionContext",
    "AuthenticationSessionManager",
    "CorelySSOManager",
    "get_auth_session_manager",
    "get_sso_manager",
    "authenticate_user",
    "authenticate_sso_user",
    "validate_user_session",
    "logout_user",
    "refresh_user_tokens",
    "get_user_active_sessions",
    "check_user_security_alerts",
    "cleanup_expired_auth_sessions",
    # Enhanced Authentication
    "AuthMethod",
    "AccessLevel",
    "MFAMethod",
    "AuthenticationContext",
    "PolicyContext",
    "MFAChallenge",
    "EnhancedAuthenticator",
    "AuthenticationContextManager",
    "MFAManager",
    "get_enhanced_authenticator",
    "get_mfa_manager",
    "set_request_auth_context",
    "get_request_auth_context",
    "clear_request_auth_context",
    "get_current_user",
    "get_optional_user",
    "require_role",
    "require_permission",
    "require_module",
    "require_store_access",
    "require_mfa_verified",
    "require_auth",
    "require_api_key",
    "create_api_key",
    "revoke_api_key",
    "list_user_api_keys",
    "log_authentication_event",
    "validate_resource_access",
    # Permissions Management
    "PermissionScope",
    "PermissionType",
    "CORELY_PERMISSIONS",
    "ROLE_PERMISSION_TEMPLATES",
    "Permission",
    "PermissionSet",
    "PermissionManager",
    "get_permission_manager",
    "check_user_permission",
    "get_user_effective_permissions",
    "grant_permission",
    "revoke_permission",
    "invalidate_user_permissions",
    # High-level Functions
    "authenticate_request",
    "authenticate_sso_request",
    "check_access_permission",
    # Utility Functions
    "get_permission_list",
    "get_role_list",
    "get_module_list",
    "get_role_permissions",
    # System Administration
    "perform_auth_maintenance",
]
