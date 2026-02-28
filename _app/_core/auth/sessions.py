"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
Authentication Session Management Module

This module provides comprehensive user authentication session management that integrates
with the database session system and supports modular organization features.

Features:
- User authentication sessions with multi-device support
- Integration with database transaction sessions
- Module-based access control (inventory, warehouse, POS, analytics, etc.)
- Session security and hijacking protection
- Tenant-specific session management
- Real-time session monitoring and management
- Session context for audit logging
- Device fingerprinting and security
"""

import asyncio
import secrets
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Set, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
import logging
from ipaddress import ip_address, IPv4Address, IPv6Address
import user_agents

from app._core.config.settings import get_settings
from app._core.database.connection import get_connection_manager
from app._core.database.session_manager import (
    create_session,
    SessionContext,
    TransactionContext,
)
from app._core.auth.tokens import (
    TokenManager,
    TokenClaims,
    SessionToken,
    TokenScope,
    ROLE_HIERARCHY,
    get_token_manager,
)
from app._core.utils.exceptions import (
    AuthenticationException,
    ValidationException,
    SecurityException,
)
from app._core.utils.constants import DatabaseConstants
from app._core.security.encryption import encrypt_data, decrypt_data


logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Authentication session states."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"
    LOCKED = "locked"


class LoginType(Enum):
    """Different login methods supported by Corely."""

    PASSWORD = "password"
    SSO = "sso"
    API_KEY = "api_key"
    MOBILE_PIN = "mobile_pin"
    BIOMETRIC = "biometric"
    QR_CODE = "qr_code"
    RFID_CARD = "rfid_card"


class DeviceType(Enum):
    """Device types for session tracking."""

    WEB_BROWSER = "web_browser"
    MOBILE_APP = "mobile_app"
    POS_TERMINAL = "pos_terminal"
    TABLET = "tablet"
    KIOSK = "kiosk"
    API_CLIENT = "api_client"
    SCANNER_DEVICE = "scanner_device"


# Corely Organization Modules - Each org can enable/disable these
ORGANIZATION_MODULES = {
    "inventory": "Inventory Management",
    "warehouse": "Warehouse Operations",
    "pos": "Point of Sale",
    "analytics": "Business Analytics",
    "accounting": "Financial Accounting",
    "hr": "Human Resources",
    "crm": "Customer Relationship Management",
    "supply_chain": "Supply Chain Management",
    "loyalty": "Customer Loyalty Program",
    "reporting": "Advanced Reporting",
    "audit": "Audit & Compliance",
    "maintenance": "Equipment Maintenance",
    "security": "Security & Access Control",
}


@dataclass
class DeviceFingerprint:
    """Device fingerprint for security tracking."""

    user_agent: str
    ip_address: str
    device_type: DeviceType
    browser_fingerprint: Optional[str] = None
    screen_resolution: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    platform: Optional[str] = None

    def generate_fingerprint_hash(self) -> str:
        """Generate a hash of the device fingerprint."""
        data = f"{self.user_agent}:{self.ip_address}:{self.device_type.value}"
        if self.browser_fingerprint:
            data += f":{self.browser_fingerprint}"
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class SessionContext:
    """Extended session context for authentication."""

    session_id: str
    user_id: str
    tenant_id: Optional[str]
    email: str
    role: str
    role_level: int
    enabled_modules: Set[str]
    store_id: Optional[str] = None
    warehouse_id: Optional[str] = None
    department_id: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    device_fingerprint: Optional[DeviceFingerprint] = None
    login_type: LoginType = LoginType.PASSWORD
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    state: SessionState = SessionState.ACTIVE
    security_flags: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        """Check if session is valid."""
        if self.state != SessionState.ACTIVE:
            return False

        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False

        return True

    def has_module_access(self, module: str) -> bool:
        """Check if session has access to a specific module."""
        return module in self.enabled_modules

    def can_access_store(self, store_id: str) -> bool:
        """Check if session can access a specific store."""
        # Super admin and tenant admin can access all stores
        if self.role in ["SUPER_ADMIN", "TENANT_ADMIN"]:
            return True

        # Store-specific roles can only access their assigned store
        if self.store_id:
            return self.store_id == store_id

        # Regional managers can access multiple stores (implement store hierarchy)
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        data = asdict(self)
        data["enabled_modules"] = list(self.enabled_modules)
        data["created_at"] = self.created_at.isoformat()
        data["last_activity"] = self.last_activity.isoformat()
        if self.expires_at:
            data["expires_at"] = self.expires_at.isoformat()
        return data


class AuthenticationSessionManager:
    """Comprehensive authentication session management for Corely."""

    def __init__(self):
        self.settings = get_settings()
        self.token_manager = get_token_manager()
        self.session_timeout = timedelta(hours=self.settings.auth.session_timeout_hours)
        self.max_sessions_per_user = self.settings.auth.max_sessions_per_user

        # Security thresholds
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        self.suspicious_activity_threshold = 10

    async def authenticate_user(
        self,
        email: str,
        password: str,
        tenant_id: Optional[str] = None,
        device_fingerprint: Optional[DeviceFingerprint] = None,
        login_type: LoginType = LoginType.PASSWORD,
        remember_me: bool = False,
    ) -> Dict[str, Any]:
        """Authenticate user and create session."""
        try:
            # Validate credentials and get user info
            user_info = await self._validate_credentials(email, password, tenant_id)

            # Check user status and permissions
            await self._check_user_status(user_info)

            # Check security restrictions
            await self._check_security_restrictions(user_info, device_fingerprint)

            # Get user's enabled modules
            enabled_modules = await self._get_user_enabled_modules(
                user_info["user_id"], user_info.get("tenant_id")
            )

            # Create session context
            session_context = SessionContext(
                session_id=secrets.token_urlsafe(32),
                user_id=user_info["user_id"],
                tenant_id=user_info.get("tenant_id"),
                email=user_info["email"],
                role=user_info["role"],
                role_level=ROLE_HIERARCHY.get(user_info["role"], 0),
                enabled_modules=enabled_modules,
                store_id=user_info.get("store_id"),
                warehouse_id=user_info.get("warehouse_id"),
                department_id=user_info.get("department_id"),
                permissions=user_info.get("permissions", []),
                device_fingerprint=device_fingerprint,
                login_type=login_type,
                expires_at=(
                    datetime.now(timezone.utc)
                    + (timedelta(days=30) if remember_me else self.session_timeout)
                ),
            )

            # Manage concurrent sessions
            await self._manage_concurrent_sessions(session_context)

            # Store session
            await self._store_session(session_context)

            # Create authentication tokens
            tokens = await self._create_authentication_tokens(session_context)

            # Log successful authentication
            await self._log_authentication_event(
                session_context, "login_success", device_fingerprint
            )

            # Update last login
            await self._update_last_login(user_info["user_id"])

            return {
                "session": {
                    "session_id": session_context.session_id,
                    "user_id": session_context.user_id,
                    "tenant_id": session_context.tenant_id,
                    "email": session_context.email,
                    "role": session_context.role,
                    "role_level": session_context.role_level,
                    "enabled_modules": list(session_context.enabled_modules),
                    "store_id": session_context.store_id,
                    "warehouse_id": session_context.warehouse_id,
                    "permissions": session_context.permissions,
                    "expires_at": session_context.expires_at.isoformat(),
                },
                "tokens": tokens,
                "user": {
                    "name": user_info.get("name", ""),
                    "profile_image": user_info.get("profile_image"),
                    "last_login": user_info.get("last_login"),
                    "preferred_language": user_info.get("preferred_language", "en"),
                    "timezone": user_info.get("timezone", "UTC"),
                },
            }

        except Exception as e:
            # Log failed authentication
            await self._log_authentication_event(
                None, "login_failed", device_fingerprint, str(e), email
            )

            # Track failed attempts
            await self._track_failed_attempt(email, device_fingerprint)

            logger.error(f"Authentication failed for {email}: {str(e)}")
            raise AuthenticationException("Authentication failed")

    async def validate_session(
        self, session_id: str, update_activity: bool = True
    ) -> Optional[SessionContext]:
        """Validate and optionally refresh session activity."""
        try:
            manager = await get_connection_manager()

            async with manager.get_collection("auth_sessions") as collection:
                session_data = await collection.find_one(
                    {"session_id": session_id, "state": SessionState.ACTIVE.value}
                )

                if not session_data:
                    return None

                # Reconstruct session context
                session_context = await self._reconstruct_session_context(session_data)

                # Check if session is still valid
                if not session_context.is_valid():
                    await self._expire_session(session_id)
                    return None

                # Update last activity
                if update_activity:
                    await self._update_session_activity(session_id)
                    session_context.last_activity = datetime.now(timezone.utc)

                return session_context

        except Exception as e:
            logger.error(f"Session validation failed: {str(e)}")
            return None

    async def refresh_session_tokens(
        self, session_id: str, refresh_token: str
    ) -> Dict[str, Any]:
        """Refresh session tokens."""
        try:
            # Validate session
            session_context = await self.validate_session(
                session_id, update_activity=True
            )
            if not session_context:
                raise AuthenticationException("Invalid session")

            # Create new token claims
            claims = TokenClaims(
                user_id=session_context.user_id,
                tenant_id=session_context.tenant_id,
                email=session_context.email,
                role=session_context.role,
                role_level=session_context.role_level,
                store_id=session_context.store_id,
                warehouse_id=session_context.warehouse_id,
                permissions=session_context.permissions,
                session_id=session_context.session_id,
            )

            # Refresh tokens
            new_tokens = await self.token_manager.refresh_token_pair(
                refresh_token, claims
            )

            logger.info(f"Refreshed tokens for session {session_id}")
            return new_tokens

        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise AuthenticationException("Failed to refresh tokens")

    async def logout_session(
        self, session_id: str, revoke_all_sessions: bool = False
    ) -> bool:
        """Logout user session."""
        try:
            # Get session info before logout
            session_context = await self.validate_session(
                session_id, update_activity=False
            )

            if revoke_all_sessions and session_context:
                # Revoke all user sessions
                await self._revoke_all_user_sessions(
                    session_context.user_id, session_id
                )
            else:
                # Revoke single session
                await self._revoke_session(session_id)

            # Log logout event
            if session_context:
                await self._log_authentication_event(session_context, "logout", None)

            logger.info(f"User logged out: session {session_id}")
            return True

        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            return False

    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all active sessions for a user."""
        try:
            manager = await get_connection_manager()
            sessions = []

            async with manager.get_collection("auth_sessions") as collection:
                cursor = collection.find(
                    {
                        "user_id": user_id,
                        "state": SessionState.ACTIVE.value,
                        "expires_at": {"$gt": datetime.now(timezone.utc)},
                    }
                ).sort("last_activity", -1)

                async for session_data in cursor:
                    # Parse device info
                    device_info = {}
                    if session_data.get("device_fingerprint"):
                        fp = session_data["device_fingerprint"]

                        # Parse user agent
                        if fp.get("user_agent"):
                            ua = user_agents.parse(fp["user_agent"])
                            device_info = {
                                "browser": f"{ua.browser.family} {ua.browser.version_string}",
                                "os": f"{ua.os.family} {ua.os.version_string}",
                                "device": ua.device.family,
                                "device_type": fp.get("device_type", "unknown"),
                            }

                    sessions.append(
                        {
                            "session_id": session_data["session_id"],
                            "created_at": session_data["created_at"],
                            "last_activity": session_data["last_activity"],
                            "ip_address": session_data.get(
                                "device_fingerprint", {}
                            ).get("ip_address"),
                            "login_type": session_data.get("login_type", "password"),
                            "device_info": device_info,
                            "is_current": False,  # Will be set by caller if needed
                        }
                    )

            return sessions

        except Exception as e:
            logger.error(f"Failed to get active sessions: {str(e)}")
            return []

    async def check_security_alerts(self, user_id: str) -> List[Dict[str, Any]]:
        """Check for security alerts related to user sessions."""
        try:
            alerts = []

            # Check for suspicious login patterns
            recent_logins = await self._get_recent_authentication_events(
                user_id, hours=24
            )

            # Multiple failed attempts
            failed_attempts = [
                e for e in recent_logins if e.get("event_type") == "login_failed"
            ]
            if len(failed_attempts) >= self.max_failed_attempts:
                alerts.append(
                    {
                        "type": "multiple_failed_attempts",
                        "severity": "high",
                        "message": f"{len(failed_attempts)} failed login attempts in 24 hours",
                        "count": len(failed_attempts),
                    }
                )

            # Logins from new locations
            successful_logins = [
                e for e in recent_logins if e.get("event_type") == "login_success"
            ]
            if len(successful_logins) > 1:
                ip_addresses = set(
                    e.get("ip_address")
                    for e in successful_logins
                    if e.get("ip_address")
                )
                if len(ip_addresses) > 2:
                    alerts.append(
                        {
                            "type": "multiple_locations",
                            "severity": "medium",
                            "message": f"Logins from {len(ip_addresses)} different IP addresses",
                            "ip_addresses": list(ip_addresses),
                        }
                    )

            # Concurrent sessions from different devices
            active_sessions = await self.get_active_sessions(user_id)
            device_types = set(
                s.get("device_info", {}).get("device_type") for s in active_sessions
            )
            if len(device_types) > 2:
                alerts.append(
                    {
                        "type": "multiple_devices",
                        "severity": "low",
                        "message": f"Active sessions on {len(device_types)} different device types",
                        "device_types": list(device_types),
                    }
                )

            return alerts

        except Exception as e:
            logger.error(f"Security check failed: {str(e)}")
            return []

    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired authentication sessions."""
        try:
            manager = await get_connection_manager()

            async with manager.get_collection("auth_sessions") as collection:
                # Mark expired sessions as expired
                result = await collection.update_many(
                    {
                        "expires_at": {"$lt": datetime.now(timezone.utc)},
                        "state": SessionState.ACTIVE.value,
                    },
                    {"$set": {"state": SessionState.EXPIRED.value}},
                )

                # Delete old expired sessions (older than 30 days)
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)
                delete_result = await collection.delete_many(
                    {
                        "expires_at": {"$lt": cutoff_date},
                        "state": {
                            "$in": [
                                SessionState.EXPIRED.value,
                                SessionState.REVOKED.value,
                            ]
                        },
                    }
                )

                total_cleaned = result.modified_count + delete_result.deleted_count
                if total_cleaned > 0:
                    logger.info(f"Cleaned up {total_cleaned} expired sessions")

                return total_cleaned

        except Exception as e:
            logger.error(f"Session cleanup failed: {str(e)}")
            return 0

    # Private methods
    async def _validate_credentials(
        self, email: str, password: str, tenant_id: Optional[str]
    ) -> Dict[str, Any]:
        """Validate user credentials against database."""
        manager = await get_connection_manager()

        # Build query
        query = {"email": email.lower(), "status": "active"}
        if tenant_id:
            query["tenant_id"] = tenant_id

        async with manager.get_collection(DatabaseConstants.USERS) as collection:
            user = await collection.find_one(query)

            if not user:
                raise AuthenticationException("Invalid credentials")

            # Verify password (implement your password hashing)
            # This is a placeholder - implement actual password verification
            if not self._verify_password(password, user.get("password_hash", "")):
                raise AuthenticationException("Invalid credentials")

            return {
                "user_id": str(user["_id"]),
                "email": user["email"],
                "tenant_id": user.get("tenant_id"),
                "role": user["role"],
                "name": user.get("name"),
                "store_id": user.get("store_id"),
                "warehouse_id": user.get("warehouse_id"),
                "department_id": user.get("department_id"),
                "permissions": user.get("permissions", []),
                "status": user["status"],
                "last_login": user.get("last_login"),
                "profile_image": user.get("profile_image"),
                "preferred_language": user.get("preferred_language", "en"),
                "timezone": user.get("timezone", "UTC"),
            }

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash - implement your hashing algorithm."""
        # Placeholder - implement actual password verification
        # Example: return bcrypt.checkpw(password.encode(), password_hash.encode())
        return True

    async def _check_user_status(self, user_info: Dict[str, Any]) -> None:
        """Check if user is allowed to login."""
        if user_info["status"] != "active":
            raise AuthenticationException("User account is not active")

        # Check for account locks, suspensions, etc.
        # Implement additional status checks as needed

    async def _check_security_restrictions(
        self, user_info: Dict[str, Any], device_fingerprint: Optional[DeviceFingerprint]
    ) -> None:
        """Check security restrictions for login."""
        # Check for too many recent failed attempts
        recent_failures = await self._get_recent_failed_attempts(
            user_info["email"], device_fingerprint
        )

        if len(recent_failures) >= self.max_failed_attempts:
            last_attempt = max(recent_failures, key=lambda x: x["timestamp"])
            lockout_until = last_attempt["timestamp"] + self.lockout_duration

            if datetime.now(timezone.utc) < lockout_until:
                raise SecurityException(
                    "Account temporarily locked due to failed attempts"
                )

    async def _get_user_enabled_modules(
        self, user_id: str, tenant_id: Optional[str]
    ) -> Set[str]:
        """Get modules enabled for user based on tenant and role."""
        try:
            enabled_modules = set()

            # Get tenant's enabled modules
            if tenant_id:
                manager = await get_connection_manager()
                async with manager.get_collection(
                    DatabaseConstants.TENANTS
                ) as collection:
                    tenant = await collection.find_one({"_id": tenant_id})
                    if tenant:
                        tenant_modules = tenant.get("enabled_modules", [])
                        enabled_modules.update(tenant_modules)

            # If no tenant, enable all modules (for super admin)
            if not enabled_modules:
                enabled_modules = set(ORGANIZATION_MODULES.keys())

            return enabled_modules

        except Exception as e:
            logger.error(f"Failed to get enabled modules: {str(e)}")
            return set(["inventory", "pos"])  # Default minimal modules

    async def _manage_concurrent_sessions(
        self, session_context: SessionContext
    ) -> None:
        """Manage concurrent sessions per user."""
        active_sessions = await self.get_active_sessions(session_context.user_id)

        if len(active_sessions) >= self.max_sessions_per_user:
            # Remove oldest sessions
            sessions_to_remove = len(active_sessions) - self.max_sessions_per_user + 1
            oldest_sessions = sorted(active_sessions, key=lambda x: x["last_activity"])[
                :sessions_to_remove
            ]

            for session in oldest_sessions:
                await self._revoke_session(session["session_id"])

    async def _store_session(self, session_context: SessionContext) -> None:
        """Store session in MongoDB."""
        manager = await get_connection_manager()

        async with manager.get_collection("auth_sessions") as collection:
            await collection.insert_one(session_context.to_dict())

    async def _create_authentication_tokens(
        self, session_context: SessionContext
    ) -> Dict[str, Any]:
        """Create JWT and session tokens."""
        from app._core.auth.tokens import create_authentication_tokens

        device_fingerprint = session_context.device_fingerprint

        return await create_authentication_tokens(
            user_id=session_context.user_id,
            tenant_id=session_context.tenant_id,
            email=session_context.email,
            role=session_context.role,
            permissions=session_context.permissions,
            store_id=session_context.store_id,
            warehouse_id=session_context.warehouse_id,
            device_id=(
                device_fingerprint.generate_fingerprint_hash()
                if device_fingerprint
                else None
            ),
            ip_address=(device_fingerprint.ip_address if device_fingerprint else None),
            user_agent=(device_fingerprint.user_agent if device_fingerprint else None),
        )

    async def _reconstruct_session_context(
        self, session_data: Dict[str, Any]
    ) -> SessionContext:
        """Reconstruct SessionContext from stored data."""
        device_fp = None
        if session_data.get("device_fingerprint"):
            fp_data = session_data["device_fingerprint"]
            device_fp = DeviceFingerprint(
                user_agent=fp_data["user_agent"],
                ip_address=fp_data["ip_address"],
                device_type=DeviceType(fp_data["device_type"]),
                browser_fingerprint=fp_data.get("browser_fingerprint"),
                screen_resolution=fp_data.get("screen_resolution"),
                timezone=fp_data.get("timezone"),
                language=fp_data.get("language"),
                platform=fp_data.get("platform"),
            )

        return SessionContext(
            session_id=session_data["session_id"],
            user_id=session_data["user_id"],
            tenant_id=session_data.get("tenant_id"),
            email=session_data["email"],
            role=session_data["role"],
            role_level=session_data["role_level"],
            enabled_modules=set(session_data.get("enabled_modules", [])),
            store_id=session_data.get("store_id"),
            warehouse_id=session_data.get("warehouse_id"),
            department_id=session_data.get("department_id"),
            permissions=session_data.get("permissions", []),
            device_fingerprint=device_fp,
            login_type=LoginType(session_data.get("login_type", "password")),
            created_at=datetime.fromisoformat(session_data["created_at"]),
            last_activity=datetime.fromisoformat(session_data["last_activity"]),
            expires_at=(
                datetime.fromisoformat(session_data["expires_at"])
                if session_data.get("expires_at")
                else None
            ),
            state=SessionState(session_data.get("state", "active")),
            security_flags=session_data.get("security_flags", {}),
            metadata=session_data.get("metadata", {}),
        )

    async def _update_session_activity(self, session_id: str) -> None:
        """Update session last activity timestamp."""
        manager = await get_connection_manager()

        async with manager.get_collection("auth_sessions") as collection:
            await collection.update_one(
                {"session_id": session_id},
                {"$set": {"last_activity": datetime.now(timezone.utc)}},
            )

    async def _expire_session(self, session_id: str) -> None:
        """Mark session as expired."""
        manager = await get_connection_manager()

        async with manager.get_collection("auth_sessions") as collection:
            await collection.update_one(
                {"session_id": session_id},
                {"$set": {"state": SessionState.EXPIRED.value}},
            )

    async def _revoke_session(self, session_id: str) -> None:
        """Revoke a session."""
        manager = await get_connection_manager()

        async with manager.get_collection("auth_sessions") as collection:
            await collection.update_one(
                {"session_id": session_id},
                {"$set": {"state": SessionState.REVOKED.value}},
            )

    async def _revoke_all_user_sessions(
        self, user_id: str, except_session_id: Optional[str] = None
    ) -> None:
        """Revoke all sessions for a user."""
        manager = await get_connection_manager()

        query = {"user_id": user_id, "state": SessionState.ACTIVE.value}
        if except_session_id:
            query["session_id"] = {"$ne": except_session_id}

        async with manager.get_collection("auth_sessions") as collection:
            await collection.update_many(
                query, {"$set": {"state": SessionState.REVOKED.value}}
            )

    async def _log_authentication_event(
        self,
        session_context: Optional[SessionContext],
        event_type: str,
        device_fingerprint: Optional[DeviceFingerprint],
        error_message: Optional[str] = None,
        email: Optional[str] = None,
    ) -> None:
        """Log authentication events for audit."""
        manager = await get_connection_manager()

        event_data = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc),
            "ip_address": device_fingerprint.ip_address if device_fingerprint else None,
            "user_agent": device_fingerprint.user_agent if device_fingerprint else None,
            "device_type": (
                device_fingerprint.device_type.value if device_fingerprint else None
            ),
        }

        if session_context:
            event_data.update(
                {
                    "user_id": session_context.user_id,
                    "tenant_id": session_context.tenant_id,
                    "email": session_context.email,
                    "role": session_context.role,
                    "session_id": session_context.session_id,
                }
            )
        elif email:
            event_data["email"] = email

        if error_message:
            event_data["error_message"] = error_message

        async with manager.get_collection("auth_events") as collection:
            await collection.insert_one(event_data)

    async def _update_last_login(self, user_id: str) -> None:
        """Update user's last login timestamp."""
        manager = await get_connection_manager()

        async with manager.get_collection(DatabaseConstants.USERS) as collection:
            await collection.update_one(
                {"_id": user_id}, {"$set": {"last_login": datetime.now(timezone.utc)}}
            )

    async def _track_failed_attempt(
        self, email: str, device_fingerprint: Optional[DeviceFingerprint]
    ) -> None:
        """Track failed authentication attempts."""
        manager = await get_connection_manager()

        attempt_data = {
            "email": email,
            "timestamp": datetime.now(timezone.utc),
            "ip_address": device_fingerprint.ip_address if device_fingerprint else None,
            "user_agent": device_fingerprint.user_agent if device_fingerprint else None,
            "device_type": (
                device_fingerprint.device_type.value if device_fingerprint else None
            ),
        }

        async with manager.get_collection("auth_failed_attempts") as collection:
            await collection.insert_one(attempt_data)

    async def _get_recent_failed_attempts(
        self,
        email: str,
        device_fingerprint: Optional[DeviceFingerprint],
        hours: int = 1,
    ) -> List[Dict[str, Any]]:
        """Get recent failed attempts for user/device."""
        manager = await get_connection_manager()

        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        query = {"email": email, "timestamp": {"$gt": cutoff_time}}

        # Add device context for more precise tracking
        if device_fingerprint:
            query["ip_address"] = device_fingerprint.ip_address

        attempts = []
        async with manager.get_collection("auth_failed_attempts") as collection:
            cursor = collection.find(query).sort("timestamp", -1)
            async for attempt in cursor:
                attempts.append(attempt)

        return attempts

    async def _get_recent_authentication_events(
        self, user_id: str, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Get recent authentication events for security analysis."""
        manager = await get_connection_manager()

        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        query = {"user_id": user_id, "timestamp": {"$gt": cutoff_time}}

        events = []
        async with manager.get_collection("auth_events") as collection:
            cursor = collection.find(query).sort("timestamp", -1)
            async for event in cursor:
                events.append(event)

        return events


class CorelySSOManager:
    """Single Sign-On integration for Corely organizations."""

    def __init__(self):
        self.settings = get_settings()
        self.auth_manager = AuthenticationSessionManager()

    async def authenticate_sso_user(
        self,
        sso_token: str,
        provider: str,
        tenant_id: Optional[str] = None,
        device_fingerprint: Optional[DeviceFingerprint] = None,
    ) -> Dict[str, Any]:
        """Authenticate user via SSO provider."""
        try:
            # Validate SSO token with provider
            user_info = await self._validate_sso_token(sso_token, provider)

            # Find or create user in Corely
            corely_user = await self._find_or_create_sso_user(
                user_info, provider, tenant_id
            )

            # Create authentication session
            return await self.auth_manager.authenticate_user(
                email=corely_user["email"],
                password="",  # SSO users don't use passwords
                tenant_id=tenant_id,
                device_fingerprint=device_fingerprint,
                login_type=LoginType.SSO,
            )

        except Exception as e:
            logger.error(f"SSO authentication failed: {str(e)}")
            raise AuthenticationException("SSO authentication failed")

    async def _validate_sso_token(self, token: str, provider: str) -> Dict[str, Any]:
        """Validate SSO token with external provider."""
        # Implement SSO token validation based on provider
        # This is a placeholder for various SSO integrations
        if provider == "google":
            return await self._validate_google_token(token)
        elif provider == "microsoft":
            return await self._validate_microsoft_token(token)
        elif provider == "okta":
            return await self._validate_okta_token(token)
        else:
            raise AuthenticationException(f"Unsupported SSO provider: {provider}")

    async def _validate_google_token(self, token: str) -> Dict[str, Any]:
        """Validate Google OAuth token."""
        # Implement Google token validation
        pass

    async def _validate_microsoft_token(self, token: str) -> Dict[str, Any]:
        """Validate Microsoft/Azure AD token."""
        # Implement Microsoft token validation
        pass

    async def _validate_okta_token(self, token: str) -> Dict[str, Any]:
        """Validate Okta token."""
        # Implement Okta token validation
        pass

    async def _find_or_create_sso_user(
        self, user_info: Dict[str, Any], provider: str, tenant_id: Optional[str]
    ) -> Dict[str, Any]:
        """Find existing SSO user or create new one."""
        manager = await get_connection_manager()

        # Try to find existing user
        async with manager.get_collection(DatabaseConstants.USERS) as collection:
            user = await collection.find_one(
                {"email": user_info["email"], "tenant_id": tenant_id}
            )

            if user:
                # Update SSO information
                await collection.update_one(
                    {"_id": user["_id"]},
                    {
                        "$set": {
                            "sso_provider": provider,
                            "sso_user_id": user_info.get("user_id"),
                            "last_login": datetime.now(timezone.utc),
                        }
                    },
                )
                return user
            else:
                # Create new SSO user
                new_user = {
                    "email": user_info["email"],
                    "name": user_info.get("name", ""),
                    "tenant_id": tenant_id,
                    "role": "CUSTOMER",  # Default role for SSO users
                    "status": "active",
                    "sso_provider": provider,
                    "sso_user_id": user_info.get("user_id"),
                    "created_at": datetime.now(timezone.utc),
                    "last_login": datetime.now(timezone.utc),
                    "permissions": [],
                    "profile_image": user_info.get("picture"),
                }

                result = await collection.insert_one(new_user)
                new_user["_id"] = result.inserted_id

                return new_user


# Global session manager instance
_auth_session_manager: Optional[AuthenticationSessionManager] = None
_sso_manager: Optional[CorelySSOManager] = None


def get_auth_session_manager() -> AuthenticationSessionManager:
    """Get global authentication session manager instance."""
    global _auth_session_manager
    if _auth_session_manager is None:
        _auth_session_manager = AuthenticationSessionManager()
    return _auth_session_manager


def get_sso_manager() -> CorelySSOManager:
    """Get global SSO manager instance."""
    global _sso_manager
    if _sso_manager is None:
        _sso_manager = CorelySSOManager()
    return _sso_manager


# Convenience functions for Corely authentication
async def authenticate_user(
    email: str,
    password: str,
    tenant_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    device_type: DeviceType = DeviceType.WEB_BROWSER,
    remember_me: bool = False,
) -> Dict[str, Any]:
    """Authenticate user with Corely credentials."""

    # Create device fingerprint
    device_fingerprint = None
    if ip_address and user_agent:
        device_fingerprint = DeviceFingerprint(
            user_agent=user_agent, ip_address=ip_address, device_type=device_type
        )

    manager = get_auth_session_manager()
    return await manager.authenticate_user(
        email=email,
        password=password,
        tenant_id=tenant_id,
        device_fingerprint=device_fingerprint,
        remember_me=remember_me,
    )


async def authenticate_sso_user(
    sso_token: str,
    provider: str,
    tenant_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    device_type: DeviceType = DeviceType.WEB_BROWSER,
) -> Dict[str, Any]:
    """Authenticate user via SSO."""

    # Create device fingerprint
    device_fingerprint = None
    if ip_address and user_agent:
        device_fingerprint = DeviceFingerprint(
            user_agent=user_agent, ip_address=ip_address, device_type=device_type
        )

    sso_manager = get_sso_manager()
    return await sso_manager.authenticate_sso_user(
        sso_token=sso_token,
        provider=provider,
        tenant_id=tenant_id,
        device_fingerprint=device_fingerprint,
    )


async def validate_user_session(session_id: str) -> Optional[SessionContext]:
    """Validate user session."""
    manager = get_auth_session_manager()
    return await manager.validate_session(session_id)


async def logout_user(session_id: str, logout_all_devices: bool = False) -> bool:
    """Logout user session."""
    manager = get_auth_session_manager()
    return await manager.logout_session(session_id, logout_all_devices)


async def refresh_user_tokens(session_id: str, refresh_token: str) -> Dict[str, Any]:
    """Refresh user authentication tokens."""
    manager = get_auth_session_manager()
    return await manager.refresh_session_tokens(session_id, refresh_token)


async def get_user_active_sessions(user_id: str) -> List[Dict[str, Any]]:
    """Get all active sessions for a user."""
    manager = get_auth_session_manager()
    return await manager.get_active_sessions(user_id)


async def check_user_security_alerts(user_id: str) -> List[Dict[str, Any]]:
    """Check for security alerts for a user."""
    manager = get_auth_session_manager()
    return await manager.check_security_alerts(user_id)


async def cleanup_expired_auth_sessions() -> int:
    """Cleanup expired authentication sessions."""
    manager = get_auth_session_manager()
    return await manager.cleanup_expired_sessions()


# Database index management for authentication collections
async def ensure_auth_indexes() -> None:
    """Ensure all authentication-related indexes are created."""
    try:
        manager = await get_connection_manager()

        # Auth sessions collection
        async with manager.get_collection("auth_sessions") as collection:
            # Primary indexes
            await collection.create_index("session_id", unique=True, background=True)
            await collection.create_index("user_id", background=True)
            await collection.create_index("state", background=True)
            await collection.create_index("expires_at", background=True)

            # Compound indexes
            await collection.create_index(
                [("user_id", 1), ("state", 1), ("expires_at", 1)], background=True
            )

            # TTL index for automatic cleanup
            await collection.create_index(
                "expires_at", expireAfterSeconds=0, background=True
            )

        # Auth events collection
        async with manager.get_collection("auth_events") as collection:
            await collection.create_index("user_id", background=True)
            await collection.create_index("event_type", background=True)
            await collection.create_index("timestamp", background=True)
            await collection.create_index("ip_address", background=True)

            # Compound index for security analysis
            await collection.create_index(
                [("user_id", 1), ("timestamp", -1)], background=True
            )

            # TTL index - keep auth events for 90 days
            await collection.create_index(
                "timestamp", expireAfterSeconds=7776000, background=True  # 90 days
            )

        # Auth failed attempts collection
        async with manager.get_collection("auth_failed_attempts") as collection:
            await collection.create_index("email", background=True)
            await collection.create_index("timestamp", background=True)
            await collection.create_index("ip_address", background=True)

            # Compound index for lockout detection
            await collection.create_index(
                [("email", 1), ("ip_address", 1), ("timestamp", -1)], background=True
            )

            # TTL index - keep failed attempts for 7 days
            await collection.create_index(
                "timestamp", expireAfterSeconds=604800, background=True  # 7 days
            )

        logger.info("Authentication indexes ensured successfully")

    except Exception as e:
        logger.error(f"Failed to ensure auth indexes: {str(e)}")
        raise


# Export all classes and functions
__all__ = [
    # Enums
    "SessionState",
    "LoginType",
    "DeviceType",
    # Constants
    "ORGANIZATION_MODULES",
    # Data Classes
    "DeviceFingerprint",
    "SessionContext",
    # Core Classes
    "AuthenticationSessionManager",
    "CorelySSOManager",
    # Global Functions
    "get_auth_session_manager",
    "get_sso_manager",
    # Convenience Functions
    "authenticate_user",
    "authenticate_sso_user",
    "validate_user_session",
    "logout_user",
    "refresh_user_tokens",
    "get_user_active_sessions",
    "check_user_security_alerts",
    "cleanup_expired_auth_sessions",
    "ensure_auth_indexes",
]
