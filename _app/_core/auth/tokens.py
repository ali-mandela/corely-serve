"""
Enterprise Multi-Tenant Stores Management System - Token Management
This module provides comprehensive JWT and session token management for the retail chain system.

Features:
- JWT token generation and validation
- Session token management with MongoDB storage
- Multi-tenant token isolation
- Role-based token claims
- Token refresh mechanisms
- Secure token revocation
- Performance optimized token validation
"""

import jwt
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import asyncio

from app._core.config.settings import get_settings
from app._core.database.connection import get_connection_manager
from app._core.utils.exceptions import AuthenticationException, ValidationException
from app._core.utils.constants import DatabaseConstants
from app._core.security.encryption import encrypt_data, decrypt_data


logger = logging.getLogger(__name__)


class TokenType(Enum):
    """Token types for different authentication scenarios."""

    ACCESS = "access"
    REFRESH = "refresh"
    SESSION = "session"
    RESET_PASSWORD = "reset_password"
    EMAIL_VERIFICATION = "email_verification"
    INVITE = "invite"
    API_KEY = "api_key"


class TokenScope(Enum):
    """Token scopes for different access levels."""

    FULL_ACCESS = "full_access"
    READ_ONLY = "read_only"
    STORE_ACCESS = "store_access"
    WAREHOUSE_ACCESS = "warehouse_access"
    CUSTOMER_ACCESS = "customer_access"
    API_ACCESS = "api_access"
    ADMIN_ACCESS = "admin_access"


# Retail Chain Role Hierarchy
ROLE_HIERARCHY = {
    "SUPER_ADMIN": 100,
    "TENANT_ADMIN": 90,
    "TENANT_MANAGER": 80,
    "STORE_MANAGER": 70,
    "WAREHOUSE_MANAGER": 70,
    "ASSISTANT_MANAGER": 60,
    "SHIFT_SUPERVISOR": 50,
    "WAREHOUSE_SUPERVISOR": 50,
    "CUSTOMER_SERVICE_MANAGER": 50,
    "BUSINESS_ANALYST": 40,
    "FINANCIAL_ANALYST": 40,
    "CASHIER": 30,
    "SALES_ASSOCIATE": 30,
    "INVENTORY_CLERK": 30,
    "WAREHOUSE_OPERATOR": 30,
    "CUSTOMER_SERVICE_REP": 30,
    "CUSTOMER": 10,
}


@dataclass
class TokenClaims:
    """Standard token claims for the retail system."""

    user_id: str
    tenant_id: Optional[str]
    email: str
    role: str
    role_level: int
    store_id: Optional[str] = None
    warehouse_id: Optional[str] = None
    permissions: List[str] = None
    scope: str = TokenScope.FULL_ACCESS.value
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    issued_at: datetime = None
    expires_at: datetime = None

    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []
        if self.issued_at is None:
            self.issued_at = datetime.now(timezone.utc)


@dataclass
class SessionToken:
    """Session token stored in MongoDB."""

    session_id: str
    user_id: str
    tenant_id: Optional[str]
    token_hash: str
    device_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    last_used: datetime
    expires_at: datetime
    is_active: bool = True
    refresh_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class JWTTokenManager:
    """JWT token management with retail chain specific features."""

    def __init__(self):
        self.settings = get_settings()
        self.algorithm = "HS256"
        self.access_token_expire = timedelta(
            minutes=self.settings.auth.access_token_expire_minutes
        )
        self.refresh_token_expire = timedelta(
            days=self.settings.auth.refresh_token_expire_days
        )

    def generate_access_token(
        self, claims: TokenClaims, expires_delta: Optional[timedelta] = None
    ) -> str:
        """Generate JWT access token."""
        try:
            # Set expiration
            expire_time = expires_delta or self.access_token_expire
            claims.expires_at = claims.issued_at + expire_time

            # Build JWT payload
            payload = {
                "sub": claims.user_id,
                "tenant_id": claims.tenant_id,
                "email": claims.email,
                "role": claims.role,
                "role_level": claims.role_level,
                "store_id": claims.store_id,
                "warehouse_id": claims.warehouse_id,
                "permissions": claims.permissions,
                "scope": claims.scope,
                "session_id": claims.session_id,
                "device_id": claims.device_id,
                "ip_address": claims.ip_address,
                "iat": int(claims.issued_at.timestamp()),
                "exp": int(claims.expires_at.timestamp()),
                "type": TokenType.ACCESS.value,
                "jti": secrets.token_hex(16),  # JWT ID for tracking
            }

            # Remove None values
            payload = {k: v for k, v in payload.items() if v is not None}

            # Generate token
            token = jwt.encode(
                payload, self.settings.auth.secret_key, algorithm=self.algorithm
            )

            logger.debug(f"Generated access token for user {claims.user_id}")
            return token

        except Exception as e:
            logger.error(f"Failed to generate access token: {str(e)}")
            raise AuthenticationException("Failed to generate access token")

    def generate_refresh_token(
        self, claims: TokenClaims, expires_delta: Optional[timedelta] = None
    ) -> str:
        """Generate JWT refresh token."""
        try:
            # Set expiration
            expire_time = expires_delta or self.refresh_token_expire
            claims.expires_at = claims.issued_at + expire_time

            # Build minimal refresh token payload
            payload = {
                "sub": claims.user_id,
                "tenant_id": claims.tenant_id,
                "session_id": claims.session_id,
                "iat": int(claims.issued_at.timestamp()),
                "exp": int(claims.expires_at.timestamp()),
                "type": TokenType.REFRESH.value,
                "jti": secrets.token_hex(16),
            }

            # Remove None values
            payload = {k: v for k, v in payload.items() if v is not None}

            # Generate token
            token = jwt.encode(
                payload, self.settings.auth.secret_key, algorithm=self.algorithm
            )

            logger.debug(f"Generated refresh token for user {claims.user_id}")
            return token

        except Exception as e:
            logger.error(f"Failed to generate refresh token: {str(e)}")
            raise AuthenticationException("Failed to generate refresh token")

    def validate_token(
        self, token: str, expected_type: Optional[TokenType] = None
    ) -> Dict[str, Any]:
        """Validate and decode JWT token."""
        try:
            # Decode token
            payload = jwt.decode(
                token, self.settings.auth.secret_key, algorithms=[self.algorithm]
            )

            # Check token type if specified
            if expected_type and payload.get("type") != expected_type.value:
                raise AuthenticationException(
                    f"Invalid token type. Expected {expected_type.value}"
                )

            # Convert timestamps back to datetime
            if "iat" in payload:
                payload["issued_at"] = datetime.fromtimestamp(
                    payload["iat"], tz=timezone.utc
                )
            if "exp" in payload:
                payload["expires_at"] = datetime.fromtimestamp(
                    payload["exp"], tz=timezone.utc
                )

            logger.debug(f"Successfully validated token for user {payload.get('sub')}")
            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            raise AuthenticationException("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise AuthenticationException("Invalid token")
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            raise AuthenticationException("Token validation failed")

    def refresh_access_token(
        self, refresh_token: str, new_claims: Optional[TokenClaims] = None
    ) -> Tuple[str, str]:
        """Refresh access token using refresh token."""
        try:
            # Validate refresh token
            refresh_payload = self.validate_token(refresh_token, TokenType.REFRESH)

            # Create new claims or use existing
            if new_claims is None:
                new_claims = TokenClaims(
                    user_id=refresh_payload["sub"],
                    tenant_id=refresh_payload.get("tenant_id"),
                    email="",  # Will be filled from database
                    role="",  # Will be filled from database
                    role_level=0,  # Will be filled from database
                    session_id=refresh_payload.get("session_id"),
                )

            # Generate new tokens
            new_access_token = self.generate_access_token(new_claims)
            new_refresh_token = self.generate_refresh_token(new_claims)

            logger.info(f"Refreshed tokens for user {new_claims.user_id}")
            return new_access_token, new_refresh_token

        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise AuthenticationException("Failed to refresh token")

    def extract_claims(self, token: str) -> TokenClaims:
        """Extract claims from JWT token."""
        try:
            payload = self.validate_token(token)

            return TokenClaims(
                user_id=payload["sub"],
                tenant_id=payload.get("tenant_id"),
                email=payload.get("email", ""),
                role=payload.get("role", ""),
                role_level=payload.get("role_level", 0),
                store_id=payload.get("store_id"),
                warehouse_id=payload.get("warehouse_id"),
                permissions=payload.get("permissions", []),
                scope=payload.get("scope", TokenScope.FULL_ACCESS.value),
                session_id=payload.get("session_id"),
                device_id=payload.get("device_id"),
                ip_address=payload.get("ip_address"),
                issued_at=payload.get("issued_at"),
                expires_at=payload.get("expires_at"),
            )

        except Exception as e:
            logger.error(f"Failed to extract claims: {str(e)}")
            raise AuthenticationException("Failed to extract token claims")


class SessionTokenManager:
    """Session token management with MongoDB storage."""

    def __init__(self):
        self.settings = get_settings()
        self.session_expire = timedelta(days=self.settings.auth.session_expire_days)

    async def create_session_token(
        self,
        user_id: str,
        tenant_id: Optional[str],
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> SessionToken:
        """Create a new session token."""
        try:
            # Generate session data
            session_id = secrets.token_urlsafe(32)
            raw_token = secrets.token_urlsafe(64)
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

            now = datetime.now(timezone.utc)
            expires_at = now + self.session_expire

            # Create session token object
            session_token = SessionToken(
                session_id=session_id,
                user_id=user_id,
                tenant_id=tenant_id,
                token_hash=token_hash,
                device_id=device_id,
                ip_address=ip_address,
                user_agent=user_agent,
                created_at=now,
                last_used=now,
                expires_at=expires_at,
            )

            # Store in MongoDB
            await self._store_session_token(session_token)

            # Return token with raw token for client
            session_token.token_hash = raw_token  # Temporarily replace for return

            logger.info(f"Created session token for user {user_id}")
            return session_token

        except Exception as e:
            logger.error(f"Failed to create session token: {str(e)}")
            raise AuthenticationException("Failed to create session token")

    async def validate_session_token(
        self, token: str, update_last_used: bool = True
    ) -> Optional[SessionToken]:
        """Validate session token against MongoDB storage."""
        try:
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            # Get connection manager and find session
            manager = await get_connection_manager()

            async with manager.get_collection(
                DatabaseConstants.USER_SESSIONS
            ) as collection:
                session_data = await collection.find_one(
                    {
                        "token_hash": token_hash,
                        "is_active": True,
                        "expires_at": {"$gt": datetime.now(timezone.utc)},
                    }
                )

                if not session_data:
                    return None

                # Convert to SessionToken object
                session_token = SessionToken(
                    session_id=session_data["session_id"],
                    user_id=session_data["user_id"],
                    tenant_id=session_data.get("tenant_id"),
                    token_hash=session_data["token_hash"],
                    device_id=session_data.get("device_id"),
                    ip_address=session_data.get("ip_address"),
                    user_agent=session_data.get("user_agent"),
                    created_at=session_data["created_at"],
                    last_used=session_data["last_used"],
                    expires_at=session_data["expires_at"],
                    is_active=session_data["is_active"],
                    refresh_count=session_data.get("refresh_count", 0),
                )

                # Update last used timestamp
                if update_last_used:
                    await self._update_last_used(session_token.session_id)
                    session_token.last_used = datetime.now(timezone.utc)

                return session_token

        except Exception as e:
            logger.error(f"Session token validation failed: {str(e)}")
            return None

    async def revoke_session_token(
        self, session_id: str, user_id: Optional[str] = None
    ) -> bool:
        """Revoke a specific session token."""
        try:
            manager = await get_connection_manager()

            query = {"session_id": session_id}
            if user_id:
                query["user_id"] = user_id

            async with manager.get_collection(
                DatabaseConstants.USER_SESSIONS
            ) as collection:
                result = await collection.update_one(
                    query, {"$set": {"is_active": False}}
                )

                success = result.modified_count > 0
                if success:
                    logger.info(f"Revoked session token {session_id}")

                return success

        except Exception as e:
            logger.error(f"Failed to revoke session token: {str(e)}")
            return False

    async def revoke_all_user_sessions(
        self, user_id: str, except_session_id: Optional[str] = None
    ) -> int:
        """Revoke all session tokens for a user."""
        try:
            manager = await get_connection_manager()

            query = {"user_id": user_id, "is_active": True}
            if except_session_id:
                query["session_id"] = {"$ne": except_session_id}

            async with manager.get_collection(
                DatabaseConstants.USER_SESSIONS
            ) as collection:
                result = await collection.update_many(
                    query, {"$set": {"is_active": False}}
                )

                count = result.modified_count
                logger.info(f"Revoked {count} session tokens for user {user_id}")

                return count

        except Exception as e:
            logger.error(f"Failed to revoke user sessions: {str(e)}")
            return 0

    async def cleanup_expired_sessions(self) -> int:
        """Remove expired session tokens."""
        try:
            manager = await get_connection_manager()

            async with manager.get_collection(
                DatabaseConstants.USER_SESSIONS
            ) as collection:
                result = await collection.delete_many(
                    {"expires_at": {"$lt": datetime.now(timezone.utc)}}
                )

                count = result.deleted_count
                if count > 0:
                    logger.info(f"Cleaned up {count} expired session tokens")

                return count

        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {str(e)}")
            return 0

    async def get_user_sessions(
        self, user_id: str, active_only: bool = True
    ) -> List[SessionToken]:
        """Get all sessions for a user."""
        try:
            manager = await get_connection_manager()

            query = {"user_id": user_id}
            if active_only:
                query["is_active"] = True
                query["expires_at"] = {"$gt": datetime.now(timezone.utc)}

            sessions = []
            async with manager.get_collection(
                DatabaseConstants.USER_SESSIONS
            ) as collection:
                cursor = collection.find(query).sort("last_used", -1)

                async for session_data in cursor:
                    session_token = SessionToken(
                        session_id=session_data["session_id"],
                        user_id=session_data["user_id"],
                        tenant_id=session_data.get("tenant_id"),
                        token_hash=session_data["token_hash"],
                        device_id=session_data.get("device_id"),
                        ip_address=session_data.get("ip_address"),
                        user_agent=session_data.get("user_agent"),
                        created_at=session_data["created_at"],
                        last_used=session_data["last_used"],
                        expires_at=session_data["expires_at"],
                        is_active=session_data["is_active"],
                        refresh_count=session_data.get("refresh_count", 0),
                    )
                    sessions.append(session_token)

            return sessions

        except Exception as e:
            logger.error(f"Failed to get user sessions: {str(e)}")
            return []

    async def _store_session_token(self, session_token: SessionToken) -> None:
        """Store session token in MongoDB."""
        manager = await get_connection_manager()

        async with manager.get_collection(
            DatabaseConstants.USER_SESSIONS
        ) as collection:
            await collection.insert_one(session_token.to_dict())

    async def _update_last_used(self, session_id: str) -> None:
        """Update the last used timestamp for a session."""
        manager = await get_connection_manager()

        async with manager.get_collection(
            DatabaseConstants.USER_SESSIONS
        ) as collection:
            await collection.update_one(
                {"session_id": session_id},
                {"$set": {"last_used": datetime.now(timezone.utc)}},
            )


class TokenManager:
    """Unified token management combining JWT and session tokens."""

    def __init__(self):
        self.jwt_manager = JWTTokenManager()
        self.session_manager = SessionTokenManager()

    async def create_token_pair(
        self,
        claims: TokenClaims,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create JWT access/refresh tokens and session token."""
        try:
            # Create session token
            session_token = await self.session_manager.create_session_token(
                user_id=claims.user_id,
                tenant_id=claims.tenant_id,
                device_id=device_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            # Update claims with session ID
            claims.session_id = session_token.session_id

            # Generate JWT tokens
            access_token = self.jwt_manager.generate_access_token(claims)
            refresh_token = self.jwt_manager.generate_refresh_token(claims)

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "session_token": session_token.token_hash,  # Raw token
                "session_id": session_token.session_id,
                "expires_in": int(self.jwt_manager.access_token_expire.total_seconds()),
                "token_type": "Bearer",
            }

        except Exception as e:
            logger.error(f"Failed to create token pair: {str(e)}")
            raise AuthenticationException("Failed to create authentication tokens")

    async def validate_access_token(
        self, access_token: str, validate_session: bool = True
    ) -> TokenClaims:
        """Validate access token and optionally check session."""
        try:
            # Validate JWT token
            claims = self.jwt_manager.extract_claims(access_token)

            # Optionally validate session
            if validate_session and claims.session_id:
                # We don't have the raw session token, so we'll validate based on session_id existence
                sessions = await self.session_manager.get_user_sessions(claims.user_id)
                active_session = next(
                    (s for s in sessions if s.session_id == claims.session_id), None
                )

                if not active_session:
                    raise AuthenticationException("Session no longer valid")

            return claims

        except Exception as e:
            logger.error(f"Access token validation failed: {str(e)}")
            raise

    async def refresh_token_pair(
        self, refresh_token: str, new_claims: Optional[TokenClaims] = None
    ) -> Dict[str, Any]:
        """Refresh both JWT and session tokens."""
        try:
            # Validate refresh token
            refresh_payload = self.jwt_manager.validate_token(
                refresh_token, TokenType.REFRESH
            )

            # Update session refresh count if session exists
            if refresh_payload.get("session_id"):
                manager = await get_connection_manager()
                async with manager.get_collection(
                    DatabaseConstants.USER_SESSIONS
                ) as collection:
                    await collection.update_one(
                        {"session_id": refresh_payload["session_id"]},
                        {
                            "$inc": {"refresh_count": 1},
                            "$set": {"last_used": datetime.now(timezone.utc)},
                        },
                    )

            # Generate new tokens
            new_access_token, new_refresh_token = self.jwt_manager.refresh_access_token(
                refresh_token, new_claims
            )

            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "expires_in": int(self.jwt_manager.access_token_expire.total_seconds()),
                "token_type": "Bearer",
            }

        except Exception as e:
            logger.error(f"Token pair refresh failed: {str(e)}")
            raise AuthenticationException("Failed to refresh tokens")

    async def revoke_all_tokens(
        self, user_id: str, except_session_id: Optional[str] = None
    ) -> bool:
        """Revoke all tokens for a user (primarily session tokens since JWT can't be revoked)."""
        try:
            count = await self.session_manager.revoke_all_user_sessions(
                user_id, except_session_id
            )

            logger.info(f"Revoked all tokens for user {user_id} ({count} sessions)")
            return count > 0

        except Exception as e:
            logger.error(f"Failed to revoke all tokens: {str(e)}")
            return False


# Global token manager instance
_token_manager: Optional[TokenManager] = None


def get_token_manager() -> TokenManager:
    """Get global token manager instance."""
    global _token_manager
    if _token_manager is None:
        _token_manager = TokenManager()
    return _token_manager


# Convenience functions
async def create_authentication_tokens(
    user_id: str,
    tenant_id: Optional[str],
    email: str,
    role: str,
    permissions: List[str],
    store_id: Optional[str] = None,
    warehouse_id: Optional[str] = None,
    device_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    scope: str = TokenScope.FULL_ACCESS.value,
) -> Dict[str, Any]:
    """Create complete authentication token set."""

    # Get role level
    role_level = ROLE_HIERARCHY.get(role, 0)

    # Create claims
    claims = TokenClaims(
        user_id=user_id,
        tenant_id=tenant_id,
        email=email,
        role=role,
        role_level=role_level,
        store_id=store_id,
        warehouse_id=warehouse_id,
        permissions=permissions,
        scope=scope,
    )

    token_manager = get_token_manager()
    return await token_manager.create_token_pair(
        claims=claims, device_id=device_id, ip_address=ip_address, user_agent=user_agent
    )


async def validate_bearer_token(token: str) -> TokenClaims:
    """Validate Bearer token (JWT access token)."""
    token_manager = get_token_manager()
    return await token_manager.validate_access_token(token)


async def refresh_authentication_tokens(refresh_token: str) -> Dict[str, Any]:
    """Refresh authentication token pair."""
    token_manager = get_token_manager()
    return await token_manager.refresh_token_pair(refresh_token)


async def revoke_user_tokens(
    user_id: str, except_session_id: Optional[str] = None
) -> bool:
    """Revoke all tokens for a user."""
    token_manager = get_token_manager()
    return await token_manager.revoke_all_tokens(user_id, except_session_id)


async def cleanup_expired_tokens() -> int:
    """Cleanup expired session tokens."""
    token_manager = get_token_manager()
    return await token_manager.session_manager.cleanup_expired_sessions()


# Export all classes and functions
__all__ = [
    # Enums
    "TokenType",
    "TokenScope",
    # Data Classes
    "TokenClaims",
    "SessionToken",
    # Constants
    "ROLE_HIERARCHY",
    # Core Classes
    "JWTTokenManager",
    "SessionTokenManager",
    "TokenManager",
    # Global Functions
    "get_token_manager",
    # Convenience Functions
    "create_authentication_tokens",
    "validate_bearer_token",
    "refresh_authentication_tokens",
    "revoke_user_tokens",
    "cleanup_expired_tokens",
]
