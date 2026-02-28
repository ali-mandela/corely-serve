"""
Enterprise Multi-Tenant Stores Management System - Rate Limiting & Throttling
This module provides API rate limiting, throttling, and abuse prevention.
"""

import time
import asyncio
import hashlib
from typing import Dict, Any, Optional, Tuple, Callable, List
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
import json

from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app._core.config.settings import get_settings
from app._core.config.environment import is_development, is_production
from app._core.utils.constants import RateLimitConstants
from app._core.utils.exceptions import RateLimitExceededException


class RateLimitStrategy(Enum):
    """Rate limiting strategies"""

    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class RateLimitRule:
    """Rate limit rule definition"""

    requests: int
    window_seconds: int
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    burst_limit: Optional[int] = None
    grace_period: int = 0


@dataclass
class RateLimitResult:
    """Rate limit check result"""

    allowed: bool
    remaining: int
    reset_time: int
    retry_after: Optional[int] = None
    current_usage: int = 0


class MemoryRateLimitStore:
    """In-memory rate limit storage for development/free hosting"""

    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self._timestamps: Dict[str, deque] = defaultdict(deque)
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.time()

    async def increment(self, key: str, window_seconds: int) -> Tuple[int, int]:
        """Increment counter and return (current_count, reset_time)"""
        await self._cleanup_expired()

        now = time.time()
        window_start = now - window_seconds

        # Clean old timestamps
        timestamps = self._timestamps[key]
        while timestamps and timestamps[0] < window_start:
            timestamps.popleft()

        # Add current timestamp
        timestamps.append(now)

        # Calculate reset time (next window)
        reset_time = int(now + window_seconds)

        return len(timestamps), reset_time

    async def get_count(self, key: str, window_seconds: int) -> Tuple[int, int]:
        """Get current count without incrementing"""
        await self._cleanup_expired()

        now = time.time()
        window_start = now - window_seconds

        # Clean old timestamps
        timestamps = self._timestamps[key]
        while timestamps and timestamps[0] < window_start:
            timestamps.popleft()

        reset_time = int(now + window_seconds)
        return len(timestamps), reset_time

    async def set_data(self, key: str, data: Dict[str, Any], ttl: int) -> None:
        """Set arbitrary data with TTL"""
        expires_at = time.time() + ttl
        self._data[key] = {**data, "_expires_at": expires_at}

    async def get_data(self, key: str) -> Optional[Dict[str, Any]]:
        """Get arbitrary data"""
        data = self._data.get(key)
        if data and data.get("_expires_at", 0) > time.time():
            return {k: v for k, v in data.items() if k != "_expires_at"}
        return None

    async def delete(self, key: str) -> None:
        """Delete key"""
        self._data.pop(key, None)
        self._timestamps.pop(key, None)

    async def _cleanup_expired(self) -> None:
        """Clean up expired data"""
        now = time.time()

        # Only cleanup every few minutes to avoid performance impact
        if now - self._last_cleanup < self._cleanup_interval:
            return

        self._last_cleanup = now

        # Clean expired data
        expired_keys = []
        for key, data in self._data.items():
            if data.get("_expires_at", 0) < now:
                expired_keys.append(key)

        for key in expired_keys:
            del self._data[key]

        # Clean old timestamps (keep only last hour)
        hour_ago = now - 3600
        for key, timestamps in self._timestamps.items():
            while timestamps and timestamps[0] < hour_ago:
                timestamps.popleft()


class RateLimitManager:
    """Main rate limiting manager"""

    def __init__(self):
        self.settings = get_settings()
        self.store = MemoryRateLimitStore()  # Use memory store for now
        self._rules_cache: Dict[str, RateLimitRule] = {}
        self._build_rules_cache()

    def _build_rules_cache(self) -> None:
        """Build rate limiting rules cache"""
        if not self.settings.rate_limit.enabled:
            return

        # Default rules
        default_requests = self.settings.rate_limit.requests_per_minute
        self._rules_cache.update(
            {
                "default": RateLimitRule(default_requests, 60),
                "auth": RateLimitRule(10, 60),  # 10 auth requests per minute
                "upload": RateLimitRule(5, 60),  # 5 uploads per minute
                "search": RateLimitRule(50, 60),  # 50 searches per minute
                "export": RateLimitRule(3, 300),  # 3 exports per 5 minutes
                "bulk": RateLimitRule(2, 300),  # 2 bulk operations per 5 minutes
            }
        )

        # Role-based rules (if user roles are available)
        self._rules_cache.update(
            {
                "admin": RateLimitRule(200, 60),  # 200 requests per minute for admins
                "manager": RateLimitRule(
                    100, 60
                ),  # 100 requests per minute for managers
                "employee": RateLimitRule(
                    50, 60
                ),  # 50 requests per minute for employees
                "customer": RateLimitRule(
                    30, 60
                ),  # 30 requests per minute for customers
            }
        )

        # IP-based rules
        self._rules_cache.update(
            {
                "ip_default": RateLimitRule(100, 60),  # 100 requests per minute per IP
                "ip_suspicious": RateLimitRule(
                    5, 300
                ),  # 5 requests per 5 minutes for suspicious IPs
            }
        )

    def get_rule(self, rule_name: str) -> Optional[RateLimitRule]:
        """Get rate limiting rule by name"""
        return self._rules_cache.get(rule_name)

    async def check_rate_limit(
        self, identifier: str, rule_name: str = "default", increment: bool = True
    ) -> RateLimitResult:
        """Check and optionally increment rate limit"""
        if not self.settings.rate_limit.enabled:
            return RateLimitResult(
                allowed=True, remaining=999999, reset_time=int(time.time() + 3600)
            )

        rule = self.get_rule(rule_name)
        if not rule:
            rule = self.get_rule("default")

        key = f"rate_limit:{rule_name}:{identifier}"

        if increment:
            current_count, reset_time = await self.store.increment(
                key, rule.window_seconds
            )
        else:
            current_count, reset_time = await self.store.get_count(
                key, rule.window_seconds
            )

        allowed = current_count <= rule.requests
        remaining = max(0, rule.requests - current_count)

        retry_after = None
        if not allowed:
            retry_after = reset_time - int(time.time())

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=retry_after,
            current_usage=current_count,
        )

    async def is_rate_limited(
        self, identifier: str, rule_name: str = "default"
    ) -> bool:
        """Check if identifier is rate limited (without incrementing)"""
        result = await self.check_rate_limit(identifier, rule_name, increment=False)
        return not result.allowed

    async def reset_rate_limit(
        self, identifier: str, rule_name: str = "default"
    ) -> None:
        """Reset rate limit for identifier"""
        key = f"rate_limit:{rule_name}:{identifier}"
        await self.store.delete(key)

    async def add_to_blocklist(
        self, identifier: str, duration_seconds: int = 3600
    ) -> None:
        """Add identifier to temporary blocklist"""
        key = f"blocklist:{identifier}"
        data = {"blocked_at": time.time(), "reason": "rate_limit_exceeded"}
        await self.store.set_data(key, data, duration_seconds)

    async def is_blocked(self, identifier: str) -> bool:
        """Check if identifier is blocked"""
        key = f"blocklist:{identifier}"
        data = await self.store.get_data(key)
        return data is not None

    def create_identifier(self, request: Request, user_id: Optional[str] = None) -> str:
        """Create rate limit identifier from request"""
        # Priority: user_id > api_key > ip_address
        if user_id:
            return f"user:{user_id}"

        # Check for API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # Hash API key for privacy
            hashed_key = hashlib.sha256(api_key.encode()).hexdigest()[:16]
            return f"api:{hashed_key}"

        # Fall back to IP address
        client_ip = self._get_client_ip(request)
        return f"ip:{client_ip}"

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        # Check forwarded headers (for proxies/load balancers)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct connection
        if hasattr(request, "client") and request.client:
            return request.client.host

        return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware for FastAPI"""

    def __init__(self, app, rate_manager: Optional[RateLimitManager] = None):
        super().__init__(app)
        self.rate_manager = rate_manager or RateLimitManager()
        self.exempt_paths = {
            "/health",
            "/ready",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply rate limiting to requests"""
        # Skip rate limiting for exempt paths
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        # Skip in development mode unless explicitly enabled
        if is_development() and not self.rate_manager.settings.rate_limit.enabled:
            return await call_next(request)

        # Create identifier for rate limiting
        user_id = await self._extract_user_id(request)
        identifier = self.rate_manager.create_identifier(request, user_id)

        # Check if blocked
        if await self.rate_manager.is_blocked(identifier):
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "message": "IP address is temporarily blocked due to abuse",
                    "retry_after": 3600,
                },
            )

        # Determine rate limiting rule
        rule_name = self._get_rule_name(request, user_id)

        # Check rate limit
        result = await self.rate_manager.check_rate_limit(identifier, rule_name)

        if not result.allowed:
            # Add to blocklist if severely over limit
            if result.current_usage > result.remaining * 5:  # 5x over limit
                await self.rate_manager.add_to_blocklist(
                    identifier, 3600
                )  # 1 hour block

            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "message": f"Rate limit exceeded. Try again in {result.retry_after} seconds.",
                    "retry_after": result.retry_after,
                },
                headers={
                    "X-RateLimit-Limit": str(
                        self.rate_manager.get_rule(rule_name).requests
                    ),
                    "X-RateLimit-Remaining": str(result.remaining),
                    "X-RateLimit-Reset": str(result.reset_time),
                    "Retry-After": str(result.retry_after),
                },
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers to response
        response.headers["X-RateLimit-Limit"] = str(
            self.rate_manager.get_rule(rule_name).requests
        )
        response.headers["X-RateLimit-Remaining"] = str(result.remaining)
        response.headers["X-RateLimit-Reset"] = str(result.reset_time)

        return response

    async def _extract_user_id(self, request: Request) -> Optional[str]:
        """Extract user ID from request (if authenticated)"""
        # This would typically extract from JWT token or session
        # For now, we'll check for a simple header
        return request.headers.get("X-User-ID")

    def _get_rule_name(self, request: Request, user_id: Optional[str]) -> str:
        """Determine which rate limiting rule to apply"""
        path = request.url.path
        method = request.method

        # Path-based rules
        if "/auth/" in path:
            return "auth"
        elif "/upload" in path or "/import" in path:
            return "upload"
        elif "/search" in path:
            return "search"
        elif "/export" in path:
            return "export"
        elif "/bulk" in path:
            return "bulk"

        # Method-based rules
        if method in ["POST", "PUT", "DELETE", "PATCH"]:
            # More restrictive for write operations
            return "default"

        # User role-based rules (if user is authenticated)
        if user_id:
            user_role = request.headers.get("X-User-Role", "").lower()
            if user_role in ["admin", "manager", "employee", "customer"]:
                return user_role

        return "default"


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on system load"""

    def __init__(self, base_manager: RateLimitManager):
        self.base_manager = base_manager
        self.system_load_threshold = 0.8
        self.adjustment_factor = 0.5
        self._last_check = 0
        self._current_load = 0.0

    async def get_adjusted_rule(self, rule_name: str) -> RateLimitRule:
        """Get rate limit rule adjusted for current system load"""
        base_rule = self.base_manager.get_rule(rule_name)
        if not base_rule:
            return None

        # Update system load periodically
        await self._update_system_load()

        if self._current_load > self.system_load_threshold:
            # Reduce rate limits when system is under load
            adjusted_requests = int(base_rule.requests * self.adjustment_factor)
            return RateLimitRule(
                requests=max(1, adjusted_requests),
                window_seconds=base_rule.window_seconds,
                strategy=base_rule.strategy,
            )

        return base_rule

    async def _update_system_load(self) -> None:
        """Update current system load estimate"""
        now = time.time()
        if now - self._last_check < 30:  # Update every 30 seconds
            return

        self._last_check = now

        try:
            import psutil

            self._current_load = psutil.cpu_percent(interval=None) / 100.0
        except ImportError:
            # Fallback: estimate load based on request volume
            self._current_load = min(1.0, len(self.base_manager._rules_cache) / 100.0)


class SecurityRateLimiter:
    """Security-focused rate limiter for abuse prevention"""

    def __init__(self, base_manager: RateLimitManager):
        self.base_manager = base_manager
        self.suspicious_patterns = {
            "rapid_requests": 100,  # More than 100 requests in 1 minute
            "auth_failures": 5,  # More than 5 auth failures in 5 minutes
            "error_rate": 0.5,  # More than 50% error rate
        }

    async def check_suspicious_activity(
        self, identifier: str, request: Request, response_status: int
    ) -> bool:
        """Check for suspicious activity patterns"""
        # Track rapid requests
        rapid_key = f"security:rapid:{identifier}"
        rapid_result = await self.base_manager.check_rate_limit(
            rapid_key, "ip_suspicious"
        )

        if not rapid_result.allowed:
            await self._flag_suspicious_ip(identifier, "rapid_requests")
            return True

        # Track authentication failures
        if request.url.path.startswith("/auth/") and response_status == 401:
            auth_key = f"security:auth_fail:{identifier}"
            auth_rule = RateLimitRule(5, 300)  # 5 failures in 5 minutes

            count, _ = await self.base_manager.store.increment(auth_key, 300)
            if count > 5:
                await self._flag_suspicious_ip(identifier, "auth_failures")
                return True

        return False

    async def _flag_suspicious_ip(self, identifier: str, reason: str) -> None:
        """Flag IP as suspicious"""
        flag_key = f"security:flagged:{identifier}"
        data = {
            "reason": reason,
            "flagged_at": time.time(),
            "severity": "high" if reason == "rapid_requests" else "medium",
        }

        # Flag for 1 hour
        await self.base_manager.store.set_data(flag_key, data, 3600)

        # Apply more restrictive rate limits
        await self.base_manager.add_to_blocklist(identifier, 1800)  # 30 minutes


# Decorators for route-level rate limiting
def rate_limit(rule_name: str = "default"):
    """Decorator for route-level rate limiting"""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # This would be implemented to work with FastAPI dependencies
            return await func(*args, **kwargs)

        wrapper._rate_limit_rule = rule_name
        return wrapper

    return decorator


# Utility functions
def setup_rate_limiting(app) -> None:
    """Setup rate limiting for FastAPI application"""
    if is_production() or get_settings().rate_limit.enabled:
        rate_manager = RateLimitManager()
        middleware = RateLimitMiddleware(app, rate_manager)
        app.add_middleware(lambda app: middleware)


def create_rate_limit_response(
    result: RateLimitResult, rule: RateLimitRule
) -> JSONResponse:
    """Create standardized rate limit response"""
    return JSONResponse(
        status_code=429,
        content={
            "error": "Too Many Requests",
            "message": f"Rate limit of {rule.requests} requests per {rule.window_seconds} seconds exceeded.",
            "retry_after": result.retry_after,
        },
        headers={
            "X-RateLimit-Limit": str(rule.requests),
            "X-RateLimit-Remaining": str(result.remaining),
            "X-RateLimit-Reset": str(result.reset_time),
            "Retry-After": str(result.retry_after) if result.retry_after else "60",
        },
    )


# Export all classes and functions
__all__ = [
    # Enums and Data Classes
    "RateLimitStrategy",
    "RateLimitRule",
    "RateLimitResult",
    # Core Classes
    "MemoryRateLimitStore",
    "RateLimitManager",
    "RateLimitMiddleware",
    "AdaptiveRateLimiter",
    "SecurityRateLimiter",
    # Decorators
    "rate_limit",
    # Utility Functions
    "setup_rate_limiting",
    "create_rate_limit_response",
]
