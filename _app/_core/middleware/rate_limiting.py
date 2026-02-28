"""
Enterprise-grade rate limiting middleware
"""

import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple, Any, List
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
import asyncio

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class RateLimitType(str, Enum):
    """Types of rate limiting"""

    IP = "ip"
    USER = "user"
    ENDPOINT = "endpoint"
    TENANT = "tenant"
    GLOBAL = "global"


@dataclass
class RateLimit:
    """Rate limit configuration"""

    requests: int  # Number of requests allowed
    window_seconds: int  # Time window in seconds
    burst_requests: int  # Burst requests allowed (optional)
    description: str = ""


class TokenBucket:
    """Token bucket algorithm for rate limiting"""

    def __init__(
        self, capacity: int, refill_rate: float, burst_capacity: Optional[int] = None
    ):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.burst_capacity = burst_capacity or capacity
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket"""
        async with self._lock:
            now = time.time()
            time_passed = now - self.last_refill

            # Refill tokens
            new_tokens = time_passed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + new_tokens)
            self.last_refill = now

            # Try to consume tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get current bucket status"""
        return {
            "tokens": self.tokens,
            "capacity": self.capacity,
            "refill_rate": self.refill_rate,
            "last_refill": self.last_refill,
        }


class SlidingWindowCounter:
    """Sliding window counter for rate limiting"""

    def __init__(self, window_seconds: int, max_requests: int):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.requests = deque()
        self._lock = asyncio.Lock()

    async def is_allowed(self) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is allowed"""
        async with self._lock:
            now = time.time()
            window_start = now - self.window_seconds

            # Remove old requests
            while self.requests and self.requests[0] <= window_start:
                self.requests.popleft()

            # Check if we can accept new request
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True, {
                    "current_requests": len(self.requests),
                    "max_requests": self.max_requests,
                    "window_seconds": self.window_seconds,
                    "reset_time": window_start + self.window_seconds,
                }

            return False, {
                "current_requests": len(self.requests),
                "max_requests": self.max_requests,
                "window_seconds": self.window_seconds,
                "reset_time": self.requests[0] + self.window_seconds,
            }


class DistributedRateLimiter:
    """Enterprise rate limiter with multiple algorithms and storage backends"""

    def __init__(self):
        # In-memory storage (in production, use Redis or similar)
        self.token_buckets: Dict[str, TokenBucket] = {}
        self.sliding_windows: Dict[str, SlidingWindowCounter] = {}
        self.rate_limit_configs: Dict[str, RateLimit] = {}

        # Default rate limits
        self._setup_default_limits()

        # Statistics
        self.stats = defaultdict(
            lambda: {"total_requests": 0, "blocked_requests": 0, "last_request": None}
        )

    def _setup_default_limits(self):
        """Setup default rate limiting configurations"""
        self.rate_limit_configs = {
            # Authentication endpoints - strict limits
            "auth_login": RateLimit(50, 300, 10, "Login attempts"),
            "auth_register": RateLimit(30, 3600, 5, "Registration attempts"),
            "auth_forgot_password": RateLimit(3, 3600, 3, "Password reset attempts"),
            # API endpoints - moderate limits
            "api_read": RateLimit(1000, 3600, 1200, "Read operations"),
            "api_write": RateLimit(100, 3600, 150, "Write operations"),
            "api_delete": RateLimit(20, 3600, 30, "Delete operations"),
            # Admin endpoints - restrictive limits
            "admin_operations": RateLimit(50, 3600, 60, "Admin operations"),
            "user_management": RateLimit(30, 3600, 40, "User management"),
            # Global limits
            "global_per_ip": RateLimit(10000, 3600, 12000, "Global per IP"),
            "global_per_user": RateLimit(5000, 3600, 6000, "Global per user"),
            # Export/import operations
            "data_export": RateLimit(5, 3600, 5, "Data export"),
            "bulk_operations": RateLimit(10, 3600, 15, "Bulk operations"),
        }

    def _get_key(
        self, limit_type: RateLimitType, identifier: str, endpoint: str = ""
    ) -> str:
        """Generate rate limiting key"""
        key_parts = [limit_type.value, identifier]
        if endpoint:
            key_parts.append(endpoint)
        return ":".join(key_parts)

    def _get_rate_limit_config(self, endpoint: str, method: str) -> Optional[RateLimit]:
        """Get rate limit configuration for endpoint"""
        # Check for specific endpoint configuration
        endpoint_key = f"{method.lower()}_{endpoint.replace('/', '_').strip('_')}"
        if endpoint_key in self.rate_limit_configs:
            return self.rate_limit_configs[endpoint_key]

        # Check for pattern-based configurations
        if "/auth/" in endpoint:
            if "login" in endpoint:
                return self.rate_limit_configs["auth_login"]
            elif "register" in endpoint or "invite" in endpoint:
                return self.rate_limit_configs["auth_register"]
            elif "forgot" in endpoint or "reset" in endpoint:
                return self.rate_limit_configs["auth_forgot_password"]

        if "/admin/" in endpoint:
            return self.rate_limit_configs["admin_operations"]

        if method.upper() in ["GET", "HEAD", "OPTIONS"]:
            return self.rate_limit_configs["api_read"]
        elif method.upper() in ["POST", "PUT", "PATCH"]:
            return self.rate_limit_configs["api_write"]
        elif method.upper() == "DELETE":
            return self.rate_limit_configs["api_delete"]

        # Default to moderate limits
        return RateLimit(100, 3600, 120, "Default API limit")

    async def check_rate_limit(
        self,
        request: Request,
        limit_type: RateLimitType,
        identifier: str,
        endpoint: str = "",
        custom_limit: Optional[RateLimit] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check rate limit for a request

        Returns:
            Tuple[bool, Dict]: (is_allowed, rate_limit_info)
        """
        # Get rate limit configuration
        if custom_limit:
            rate_limit = custom_limit
        else:
            rate_limit = self._get_rate_limit_config(endpoint, request.method)

        if not rate_limit:
            return True, {}

        # Generate key
        key = self._get_key(limit_type, identifier, endpoint)

        # Use sliding window counter
        if key not in self.sliding_windows:
            self.sliding_windows[key] = SlidingWindowCounter(
                rate_limit.window_seconds, rate_limit.requests
            )

        allowed, info = await self.sliding_windows[key].is_allowed()

        # Update statistics
        self.stats[key]["total_requests"] += 1
        self.stats[key]["last_request"] = datetime.now(timezone.utc)
        if not allowed:
            self.stats[key]["blocked_requests"] += 1

        # Add rate limit info
        info.update(
            {
                "limit_type": limit_type.value,
                "identifier": identifier,
                "endpoint": endpoint,
                "rate_limit_config": {
                    "requests": rate_limit.requests,
                    "window_seconds": rate_limit.window_seconds,
                    "description": rate_limit.description,
                },
            }
        )

        return allowed, info

    async def check_multiple_limits(
        self, request: Request, checks: List[Tuple[RateLimitType, str, str]]
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """Check multiple rate limits"""
        results = []
        overall_allowed = True

        for limit_type, identifier, endpoint in checks:
            allowed, info = await self.check_rate_limit(
                request, limit_type, identifier, endpoint
            )
            results.append(info)
            if not allowed:
                overall_allowed = False

        return overall_allowed, results

    def get_statistics(self, key_pattern: str = "") -> Dict[str, Any]:
        """Get rate limiting statistics"""
        if key_pattern:
            filtered_stats = {k: v for k, v in self.stats.items() if key_pattern in k}
        else:
            filtered_stats = dict(self.stats)

        return {
            "statistics": filtered_stats,
            "active_buckets": len(self.token_buckets),
            "active_windows": len(self.sliding_windows),
            "configurations": {
                k: v.__dict__ for k, v in self.rate_limit_configs.items()
            },
        }

    async def cleanup_expired(self):
        """Clean up expired rate limit data"""
        current_time = time.time()
        expired_keys = []

        # Clean up sliding windows
        for key, window in self.sliding_windows.items():
            async with window._lock:
                # Remove if no recent activity
                if (
                    not window.requests
                    or (current_time - window.requests[-1]) > window.window_seconds * 2
                ):
                    expired_keys.append(key)

        for key in expired_keys:
            self.sliding_windows.pop(key, None)

        logger.debug(f"Cleaned up {len(expired_keys)} expired rate limit entries")


# Global rate limiter instance
rate_limiter = DistributedRateLimiter()


class RateLimitMiddleware:
    """FastAPI middleware for rate limiting"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        # Extract identifiers
        ip_address = self._get_client_ip(request)
        user_id = self._get_user_id(request)
        tenant_id = self._get_tenant_id(request)
        endpoint = request.url.path

        # Prepare rate limit checks
        checks = [
            (RateLimitType.IP, ip_address, endpoint),
        ]

        if user_id:
            checks.append((RateLimitType.USER, user_id, endpoint))

        if tenant_id:
            checks.append((RateLimitType.TENANT, tenant_id, endpoint))

        # Check rate limits
        allowed, results = await rate_limiter.check_multiple_limits(request, checks)

        if not allowed:
            # Find the most restrictive limit that was exceeded
            blocked_result = next(
                (r for r in results if not r.get("allowed", True)), results[0]
            )

            # Create rate limit response
            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests",
                    "rate_limit_info": blocked_result,
                    "retry_after": blocked_result.get("reset_time", time.time() + 60)
                    - time.time(),
                },
                headers={
                    "Retry-After": str(
                        int(
                            blocked_result.get("reset_time", time.time() + 60)
                            - time.time()
                        )
                    ),
                    "X-RateLimit-Limit": str(blocked_result.get("max_requests", 0)),
                    "X-RateLimit-Remaining": str(
                        max(
                            0,
                            blocked_result.get("max_requests", 0)
                            - blocked_result.get("current_requests", 0),
                        )
                    ),
                    "X-RateLimit-Reset": str(
                        int(blocked_result.get("reset_time", time.time() + 60))
                    ),
                },
            )

            await response(scope, receive, send)
            return

        # Add rate limit headers to successful responses
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))

                # Add rate limit headers from first result
                if results:
                    result = results[0]
                    headers.extend(
                        [
                            (
                                b"x-ratelimit-limit",
                                str(result.get("max_requests", 0)).encode(),
                            ),
                            (
                                b"x-ratelimit-remaining",
                                str(
                                    max(
                                        0,
                                        result.get("max_requests", 0)
                                        - result.get("current_requests", 0),
                                    )
                                ).encode(),
                            ),
                            (
                                b"x-ratelimit-reset",
                                str(
                                    int(result.get("reset_time", time.time() + 60))
                                ).encode(),
                            ),
                        ]
                    )

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, send_with_headers)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address"""
        # Check for forwarded headers
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    def _get_user_id(self, request: Request) -> Optional[str]:
        """Extract user ID from request (implement based on your auth system)"""
        # This would typically extract from JWT token
        # For now, return None as placeholder
        return getattr(request.state, "user_id", None)

    def _get_tenant_id(self, request: Request) -> Optional[str]:
        """Extract tenant ID from request"""
        return getattr(request.state, "tenant_id", None)


# Decorator for endpoint-specific rate limiting
def rate_limit(
    requests: int,
    window_seconds: int,
    limit_type: RateLimitType = RateLimitType.IP,
    burst_requests: Optional[int] = None,
    error_message: str = "Rate limit exceeded",
):
    """Decorator for endpoint-specific rate limiting"""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract request from args
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                # If no request found, proceed without rate limiting
                return await func(*args, **kwargs)

            # Extract identifier based on limit type
            if limit_type == RateLimitType.IP:
                identifier = RateLimitMiddleware(None)._get_client_ip(request)
            elif limit_type == RateLimitType.USER:
                identifier = (
                    RateLimitMiddleware(None)._get_user_id(request) or "anonymous"
                )
            elif limit_type == RateLimitType.TENANT:
                identifier = (
                    RateLimitMiddleware(None)._get_tenant_id(request) or "no_tenant"
                )
            else:
                identifier = "global"

            # Create custom rate limit
            custom_limit = RateLimit(
                requests=requests,
                window_seconds=window_seconds,
                burst_requests=burst_requests or requests,
                description=f"Custom limit for {func.__name__}",
            )

            # Check rate limit
            allowed, info = await rate_limiter.check_rate_limit(
                request=request,
                limit_type=limit_type,
                identifier=identifier,
                endpoint=request.url.path,
                custom_limit=custom_limit,
            )

            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={"error": error_message, "rate_limit_info": info},
                    headers={
                        "Retry-After": str(
                            int(info.get("reset_time", time.time() + 60) - time.time())
                        )
                    },
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator
