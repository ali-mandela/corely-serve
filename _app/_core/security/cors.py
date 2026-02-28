"""
Enterprise Multi-Tenant Stores Management System - CORS Security Configuration
This module provides CORS (Cross-Origin Resource Sharing) configuration and security.
"""

import re
from typing import List, Dict, Any, Optional, Union, Callable
from urllib.parse import urlparse
from fastapi import Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from app._core.config.settings import get_settings
from app._core.config.environment import is_development, is_production
from app._core.utils.constants import SecurityConstants
from app._core.utils.exceptions import AuthorizationException


class CORSConfig:
    """CORS configuration manager for different environments"""

    def __init__(self):
        self.settings = get_settings()
        self._allowed_origins_cache = None
        self._compiled_patterns = None

    def get_allowed_origins(self) -> List[str]:
        """Get allowed origins based on environment"""
        if self._allowed_origins_cache is not None:
            return self._allowed_origins_cache

        origins = []

        if is_development():
            # Development: Allow localhost and common dev ports
            origins.extend(
                [
                    "http://localhost:3000",
                    "http://localhost:3001",
                    "http://localhost:8000",
                    "http://localhost:8080",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:3001",
                    "http://127.0.0.1:8000",
                    "http://127.0.0.1:8080",
                    "http://0.0.0.0:3000",
                    "http://0.0.0.0:8000",
                ]
            )

            # Add any configured development origins
            if self.settings.security.allowed_origins:
                origins.extend(self.settings.security.allowed_origins)

        elif is_production():
            # Production: Only allow explicitly configured origins
            if self.settings.security.allowed_origins:
                origins.extend(self.settings.security.allowed_origins)

            # Add common production origins if not already configured
            prod_origins = [
                "https://app.yourdomain.com",
                "https://admin.yourdomain.com",
                "https://mobile.yourdomain.com",
            ]

            for origin in prod_origins:
                if origin not in origins and self._is_valid_production_origin(origin):
                    origins.append(origin)

        # Remove duplicates and cache
        self._allowed_origins_cache = list(set(origins))
        return self._allowed_origins_cache

    def _is_valid_production_origin(self, origin: str) -> bool:
        """Validate production origin URL"""
        try:
            parsed = urlparse(origin)
            return (
                parsed.scheme == "https"  # HTTPS only in production
                and parsed.netloc  # Must have domain
                and not parsed.netloc.startswith("localhost")  # No localhost
                and not parsed.netloc.startswith("127.0.0.1")  # No local IPs
            )
        except Exception:
            return False

    def get_allowed_methods(self) -> List[str]:
        """Get allowed HTTP methods"""
        if is_development():
            return ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        else:
            return self.settings.security.cors_allow_methods

    def get_allowed_headers(self) -> List[str]:
        """Get allowed request headers"""
        base_headers = [
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization",
            "X-Requested-With",
            "X-Tenant-ID",
            "X-Request-ID",
            "X-Correlation-ID",
            "Cache-Control",
        ]

        if is_development():
            # Allow more headers in development
            base_headers.extend(["X-Debug-Mode", "X-Dev-Token", "Origin", "Referer"])

        # Add any configured headers
        if self.settings.security.cors_allow_headers:
            base_headers.extend(self.settings.security.cors_allow_headers)

        return list(set(base_headers))

    def get_exposed_headers(self) -> List[str]:
        """Get headers exposed to the client"""
        return [
            "X-Total-Count",
            "X-Page-Count",
            "X-Request-ID",
            "X-Rate-Limit-Remaining",
            "X-Rate-Limit-Reset",
            "X-API-Version",
        ]

    def allow_credentials(self) -> bool:
        """Check if credentials are allowed"""
        return self.settings.security.cors_allow_credentials

    def get_max_age(self) -> int:
        """Get preflight cache duration"""
        if is_development():
            return 300  # 5 minutes in development
        else:
            return 86400  # 24 hours in production


class AdvancedCORSMiddleware(BaseHTTPMiddleware):
    """Advanced CORS middleware with dynamic origin validation"""

    def __init__(self, app, cors_config: CORSConfig):
        super().__init__(app)
        self.cors_config = cors_config
        self._origin_patterns = self._compile_origin_patterns()

    def _compile_origin_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for dynamic origin matching"""
        patterns = []

        if is_development():
            # Development patterns for local development
            dev_patterns = [
                r"^https?://localhost:\d+$",
                r"^https?://127\.0\.0\.1:\d+$",
                r"^https?://0\.0\.0\.0:\d+$",
                r"^https?://.*\.ngrok\.io$",  # ngrok tunnels
                r"^https?://.*\.localhost:\d+$",  # subdomain localhost
            ]

            for pattern in dev_patterns:
                patterns.append(re.compile(pattern))

        return patterns

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process CORS for each request"""
        origin = request.headers.get("origin")

        # Handle preflight requests
        if request.method == "OPTIONS":
            return await self._handle_preflight(request, origin)

        # Process actual request
        response = await call_next(request)

        # Add CORS headers to response
        if origin:
            await self._add_cors_headers(response, request, origin)

        return response

    async def _handle_preflight(
        self, request: Request, origin: Optional[str]
    ) -> Response:
        """Handle CORS preflight requests"""
        if not origin:
            return Response(status_code=400, content="Origin header required")

        if not self._is_origin_allowed(origin):
            return Response(status_code=403, content="Origin not allowed")

        # Get requested method and headers
        requested_method = request.headers.get("access-control-request-method")
        requested_headers = request.headers.get("access-control-request-headers", "")

        # Validate requested method
        allowed_methods = self.cors_config.get_allowed_methods()
        if requested_method and requested_method not in allowed_methods:
            return Response(status_code=405, content="Method not allowed")

        # Create preflight response
        response = Response(status_code=200)

        # Add CORS headers
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = ", ".join(allowed_methods)
        response.headers["Access-Control-Allow-Headers"] = ", ".join(
            self.cors_config.get_allowed_headers()
        )
        response.headers["Access-Control-Max-Age"] = str(self.cors_config.get_max_age())

        if self.cors_config.allow_credentials():
            response.headers["Access-Control-Allow-Credentials"] = "true"

        return response

    async def _add_cors_headers(
        self, response: Response, request: Request, origin: str
    ) -> None:
        """Add CORS headers to actual response"""
        if not self._is_origin_allowed(origin):
            return

        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Expose-Headers"] = ", ".join(
            self.cors_config.get_exposed_headers()
        )

        if self.cors_config.allow_credentials():
            response.headers["Access-Control-Allow-Credentials"] = "true"

        # Add security headers
        if is_production():
            response.headers["Vary"] = "Origin"
            response.headers["X-Content-Type-Options"] = "nosniff"

    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is allowed"""
        if not origin:
            return False

        # Check exact matches first
        allowed_origins = self.cors_config.get_allowed_origins()
        if origin in allowed_origins:
            return True

        # Check wildcard origins
        if "*" in allowed_origins:
            return True

        # Check pattern matches (for development)
        for pattern in self._origin_patterns:
            if pattern.match(origin):
                return True

        return False


class TenantCORSManager:
    """Tenant-specific CORS management"""

    def __init__(self):
        self.tenant_origins: Dict[str, List[str]] = {}
        self.tenant_configs: Dict[str, Dict[str, Any]] = {}

    def add_tenant_origins(self, tenant_id: str, origins: List[str]) -> None:
        """Add allowed origins for a specific tenant"""
        if tenant_id not in self.tenant_origins:
            self.tenant_origins[tenant_id] = []

        # Validate origins before adding
        valid_origins = []
        for origin in origins:
            if self._validate_tenant_origin(origin):
                valid_origins.append(origin)

        self.tenant_origins[tenant_id].extend(valid_origins)
        self.tenant_origins[tenant_id] = list(set(self.tenant_origins[tenant_id]))

    def get_tenant_origins(self, tenant_id: str) -> List[str]:
        """Get allowed origins for a tenant"""
        return self.tenant_origins.get(tenant_id, [])

    def is_origin_allowed_for_tenant(self, tenant_id: str, origin: str) -> bool:
        """Check if origin is allowed for specific tenant"""
        tenant_origins = self.get_tenant_origins(tenant_id)
        return origin in tenant_origins

    def _validate_tenant_origin(self, origin: str) -> bool:
        """Validate tenant-specific origin"""
        try:
            parsed = urlparse(origin)

            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False

            # In production, must use HTTPS
            if is_production() and parsed.scheme != "https":
                return False

            # No suspicious patterns
            suspicious_patterns = ["javascript:", "data:", "blob:", "file:"]

            if any(pattern in origin.lower() for pattern in suspicious_patterns):
                return False

            return True

        except Exception:
            return False

    def set_tenant_cors_config(self, tenant_id: str, config: Dict[str, Any]) -> None:
        """Set custom CORS configuration for tenant"""
        self.tenant_configs[tenant_id] = config

    def get_tenant_cors_config(self, tenant_id: str) -> Dict[str, Any]:
        """Get tenant-specific CORS configuration"""
        return self.tenant_configs.get(tenant_id, {})


class CORSSecurityEnforcer:
    """Additional CORS security enforcement"""

    @staticmethod
    def validate_origin_header(request: Request) -> bool:
        """Validate Origin header for security"""
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")

        if not origin:
            return True  # No origin header is fine for same-origin requests

        # Check for origin/referer mismatch (potential CSRF)
        if referer:
            try:
                origin_parsed = urlparse(origin)
                referer_parsed = urlparse(referer)

                # Origins should match
                if origin_parsed.netloc != referer_parsed.netloc:
                    return False

            except Exception:
                return False

        return True

    @staticmethod
    def check_csrf_protection(request: Request) -> bool:
        """Check CSRF protection for state-changing requests"""
        # Only check for state-changing methods
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return True

        origin = request.headers.get("origin")
        referer = request.headers.get("referer")

        # For AJAX requests, require either Origin or Referer
        if not origin and not referer:
            x_requested_with = request.headers.get("x-requested-with")
            if x_requested_with != "XMLHttpRequest":
                return False

        return True

    @staticmethod
    def detect_cors_abuse(request: Request) -> bool:
        """Detect potential CORS abuse patterns"""
        origin = request.headers.get("origin")

        if not origin:
            return False

        # Check for suspicious origin patterns
        suspicious_patterns = [
            r"null",
            r"file://",
            r"data:",
            r"javascript:",
            r".*\.onion$",  # Tor hidden services
            r".*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*",  # Raw IP addresses
        ]

        for pattern in suspicious_patterns:
            if re.match(pattern, origin, re.IGNORECASE):
                return True

        return False


def create_cors_middleware(app) -> AdvancedCORSMiddleware:
    """Create and configure CORS middleware"""
    cors_config = CORSConfig()
    return AdvancedCORSMiddleware(app, cors_config)


def get_basic_cors_config() -> Dict[str, Any]:
    """Get basic CORS configuration for FastAPI CORSMiddleware"""
    cors_config = CORSConfig()

    return {
        "allow_origins": cors_config.get_allowed_origins(),
        "allow_credentials": cors_config.allow_credentials(),
        "allow_methods": cors_config.get_allowed_methods(),
        "allow_headers": cors_config.get_allowed_headers(),
        "expose_headers": cors_config.get_exposed_headers(),
        "max_age": cors_config.get_max_age(),
    }


def setup_cors_for_app(app):
    """Setup CORS for FastAPI application"""
    if is_development():
        # Use permissive CORS in development
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    else:
        # Use strict CORS in production
        cors_config = get_basic_cors_config()
        app.add_middleware(CORSMiddleware, **cors_config)


def validate_cors_request(request: Request) -> None:
    """Validate CORS request and raise exception if invalid"""
    # Check Origin header validity
    if not CORSSecurityEnforcer.validate_origin_header(request):
        raise AuthorizationException("Invalid Origin header")

    # Check CSRF protection
    if not CORSSecurityEnforcer.check_csrf_protection(request):
        raise AuthorizationException("CSRF protection failed")

    # Check for CORS abuse
    if CORSSecurityEnforcer.detect_cors_abuse(request):
        raise AuthorizationException("Suspicious CORS request detected")


# Utility functions for CORS management
def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin"""
    try:
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)

        return parsed1.scheme == parsed2.scheme and parsed1.netloc == parsed2.netloc
    except Exception:
        return False


def get_origin_from_request(request: Request) -> Optional[str]:
    """Extract origin from request headers"""
    return request.headers.get("origin") or request.headers.get("referer")


def log_cors_violation(request: Request, reason: str) -> None:
    """Log CORS policy violations for security monitoring"""
    import logging

    logger = logging.getLogger("security.cors")

    origin = request.headers.get("origin", "unknown")
    user_agent = request.headers.get("user-agent", "unknown")
    client_ip = getattr(request, "client", {}).get("host", "unknown")

    logger.warning(
        f"CORS violation: {reason} | "
        f"Origin: {origin} | "
        f"IP: {client_ip} | "
        f"User-Agent: {user_agent} | "
        f"Method: {request.method} | "
        f"Path: {request.url.path}"
    )


# Export all classes and functions
__all__ = [
    # Classes
    "CORSConfig",
    "AdvancedCORSMiddleware",
    "TenantCORSManager",
    "CORSSecurityEnforcer",
    # Functions
    "create_cors_middleware",
    "get_basic_cors_config",
    "setup_cors_for_app",
    "validate_cors_request",
    "is_same_origin",
    "get_origin_from_request",
    "log_cors_violation",
]
