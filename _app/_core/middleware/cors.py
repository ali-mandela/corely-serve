"""
CORS middleware configuration for production applications
"""
import logging
from typing import List, Optional, Union
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from ..config import get_settings

logger = logging.getLogger(__name__)


class EnhancedCORSMiddleware(BaseHTTPMiddleware):
    """
    Enhanced CORS middleware with additional security features
    """

    def __init__(
        self,
        app,
        allow_origins: List[str] = None,
        allow_methods: List[str] = None,
        allow_headers: List[str] = None,
        allow_credentials: bool = False,
        allow_origin_regex: Optional[str] = None,
        expose_headers: List[str] = None,
        max_age: int = 600,
        log_cors_requests: bool = True
    ):
        super().__init__(app)
        self.allow_origins = allow_origins or ["*"]
        self.allow_methods = allow_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.allow_headers = allow_headers or [
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization",
            "X-Requested-With",
            "X-Request-ID",
            "X-Correlation-ID",
            "X-Tenant-ID",
            "X-API-Version"
        ]
        self.allow_credentials = allow_credentials
        self.allow_origin_regex = allow_origin_regex
        self.expose_headers = expose_headers or [
            "X-Request-ID",
            "X-Correlation-ID",
            "X-Rate-Limit-Remaining",
            "X-Rate-Limit-Reset"
        ]
        self.max_age = max_age
        self.log_cors_requests = log_cors_requests

    async def dispatch(self, request: Request, call_next) -> Response:
        origin = request.headers.get("origin")

        # Log CORS requests if enabled
        if self.log_cors_requests and origin:
            logger.debug(
                f"CORS request from origin: {origin} for {request.method} {request.url.path}"
            )

        # Handle preflight requests
        if request.method == "OPTIONS":
            response = await self._handle_preflight(request, origin)
            return response

        # Process normal requests
        response = await call_next(request)

        # Add CORS headers to response
        if origin and self._is_origin_allowed(origin):
            self._add_cors_headers(response, origin)

        return response

    async def _handle_preflight(self, request: Request, origin: Optional[str]) -> Response:
        """Handle CORS preflight requests"""
        response = Response(status_code=200)

        if origin and self._is_origin_allowed(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allow_methods)
            response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allow_headers)

            if self.allow_credentials:
                response.headers["Access-Control-Allow-Credentials"] = "true"

            if self.max_age:
                response.headers["Access-Control-Max-Age"] = str(self.max_age)

            if self.expose_headers:
                response.headers["Access-Control-Expose-Headers"] = ", ".join(self.expose_headers)

        return response

    def _add_cors_headers(self, response: Response, origin: str):
        """Add CORS headers to response"""
        response.headers["Access-Control-Allow-Origin"] = origin

        if self.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"

        if self.expose_headers:
            response.headers["Access-Control-Expose-Headers"] = ", ".join(self.expose_headers)

    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is allowed"""
        if "*" in self.allow_origins:
            return True

        if origin in self.allow_origins:
            return True

        # Check regex pattern if configured
        if self.allow_origin_regex:
            import re
            if re.match(self.allow_origin_regex, origin):
                return True

        return False


def get_cors_config() -> dict:
    """
    Get CORS configuration based on environment
    """
    settings = get_settings()

    if settings.ENVIRONMENT == "development":
        return {
            "allow_origins": ["*"],
            "allow_credentials": True,
            "allow_methods": ["*"],
            "allow_headers": ["*"],
        }
    elif settings.ENVIRONMENT == "testing":
        return {
            "allow_origins": [
                "http://localhost:3000",
                "http://localhost:3001",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:3001"
            ],
            "allow_credentials": True,
            "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            "allow_headers": [
                "Accept",
                "Accept-Language",
                "Content-Language",
                "Content-Type",
                "Authorization",
                "X-Requested-With",
                "X-Request-ID",
                "X-Correlation-ID",
                "X-Tenant-ID",
                "X-API-Version"
            ],
        }
    else:  # production
        # In production, you should specify exact origins
        allowed_origins = [
            "https://yourdomain.com",
            "https://app.yourdomain.com",
            "https://admin.yourdomain.com"
        ]

        # Override with environment variable if set
        if settings.CORS_ORIGINS:
            allowed_origins = settings.CORS_ORIGINS.split(",")

        return {
            "allow_origins": allowed_origins,
            "allow_credentials": True,
            "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            "allow_headers": [
                "Accept",
                "Accept-Language",
                "Content-Language",
                "Content-Type",
                "Authorization",
                "X-Requested-With",
                "X-Request-ID",
                "X-Correlation-ID",
                "X-Tenant-ID",
                "X-API-Version"
            ],
            "expose_headers": [
                "X-Request-ID",
                "X-Correlation-ID",
                "X-Rate-Limit-Remaining",
                "X-Rate-Limit-Reset",
                "X-Total-Count"
            ],
            "max_age": 3600,  # 1 hour
        }


def create_cors_middleware():
    """
    Factory function to create CORS middleware with environment-specific config
    """
    config = get_cors_config()
    logger.info(f"Setting up CORS with origins: {config.get('allow_origins')}")

    return CORSMiddleware, config


def create_enhanced_cors_middleware():
    """
    Factory function to create enhanced CORS middleware
    """
    config = get_cors_config()
    logger.info(f"Setting up Enhanced CORS with origins: {config.get('allow_origins')}")

    return lambda app: EnhancedCORSMiddleware(app, **config)


# Security headers for CORS
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to responses
    """

    def __init__(self, app, headers: dict = None):
        super().__init__(app)
        self.headers = headers or SECURITY_HEADERS

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Add security headers
        for header, value in self.headers.items():
            response.headers[header] = value

        return response


def create_security_headers_middleware(custom_headers: dict = None):
    """
    Factory function to create security headers middleware
    """
    headers = SECURITY_HEADERS.copy()
    if custom_headers:
        headers.update(custom_headers)

    return lambda app: SecurityHeadersMiddleware(app, headers)