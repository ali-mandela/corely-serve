"""
Enterprise Multi-Tenant Stores Management System - Security Middleware
This module provides comprehensive security middleware that integrates all security components.
"""

import time
import uuid
import logging
from typing import Optional, Dict, Any, Callable, List
from datetime import datetime
import json

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from app._core.config.settings import get_settings
from app._core.config.environment import is_development, is_production
from app._core.security.validation import (
    detect_malicious_input,
    sanitize_user_input,
    validate_cors_request,
)
from app._core.security.rate_limiting import RateLimitManager, SecurityRateLimiter
from app._core.security.cors import CORSSecurityEnforcer, log_cors_violation
from app._core.utils.constants import SecurityConstants
from app._core.utils.exceptions import (
    AuthorizationException,
    ValidationException,
    RateLimitExceededException,
)


logger = logging.getLogger(__name__)


class SecurityContext:
    """Security context for request processing"""

    def __init__(self, request: Request):
        self.request = request
        self.request_id = str(uuid.uuid4())
        self.start_time = time.time()
        self.client_ip = self._get_client_ip()
        self.user_agent = request.headers.get("user-agent", "")
        self.origin = request.headers.get("origin")
        self.referer = request.headers.get("referer")
        self.tenant_id: Optional[str] = None
        self.user_id: Optional[str] = None
        self.user_role: Optional[str] = None
        self.is_authenticated = False
        self.security_flags: List[str] = []
        self.risk_score = 0

    def _get_client_ip(self) -> str:
        """Get client IP address"""
        # Check forwarded headers (for proxies/load balancers)
        forwarded_for = self.request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = self.request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct connection
        if hasattr(self.request, "client") and self.request.client:
            return self.request.client.host

        return "unknown"

    def add_security_flag(self, flag: str) -> None:
        """Add security flag to context"""
        self.security_flags.append(flag)
        self.risk_score += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert security context to dictionary for logging"""
        return {
            "request_id": self.request_id,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "origin": self.origin,
            "referer": self.referer,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "user_role": self.user_role,
            "is_authenticated": self.is_authenticated,
            "security_flags": self.security_flags,
            "risk_score": self.risk_score,
            "path": self.request.url.path,
            "method": self.request.method,
            "processing_time": time.time() - self.start_time,
        }


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""

    def __init__(self, app):
        super().__init__(app)
        self.settings = get_settings()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to response"""
        response = await call_next(request)

        # Basic security headers
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-Permitted-Cross-Domain-Policies": "none",
        }

        # Add security headers from settings
        if hasattr(self.settings.security, "security_headers"):
            security_headers.update(self.settings.security.security_headers)

        # Production-specific headers
        if is_production():
            if self.settings.security.require_https:
                security_headers["Strict-Transport-Security"] = (
                    "max-age=31536000; includeSubDomains"
                )

            # Content Security Policy
            csp = self._build_csp_header()
            if csp:
                security_headers["Content-Security-Policy"] = csp

        # Apply headers to response
        for header, value in security_headers.items():
            response.headers[header] = value

        return response

    def _build_csp_header(self) -> str:
        """Build Content Security Policy header"""
        if is_development():
            # Relaxed CSP for development
            return "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https:; connect-src 'self' ws: wss:"
        else:
            # Strict CSP for production
            return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none';"


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Validate and sanitize incoming requests"""

    def __init__(self, app):
        super().__init__(app)
        self.max_request_size = 10 * 1024 * 1024  # 10MB
        self.max_header_size = 16 * 1024  # 16KB

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Validate incoming request"""
        try:
            # Check request size
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.max_request_size:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "Request too large",
                        "max_size": self.max_request_size,
                    },
                )

            # Check header size
            total_header_size = sum(len(k) + len(v) for k, v in request.headers.items())
            if total_header_size > self.max_header_size:
                return JSONResponse(
                    status_code=431, content={"error": "Request headers too large"}
                )

            # Validate HTTP method
            allowed_methods = {
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "OPTIONS",
                "HEAD",
            }
            if request.method not in allowed_methods:
                return JSONResponse(
                    status_code=405, content={"error": "Method not allowed"}
                )

            # Check for malicious patterns in URL
            if detect_malicious_input(str(request.url)):
                logger.warning(f"Malicious URL detected: {request.url}")
                return JSONResponse(
                    status_code=400, content={"error": "Invalid request"}
                )

            # Validate query parameters
            for key, value in request.query_params.items():
                if detect_malicious_input(f"{key}={value}"):
                    logger.warning(f"Malicious query parameter: {key}={value}")
                    return JSONResponse(
                        status_code=400, content={"error": "Invalid query parameters"}
                    )

            # Process request
            response = await call_next(request)
            return response

        except Exception as e:
            logger.error(f"Request validation error: {str(e)}")
            return JSONResponse(
                status_code=500, content={"error": "Internal server error"}
            )


class SecurityLoggingMiddleware(BaseHTTPMiddleware):
    """Security-focused request/response logging"""

    def __init__(self, app):
        super().__init__(app)
        self.security_logger = logging.getLogger("security")
        self.suspicious_paths = {
            "/admin",
            "/.env",
            "/config",
            "/backup",
            "/wp-admin",
            "/phpmyadmin",
            "/.git",
            "/debug",
            "/test",
        }
        self.sensitive_headers = {
            "authorization",
            "x-api-key",
            "cookie",
            "x-auth-token",
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log security-relevant request/response data"""
        security_ctx = SecurityContext(request)

        # Add request ID to headers for tracing
        request.state.security_context = security_ctx

        start_time = time.time()

        try:
            # Pre-request security checks
            await self._pre_request_checks(security_ctx)

            # Process request
            response = await call_next(request)

            # Post-request security analysis
            await self._post_request_analysis(security_ctx, response, start_time)

            # Add request ID to response headers
            response.headers["X-Request-ID"] = security_ctx.request_id

            return response

        except Exception as e:
            # Log security exceptions
            self.security_logger.error(
                f"Security middleware error: {str(e)}",
                extra={"security_context": security_ctx.to_dict()},
            )
            raise

    async def _pre_request_checks(self, ctx: SecurityContext) -> None:
        """Perform pre-request security checks"""
        request = ctx.request

        # Check for suspicious paths
        path_lower = request.url.path.lower()
        for suspicious_path in self.suspicious_paths:
            if suspicious_path in path_lower:
                ctx.add_security_flag("suspicious_path")
                self.security_logger.warning(
                    f"Suspicious path access: {request.url.path}",
                    extra={"security_context": ctx.to_dict()},
                )

        # Check for bot/scanner patterns
        user_agent = ctx.user_agent.lower()
        bot_patterns = ["bot", "crawler", "spider", "scan", "test", "curl", "wget"]
        if any(pattern in user_agent for pattern in bot_patterns):
            ctx.add_security_flag("potential_bot")

        # Check for missing critical headers
        if not request.headers.get("user-agent"):
            ctx.add_security_flag("missing_user_agent")

        # Log high-risk requests
        if ctx.risk_score >= 2:
            self.security_logger.warning(
                f"High-risk request detected", extra={"security_context": ctx.to_dict()}
            )

    async def _post_request_analysis(
        self, ctx: SecurityContext, response: Response, start_time: float
    ) -> None:
        """Analyze response for security issues"""
        processing_time = time.time() - start_time

        # Check for unusually long processing times (potential DoS)
        if processing_time > 10.0:  # 10 seconds
            ctx.add_security_flag("slow_request")
            self.security_logger.warning(
                f"Slow request detected: {processing_time:.2f}s",
                extra={"security_context": ctx.to_dict()},
            )

        # Log error responses
        if response.status_code >= 400:
            log_level = logging.WARNING if response.status_code < 500 else logging.ERROR
            self.security_logger.log(
                log_level,
                f"Error response: {response.status_code}",
                extra={
                    "security_context": ctx.to_dict(),
                    "response_status": response.status_code,
                },
            )

        # Log successful authentication events
        if "/auth/" in ctx.request.url.path and response.status_code == 200:
            self.security_logger.info(
                "Authentication successful", extra={"security_context": ctx.to_dict()}
            )


class ThreatDetectionMiddleware(BaseHTTPMiddleware):
    """Advanced threat detection middleware"""

    def __init__(self, app):
        super().__init__(app)
        self.rate_manager = RateLimitManager()
        self.security_limiter = SecurityRateLimiter(self.rate_manager)
        self.threat_logger = logging.getLogger("security.threats")

        # Threat detection patterns
        self.sql_injection_patterns = [
            r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bDROP\b)",
            r"(--|#|/\*|\*/)",
            r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+",
        ]

        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r"on\w+\s*=",
        ]

        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%252e%252e%252f",
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Detect and prevent various threats"""
        try:
            # Get security context
            security_ctx = getattr(
                request.state, "security_context", SecurityContext(request)
            )

            # Perform threat detection
            threat_detected = await self._detect_threats(request, security_ctx)

            if threat_detected:
                # Block the request
                await self._handle_threat(request, security_ctx, threat_detected)
                return JSONResponse(
                    status_code=403,
                    content={"error": "Request blocked by security policy"},
                )

            # Process request
            response = await call_next(request)

            # Post-response threat analysis
            await self.security_limiter.check_suspicious_activity(
                self.rate_manager.create_identifier(request),
                request,
                response.status_code,
            )

            return response

        except Exception as e:
            self.threat_logger.error(f"Threat detection error: {str(e)}")
            return await call_next(request)

    async def _detect_threats(
        self, request: Request, ctx: SecurityContext
    ) -> Optional[str]:
        """Detect various types of threats"""
        # Check for SQL injection
        if await self._check_sql_injection(request):
            ctx.add_security_flag("sql_injection_attempt")
            return "sql_injection"

        # Check for XSS
        if await self._check_xss(request):
            ctx.add_security_flag("xss_attempt")
            return "xss"

        # Check for path traversal
        if await self._check_path_traversal(request):
            ctx.add_security_flag("path_traversal_attempt")
            return "path_traversal"

        # Check for CSRF
        if await self._check_csrf(request):
            ctx.add_security_flag("csrf_attempt")
            return "csrf"

        # Check for excessive requests
        if await self._check_rate_abuse(request):
            ctx.add_security_flag("rate_abuse")
            return "rate_abuse"

        return None

    async def _check_sql_injection(self, request: Request) -> bool:
        """Check for SQL injection attempts"""
        # Check query parameters
        for key, value in request.query_params.items():
            for pattern in self.sql_injection_patterns:
                import re

                if re.search(pattern, f"{key}={value}", re.IGNORECASE):
                    return True

        # Check URL path
        for pattern in self.sql_injection_patterns:
            import re

            if re.search(pattern, request.url.path, re.IGNORECASE):
                return True

        return False

    async def _check_xss(self, request: Request) -> bool:
        """Check for XSS attempts"""
        # Check query parameters
        for key, value in request.query_params.items():
            for pattern in self.xss_patterns:
                import re

                if re.search(pattern, f"{key}={value}", re.IGNORECASE):
                    return True

        # Check headers
        for header_name, header_value in request.headers.items():
            for pattern in self.xss_patterns:
                import re

                if re.search(pattern, header_value, re.IGNORECASE):
                    return True

        return False

    async def _check_path_traversal(self, request: Request) -> bool:
        """Check for path traversal attempts"""
        path = request.url.path
        for pattern in self.path_traversal_patterns:
            import re

            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False

    async def _check_csrf(self, request: Request) -> bool:
        """Check for CSRF attempts"""
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return False

        # Check for missing CSRF protection
        if not CORSSecurityEnforcer.check_csrf_protection(request):
            return True

        return False

    async def _check_rate_abuse(self, request: Request) -> bool:
        """Check for rate limit abuse"""
        identifier = self.rate_manager.create_identifier(request)

        # Check if already rate limited
        if await self.rate_manager.is_rate_limited(identifier, "default"):
            return True

        # Check if blocked
        if await self.rate_manager.is_blocked(identifier):
            return True

        return False

    async def _handle_threat(
        self, request: Request, ctx: SecurityContext, threat_type: str
    ) -> None:
        """Handle detected threat"""
        identifier = self.rate_manager.create_identifier(request)

        # Log the threat
        self.threat_logger.error(
            f"Threat detected: {threat_type}",
            extra={
                "security_context": ctx.to_dict(),
                "threat_type": threat_type,
                "identifier": identifier,
            },
        )

        # Apply blocking based on threat severity
        if threat_type in ["sql_injection", "xss", "path_traversal"]:
            # Block for 1 hour for severe threats
            await self.rate_manager.add_to_blocklist(identifier, 3600)
        else:
            # Block for 15 minutes for moderate threats
            await self.rate_manager.add_to_blocklist(identifier, 900)


class ComprehensiveSecurityMiddleware(BaseHTTPMiddleware):
    """Main security middleware that orchestrates all security components"""

    def __init__(self, app):
        super().__init__(app)
        self.settings = get_settings()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Orchestrate all security checks"""
        # Skip security for health checks in development
        if is_development() and request.url.path in ["/health", "/ready"]:
            return await call_next(request)

        try:
            # 1. CORS validation
            if is_production():
                validate_cors_request(request)

            # 2. Process through all security middlewares
            # (The individual middlewares are already applied to the app)
            response = await call_next(request)

            # 3. Post-processing security checks
            await self._post_process_security(request, response)

            return response

        except AuthorizationException as e:
            return JSONResponse(
                status_code=403, content={"error": "Access denied", "message": str(e)}
            )
        except ValidationException as e:
            return JSONResponse(
                status_code=400,
                content={"error": "Validation failed", "message": str(e)},
            )
        except RateLimitExceededException as e:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "message": str(e)},
            )
        except Exception as e:
            logger.error(f"Security middleware error: {str(e)}")
            return JSONResponse(
                status_code=500, content={"error": "Internal server error"}
            )

    async def _post_process_security(
        self, request: Request, response: Response
    ) -> None:
        """Post-process security checks"""
        # Add security context to response if available
        if hasattr(request.state, "security_context"):
            security_ctx = request.state.security_context

            # Add security headers based on context
            if security_ctx.risk_score > 0:
                response.headers["X-Security-Risk-Score"] = str(security_ctx.risk_score)

            if security_ctx.security_flags:
                response.headers["X-Security-Flags"] = ",".join(
                    security_ctx.security_flags
                )


def setup_security_middleware(app) -> None:
    """Setup all security middleware for the application"""
    # Apply middleware in the correct order (last added = first executed)

    # 1. Comprehensive security middleware (outermost)
    app.add_middleware(ComprehensiveSecurityMiddleware)

    # 2. Threat detection
    app.add_middleware(ThreatDetectionMiddleware)

    # 3. Security logging
    app.add_middleware(SecurityLoggingMiddleware)

    # 4. Request validation
    app.add_middleware(RequestValidationMiddleware)

    # 5. Security headers (innermost)
    app.add_middleware(SecurityHeadersMiddleware)


# Export all classes and functions
__all__ = [
    # Data Classes
    "SecurityContext",
    # Middleware Classes
    "SecurityHeadersMiddleware",
    "RequestValidationMiddleware",
    "SecurityLoggingMiddleware",
    "ThreatDetectionMiddleware",
    "ComprehensiveSecurityMiddleware",
    # Setup Function
    "setup_security_middleware",
]
