"""
Security middleware for enterprise applications
"""

import re
import json
import time
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse
import ipaddress

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..audit.logger import log_security_event
from ..audit.models import AuditEventType, AuditSeverity

logger = logging.getLogger(__name__)


class SecurityConfig:
    """Security configuration settings"""

    # CORS settings
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:4200",
        "http://localhost:4201",
        "http://127.0.0.1:4200",
        "http://127.0.0.1:4201",
        "*"
    ]
    ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
    ALLOWED_HEADERS: List[str] = [
        "authorization",
        "content-type",
        "accept",
        "origin",
        "user-agent",
        "x-requested-with",
        "x-forwarded-for",
        "x-api-key",
        "x-real-ip",
        "access-control-allow-origin",
        "access-control-allow-headers",
        "access-control-allow-methods",
    ]
    ALLOW_CREDENTIALS: bool = True

    # Security headers
    SECURITY_HEADERS: Dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        
    }

    # Request validation
    MAX_REQUEST_SIZE: int = 10 * 1024 * 1024  # 10MB
    MAX_JSON_DEPTH: int = 10
    MAX_HEADER_SIZE: int = 8192
    MAX_URL_LENGTH: int = 2048

    # Suspicious patterns
    SQL_INJECTION_PATTERNS: List[str] = [
        r"(\bunion\b.*\bselect\b)|(\bselect\b.*\bunion\b)",
        r"\b(select|insert|update|delete|drop|create|alter|exec|execute)\b",
        r"(\bor\b|\band\b).*['\"].*['\"]",
        r"['\"].*(\bor\b|\band\b).*['\"]",
        r"['\"];.*--",
        r"\/\*.*\*\/",
    ]

    XSS_PATTERNS: List[str] = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<embed[^>]*>",
        r"<object[^>]*>.*?</object>",
    ]

    PATH_TRAVERSAL_PATTERNS: List[str] = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"..%2f",
        r"..%5c",
    ]

    # Blocked IPs and user agents
    BLOCKED_IPS: Set[str] = set()
    BLOCKED_USER_AGENTS: List[str] = [
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "nessus",
        "burpsuite",
        "owasp",
        "w3af",
        "acunetix",
    ]

    # Rate limiting for suspicious activity
    SUSPICIOUS_ACTIVITY_THRESHOLD: int = 1000
    BLOCK_DURATION_MINUTES: int = 15


class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware"""

    def __init__(self, app, config: Optional[SecurityConfig] = None):
        super().__init__(app)
        self.config = config or SecurityConfig()
        self.blocked_ips: Dict[str, datetime] = {}
        self.suspicious_activity: Dict[str, List[datetime]] = {}

    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch method"""
        start_time = time.time()

        # Skip security checks for OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            response = await call_next(request)
            return response

        # Skip security checks for auth and onboarding endpoints
        if request.url.path.startswith(("/api/v1/onboarding", "/api/v1/auth")):
            response = await call_next(request)
            return response

        try:
            # Extract client information
            client_ip = self._get_client_ip(request)
            print("IP", client_ip)
            user_agent = request.headers.get("user-agent", "")

            # 1. Check blocked IPs
            if await self._check_blocked_ip(client_ip):
                return await self._create_blocked_response("IP address blocked")

            # 2. Check blocked user agents
            if await self._check_blocked_user_agent(user_agent):
                return await self._create_blocked_response("User agent blocked")

            # 3. Validate request size and headers
            if not await self._validate_request_constraints(request):
                return await self._create_error_response(
                    "Request validation failed", 400
                )

            # 4. Check for malicious patterns
            threat_detected = await self._detect_threats(request)
            if threat_detected:
                await self._handle_threat_detection(client_ip, threat_detected)
                return await self._create_blocked_response(
                    f"Threat detected: {threat_detected}"
                )

            # 5. Add security headers to request state
            request.state.security_start_time = start_time
            request.state.client_ip = client_ip

            # Process request
            response = await call_next(request)

            # 6. Add security headers to response
            self._add_security_headers(response)

            # 7. Log successful request
            processing_time = time.time() - start_time
            if processing_time > 5.0:  # Log slow requests
                logger.warning(
                    f"Slow request detected: {request.url.path} took {processing_time:.2f}s"
                )

            return response

        except Exception as e:
            # Log security exception
            logger.error(f"Security middleware error: {e}")
            await log_security_event(
                event_type=AuditEventType.SECURITY_VIOLATION,
                description=f"Security middleware error: {str(e)}",
                user_id=None,
                ip_address=self._get_client_ip(request),
                severity=AuditSeverity.HIGH,
            )

            return await self._create_error_response("Security check failed", 500)

    def _get_client_ip(self, request: Request) -> str:
        """Extract real client IP address"""
        # Check forwarded headers
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take the first IP in the chain
            ip = forwarded_for.split(",")[0].strip()
            if self._is_valid_ip(ip):
                return ip

        real_ip = request.headers.get("x-real-ip")
        if real_ip and self._is_valid_ip(real_ip):
            return real_ip

        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    async def _check_blocked_ip(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        if ip in self.config.BLOCKED_IPS:
            return True

        # Check temporary blocks
        if ip in self.blocked_ips:
            block_time = self.blocked_ips[ip]
            if (datetime.utcnow() - block_time).total_seconds() < (
                self.config.BLOCK_DURATION_MINUTES * 60
            ):
                return True
            else:
                # Remove expired block
                del self.blocked_ips[ip]

        return False

    async def _check_blocked_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is blocked"""
        user_agent_lower = user_agent.lower()
        return any(
            blocked in user_agent_lower for blocked in self.config.BLOCKED_USER_AGENTS
        )

    async def _validate_request_constraints(self, request: Request) -> bool:
        """Validate request size and constraints"""
        # Check URL length
        if len(str(request.url)) > self.config.MAX_URL_LENGTH:
            logger.warning(f"URL too long: {len(str(request.url))} characters")
            return False

        # Check header size
        total_header_size = sum(len(f"{k}: {v}") for k, v in request.headers.items())
        if total_header_size > self.config.MAX_HEADER_SIZE:
            logger.warning(f"Headers too large: {total_header_size} bytes")
            return False

        # Check content length
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.config.MAX_REQUEST_SIZE:
                    logger.warning(f"Request body too large: {content_length} bytes")
                    return False
            except ValueError:
                return False

        return True

    async def _detect_threats(self, request: Request) -> Optional[str]:
        """Detect various security threats"""
        url_path = str(request.url.path)
        query_string = str(request.url.query) if request.url.query else ""
        user_agent = request.headers.get("user-agent", "")

        # Combine all text to check
        text_to_check = f"{url_path} {query_string} {user_agent}".lower()

        # Check for SQL injection
        for pattern in self.config.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return "SQL_INJECTION"

        # Check for XSS
        for pattern in self.config.XSS_PATTERNS:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return "XSS_ATTEMPT"

        # Check for path traversal
        for pattern in self.config.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return "PATH_TRAVERSAL"

        # Check for suspicious patterns in request body
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                if hasattr(request, "_body"):
                    body = request._body.decode("utf-8", errors="ignore")
                    for pattern in (
                        self.config.SQL_INJECTION_PATTERNS + self.config.XSS_PATTERNS
                    ):
                        if re.search(pattern, body, re.IGNORECASE):
                            return "MALICIOUS_PAYLOAD"
            except:
                pass  # Ignore body parsing errors

        return None

    async def _handle_threat_detection(self, client_ip: str, threat_type: str):
        """Handle detected security threat"""
        now = datetime.utcnow()

        # Track suspicious activity
        if client_ip not in self.suspicious_activity:
            self.suspicious_activity[client_ip] = []

        self.suspicious_activity[client_ip].append(now)

        # Clean old entries (last hour)
        cutoff_time = (
            now.replace(hour=now.hour - 1)
            if now.hour > 0
            else now.replace(day=now.day - 1, hour=23)
        )
        self.suspicious_activity[client_ip] = [
            t for t in self.suspicious_activity[client_ip] if t > cutoff_time
        ]

        # Check if threshold exceeded
        if (
            len(self.suspicious_activity[client_ip])
            >= self.config.SUSPICIOUS_ACTIVITY_THRESHOLD
        ):
            # Block IP temporarily
            self.blocked_ips[client_ip] = now
            logger.warning(
                f"Temporarily blocked IP {client_ip} due to suspicious activity"
            )

        # Log security event
        await log_security_event(
            event_type=AuditEventType.SECURITY_VIOLATION,
            description=f"Security threat detected: {threat_type}",
            user_id=None,
            ip_address=client_ip,
            severity=AuditSeverity.HIGH,
            context={
                "threat_type": threat_type,
                "suspicious_requests": len(self.suspicious_activity[client_ip]),
            },
        )

    def _add_security_headers(self, response: Response):
        env = False
        """Add security headers to response"""
        for header, value in self.config.SECURITY_HEADERS.items():
            response.headers[header] = value
        if  env:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    async def _create_blocked_response(self, message: str) -> JSONResponse:
        """Create response for blocked requests"""
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Access Denied",
                "message": message,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    async def _create_error_response(
        self, message: str, status_code: int
    ) -> JSONResponse:
        """Create error response"""
        return JSONResponse(
            status_code=status_code,
            content={
                "error": "Security Error",
                "message": message,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF protection middleware"""

    def __init__(self, app, secret_key: str, safe_methods: Optional[Set[str]] = None):
        super().__init__(app)
        self.secret_key = secret_key
        self.safe_methods = safe_methods or {"GET", "HEAD", "OPTIONS", "TRACE"}

    async def dispatch(self, request: Request, call_next):
        """CSRF protection dispatch"""
        # Skip CSRF for safe methods
        if request.method in self.safe_methods:
            return await call_next(request)

        # Skip for API endpoints with proper authentication
        if self._is_api_request(request):
            return await call_next(request)

        # Validate CSRF token
        if not await self._validate_csrf_token(request):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "CSRF token missing or invalid"},
            )

        return await call_next(request)

    def _is_api_request(self, request: Request) -> bool:
        """Check if request is API request with proper auth"""
        # Check for Authorization header (API requests)
        if request.headers.get("authorization"):
            return True

        # Check for API path prefix
        if request.url.path.startswith("/api/"):
            return True

        return False

    async def _validate_csrf_token(self, request: Request) -> bool:
        """Validate CSRF token"""
        # Get token from header or form data
        csrf_token = request.headers.get("x-csrf-token")

        if not csrf_token:
            # Try to get from form data
            try:
                form_data = await request.form()
                csrf_token = form_data.get("csrf_token")
            except:
                pass

        if not csrf_token:
            return False

        # Validate token (implement proper CSRF token validation)
        return self._verify_csrf_token(csrf_token, request)

    def _verify_csrf_token(self, token: str, request: Request) -> bool:
        """Verify CSRF token (placeholder implementation)"""
        # In production, implement proper CSRF token verification
        # This would typically involve:
        # 1. Extracting session ID or user ID
        # 2. Generating expected token based on session + secret
        # 3. Comparing with provided token
        return True  # Placeholder


class IPWhitelistMiddleware(BaseHTTPMiddleware):
    """IP whitelist middleware for admin endpoints"""

    def __init__(self, app, whitelist: List[str], protected_paths: List[str]):
        super().__init__(app)
        self.whitelist = set(whitelist)
        self.protected_paths = protected_paths

    async def dispatch(self, request: Request, call_next):
        """IP whitelist dispatch"""
        # Check if path is protected
        if not any(request.url.path.startswith(path) for path in self.protected_paths):
            return await call_next(request)

        # Get client IP
        client_ip = self._get_client_ip(request)

        # Check if IP is whitelisted
        if not self._is_ip_whitelisted(client_ip):
            await log_security_event(
                event_type=AuditEventType.SECURITY_VIOLATION,
                description=f"Access attempt from non-whitelisted IP: {client_ip}",
                user_id=None,
                ip_address=client_ip,
                severity=AuditSeverity.HIGH,
            )

            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "Access Denied",
                    "message": "IP address not authorized",
                },
            )

        return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    def _is_ip_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist"""
        if ip in self.whitelist:
            return True

        # Check for CIDR ranges
        try:
            ip_obj = ipaddress.ip_address(ip)
            for whitelist_entry in self.whitelist:
                if "/" in whitelist_entry:
                    # CIDR range
                    network = ipaddress.ip_network(whitelist_entry, strict=False)
                    if ip_obj in network:
                        return True
        except ValueError:
            pass

        return False


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Request validation and sanitization middleware"""

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        """Request validation dispatch"""
        # Skip validation for OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Validate JSON requests
        if request.headers.get("content-type", "").startswith("application/json"):
            if not await self._validate_json_request(request):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Invalid JSON request"},
                )

        return await call_next(request)

    async def _validate_json_request(self, request: Request) -> bool:
        """Validate JSON request structure"""
        try:
            if hasattr(request, "_body"):
                body = request._body
                if body:
                    data = json.loads(body.decode("utf-8"))
                    return self._validate_json_depth(data)
            return True
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def _validate_json_depth(self, obj, depth: int = 0) -> bool:
        """Validate JSON depth to prevent DoS attacks"""
        if depth > 100:  # Max depth
            return False

        if isinstance(obj, dict):
            for value in obj.values():
                if not self._validate_json_depth(value, depth + 1):
                    return False
        elif isinstance(obj, list):
            for item in obj:
                if not self._validate_json_depth(item, depth + 1):
                    return False

        return True
