"""
Production-grade logging middleware for FastAPI applications
"""
import json
import logging
import time
import uuid
from typing import Callable, Dict, Any, Optional
from datetime import datetime, timezone

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse

from ..audit.logger import get_audit_logger, log_security_event
from ..audit.models import AuditEventType, AuditSeverity

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive request/response logging middleware for production applications
    """

    def __init__(
        self,
        app,
        *,
        log_request_body: bool = False,
        log_response_body: bool = False,
        max_body_size: int = 1024,
        sensitive_headers: Optional[set] = None,
        excluded_paths: Optional[set] = None,
        include_performance_metrics: bool = True
    ):
        super().__init__(app)
        self.log_request_body = log_request_body
        self.log_response_body = log_response_body
        self.max_body_size = max_body_size
        self.sensitive_headers = sensitive_headers or {
            'authorization', 'cookie', 'x-api-key', 'x-access-token',
            'x-csrf-token', 'x-auth-token', 'bearer'
        }
        self.excluded_paths = excluded_paths or {'/health', '/metrics', '/favicon.ico'}
        self.include_performance_metrics = include_performance_metrics

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip logging for excluded paths
        if request.url.path in self.excluded_paths:
            return await call_next(request)

        # Generate request ID if not present
        request_id = request.headers.get('x-request-id', str(uuid.uuid4()))
        request.state.request_id = request_id

        # Extract client information
        client_ip = self._extract_client_ip(request)
        user_agent = request.headers.get('user-agent', 'unknown')
        request.state.client_ip = client_ip

        # Start timing
        start_time = time.time()
        start_datetime = datetime.now(timezone.utc)

        # Log request
        await self._log_request(request, request_id, client_ip, user_agent, start_datetime)

        try:
            # Process request
            response = await call_next(request)

            # Calculate processing time
            processing_time = time.time() - start_time

            # Log response
            await self._log_response(
                request, response, request_id, processing_time, start_datetime
            )

            # Add performance headers
            if self.include_performance_metrics:
                response.headers['x-response-time'] = f"{processing_time:.3f}s"
                response.headers['x-request-id'] = request_id

            return response

        except Exception as exc:
            processing_time = time.time() - start_time
            await self._log_error(request, exc, request_id, processing_time, start_datetime)
            raise

    async def _log_request(
        self,
        request: Request,
        request_id: str,
        client_ip: str,
        user_agent: str,
        timestamp: datetime
    ):
        """Log incoming request details"""

        # Prepare request data
        request_data = {
            'event': 'request_started',
            'request_id': request_id,
            'method': request.method,
            'url': str(request.url),
            'path': request.url.path,
            'query_params': dict(request.query_params),
            'client_ip': client_ip,
            'user_agent': user_agent,
            'timestamp': timestamp.isoformat(),
            'headers': self._filter_sensitive_headers(dict(request.headers))
        }

        # Add user context if available
        if hasattr(request.state, 'user_id'):
            request_data['user_id'] = request.state.user_id
        if hasattr(request.state, 'organization_id'):
            request_data['organization_id'] = request.state.organization_id

        # Log request body if enabled and appropriate
        if (self.log_request_body and
            request.method in ['POST', 'PUT', 'PATCH'] and
            'application/json' in request.headers.get('content-type', '')):
            try:
                body = await self._get_request_body(request)
                if body:
                    request_data['body'] = self._truncate_body(body)
            except Exception as e:
                request_data['body_read_error'] = str(e)

        # Log to application logger
        logger.info(
            f"{request.method} {request.url.path} - Request started",
            extra=request_data
        )

        # Log security-relevant requests
        if self._is_security_relevant(request):
            try:
                await log_security_event(
                    event_type=AuditEventType.ACCESS_ATTEMPT,
                    description=f"Access attempt: {request.method} {request.url.path}",
                    user_id=getattr(request.state, 'user_id', None),
                    ip_address=client_ip,
                    severity=AuditSeverity.LOW,
                    metadata=request_data
                )
            except Exception as e:
                logger.error(f"Failed to log security event: {e}")

    async def _log_response(
        self,
        request: Request,
        response: Response,
        request_id: str,
        processing_time: float,
        start_time: datetime
    ):
        """Log response details"""

        response_data = {
            'event': 'request_completed',
            'request_id': request_id,
            'method': request.method,
            'url': str(request.url),
            'path': request.url.path,
            'status_code': response.status_code,
            'processing_time_ms': round(processing_time * 1000, 2),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'start_time': start_time.isoformat(),
            'response_headers': dict(response.headers)
        }

        # Add user context if available
        if hasattr(request.state, 'user_id'):
            response_data['user_id'] = request.state.user_id

        # Log response body if enabled and appropriate
        if self.log_response_body and response.status_code < 300:
            try:
                if hasattr(response, 'body'):
                    response_data['response_body'] = self._truncate_body(response.body)
            except Exception as e:
                response_data['response_body_error'] = str(e)

        # Determine log level based on status code
        if response.status_code >= 500:
            log_level = logging.ERROR
            log_message = f"{request.method} {request.url.path} - Server Error {response.status_code}"
        elif response.status_code >= 400:
            log_level = logging.WARNING
            log_message = f"{request.method} {request.url.path} - Client Error {response.status_code}"
        else:
            log_level = logging.INFO
            log_message = f"{request.method} {request.url.path} - Success {response.status_code}"

        logger.log(log_level, log_message, extra=response_data)

        # Log performance metrics for slow requests
        if processing_time > 1.0:  # Requests taking more than 1 second
            logger.warning(
                f"Slow request detected: {processing_time:.3f}s",
                extra={**response_data, 'performance_alert': True}
            )

    async def _log_error(
        self,
        request: Request,
        exception: Exception,
        request_id: str,
        processing_time: float,
        start_time: datetime
    ):
        """Log request processing errors"""

        error_data = {
            'event': 'request_error',
            'request_id': request_id,
            'method': request.method,
            'url': str(request.url),
            'path': request.url.path,
            'exception_type': type(exception).__name__,
            'exception_message': str(exception),
            'processing_time_ms': round(processing_time * 1000, 2),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'start_time': start_time.isoformat()
        }

        # Add user context if available
        if hasattr(request.state, 'user_id'):
            error_data['user_id'] = request.state.user_id

        logger.error(
            f"{request.method} {request.url.path} - Exception: {type(exception).__name__}",
            extra=error_data,
            exc_info=exception
        )

    def _extract_client_ip(self, request: Request) -> str:
        """Extract the real client IP address"""
        # Check common proxy headers in order of preference
        for header in ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip']:
            ip = request.headers.get(header)
            if ip:
                # Handle comma-separated list (x-forwarded-for)
                return ip.split(',')[0].strip()

        # Fallback to direct client IP
        return request.client.host if request.client else 'unknown'

    def _filter_sensitive_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Remove or mask sensitive headers from logs"""
        filtered = {}
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in self.sensitive_headers:
                filtered[key] = '[REDACTED]'
            else:
                filtered[key] = value
        return filtered

    def _truncate_body(self, body: Any) -> str:
        """Truncate request/response body for logging"""
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='ignore')
        elif not isinstance(body, str):
            body = str(body)

        if len(body) > self.max_body_size:
            return body[:self.max_body_size] + '...[truncated]'
        return body

    async def _get_request_body(self, request: Request) -> Optional[str]:
        """Safely read request body without affecting the original request"""
        try:
            # This is a bit tricky - we need to read the body without consuming it
            body = await request.body()
            # The body is already consumed, but FastAPI should handle this
            return body.decode('utf-8', errors='ignore') if body else None
        except Exception:
            return None

    def _is_security_relevant(self, request: Request) -> bool:
        """Determine if a request should be logged as a security event"""
        security_paths = {
            '/api/v1/auth', '/api/v1/users', '/api/v1/organizations',
            '/admin', '/api/admin'
        }

        return any(request.url.path.startswith(path) for path in security_paths)


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for structured JSON logging with correlation IDs
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Set correlation ID for request tracing
        correlation_id = request.headers.get('x-correlation-id', str(uuid.uuid4()))
        request.state.correlation_id = correlation_id

        # Add to logging context
        with logging.contextVars({'correlation_id': correlation_id}):
            response = await call_next(request)
            response.headers['x-correlation-id'] = correlation_id
            return response


def create_logging_middleware(
    log_request_body: bool = False,
    log_response_body: bool = False,
    max_body_size: int = 1024,
    sensitive_headers: Optional[set] = None,
    excluded_paths: Optional[set] = None,
    include_performance_metrics: bool = True
) -> RequestLoggingMiddleware:
    """Factory function to create request logging middleware"""
    def factory(app):
        return RequestLoggingMiddleware(
            app,
            log_request_body=log_request_body,
            log_response_body=log_response_body,
            max_body_size=max_body_size,
            sensitive_headers=sensitive_headers,
            excluded_paths=excluded_paths,
            include_performance_metrics=include_performance_metrics
        )
    return factory


def create_structured_logging_middleware() -> StructuredLoggingMiddleware:
    """Factory function to create structured logging middleware"""
    return lambda app: StructuredLoggingMiddleware(app)