"""
Error handling middleware for production applications
"""
import logging
import traceback
from typing import Callable, Dict, Any
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..utils import BaseAppException, ValidationException, AuthenticationException, AuthorizationException
from ..audit import audit_security_incident, AuditSeverity

logger = logging.getLogger(__name__)


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Centralized error handling middleware
    """

    def __init__(self, app, include_stack_trace: bool = False):
        super().__init__(app)
        self.include_stack_trace = include_stack_trace
        self.error_handlers = {
            BaseAppException: self._handle_app_exception,
            ValidationException: self._handle_validation_exception,
            AuthenticationException: self._handle_auth_exception,
            AuthorizationException: self._handle_authz_exception,
            ValueError: self._handle_value_error,
            KeyError: self._handle_key_error,
            AttributeError: self._handle_attribute_error,
            Exception: self._handle_generic_exception
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            return await self._handle_exception(request, exc)

    async def _handle_exception(self, request: Request, exc: Exception) -> JSONResponse:
        """Handle exceptions and return appropriate JSON responses"""

        # Find the most specific handler
        handler = None
        for exc_type, exc_handler in self.error_handlers.items():
            if isinstance(exc, exc_type):
                handler = exc_handler
                break

        if handler is None:
            handler = self._handle_generic_exception

        error_response = await handler(request, exc)

        # Log the error
        await self._log_error(request, exc, error_response)

        return error_response

    async def _handle_app_exception(self, request: Request, exc: BaseAppException) -> JSONResponse:
        """Handle application-specific exceptions"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": {
                    "code": exc.error_code,
                    "message": exc.message,
                    "details": exc.details,
                    "type": type(exc).__name__
                },
                "request_id": self._get_request_id(request)
            }
        )

    async def _handle_validation_exception(self, request: Request, exc: ValidationException) -> JSONResponse:
        """Handle validation exceptions"""
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Validation failed",
                    "details": exc.details if hasattr(exc, 'details') else str(exc),
                    "type": "ValidationError"
                },
                "request_id": self._get_request_id(request)
            }
        )

    async def _handle_auth_exception(self, request: Request, exc: AuthenticationException) -> JSONResponse:
        """Handle authentication exceptions"""
        # Log security incident
        try:
            await audit_security_incident(
                incident_type="authentication_failure",
                description=f"Authentication failed: {str(exc)}",
                user_id=None,
                ip_address=self._get_client_ip(request),
                severity=AuditSeverity.MEDIUM
            )
        except Exception as audit_error:
            logger.error(f"Failed to log security incident: {audit_error}")

        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "success": False,
                "error": {
                    "code": "AUTHENTICATION_ERROR",
                    "message": "Authentication failed",
                    "type": "AuthenticationError"
                },
                "request_id": self._get_request_id(request)
            },
            headers={"WWW-Authenticate": "Bearer"}
        )

    async def _handle_authz_exception(self, request: Request, exc: AuthorizationException) -> JSONResponse:
        """Handle authorization exceptions"""
        # Log security incident
        try:
            await audit_security_incident(
                incident_type="authorization_failure",
                description=f"Authorization failed: {str(exc)}",
                user_id=getattr(request.state, 'user_id', None),
                ip_address=self._get_client_ip(request),
                severity=AuditSeverity.MEDIUM
            )
        except Exception as audit_error:
            logger.error(f"Failed to log security incident: {audit_error}")

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "success": False,
                "error": {
                    "code": "AUTHORIZATION_ERROR",
                    "message": "Access denied",
                    "type": "AuthorizationError"
                },
                "request_id": self._get_request_id(request)
            }
        )

    async def _handle_value_error(self, request: Request, exc: ValueError) -> JSONResponse:
        """Handle ValueError exceptions"""
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "error": {
                    "code": "INVALID_VALUE",
                    "message": "Invalid value provided",
                    "details": str(exc),
                    "type": "ValueError"
                },
                "request_id": self._get_request_id(request)
            }
        )

    async def _handle_key_error(self, request: Request, exc: KeyError) -> JSONResponse:
        """Handle KeyError exceptions"""
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "error": {
                    "code": "MISSING_FIELD",
                    "message": f"Required field missing: {str(exc)}",
                    "type": "KeyError"
                },
                "request_id": self._get_request_id(request)
            }
        )

    async def _handle_attribute_error(self, request: Request, exc: AttributeError) -> JSONResponse:
        """Handle AttributeError exceptions"""
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Internal server error",
                    "type": "AttributeError"
                },
                "request_id": self._get_request_id(request)
            }
        )

    async def _handle_generic_exception(self, request: Request, exc: Exception) -> JSONResponse:
        """Handle all other exceptions"""
        error_details = {
            "success": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "type": type(exc).__name__
            },
            "request_id": self._get_request_id(request)
        }

        # Include stack trace in development
        if self.include_stack_trace:
            error_details["error"]["traceback"] = traceback.format_exc()
            error_details["error"]["details"] = str(exc)

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_details
        )

    async def _log_error(self, request: Request, exc: Exception, response: JSONResponse):
        """Log error details"""
        log_context = {
            "method": request.method,
            "url": str(request.url),
            "client_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent", "unknown"),
            "request_id": self._get_request_id(request),
            "status_code": response.status_code,
            "exception_type": type(exc).__name__,
            "exception_message": str(exc)
        }

        if response.status_code >= 500:
            logger.error(f"Server error occurred", extra=log_context, exc_info=exc)
        elif response.status_code >= 400:
            logger.warning(f"Client error occurred", extra=log_context)
        else:
            logger.info(f"Error handled", extra=log_context)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _get_request_id(self, request: Request) -> str:
        """Extract request ID from request"""
        return getattr(request.state, 'request_id',
                      request.headers.get("x-request-id", "unknown"))


class ValidationErrorMiddleware(BaseHTTPMiddleware):
    """
    Middleware for handling validation errors from Pydantic models
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            # Handle Pydantic validation errors
            if hasattr(exc, 'errors') and callable(getattr(exc, 'errors')):
                return JSONResponse(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    content={
                        "success": False,
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Request validation failed",
                            "details": exc.errors(),
                            "type": "ValidationError"
                        },
                        "request_id": getattr(request.state, 'request_id', 'unknown')
                    }
                )
            raise exc


def create_error_handling_middleware(include_stack_trace: bool = False) -> ErrorHandlingMiddleware:
    """Factory function to create error handling middleware"""
    return lambda app: ErrorHandlingMiddleware(app, include_stack_trace=include_stack_trace)


def create_validation_error_middleware() -> ValidationErrorMiddleware:
    """Factory function to create validation error middleware"""
    return lambda app: ValidationErrorMiddleware(app)