"""
Audit decorators for automatic event logging
"""
import asyncio
import functools
import inspect
import logging
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable, Union
from fastapi import Request

from .models import AuditEventType, AuditSeverity
from .logger import get_audit_logger
from .events import get_event_manager

logger = logging.getLogger(__name__)


def audit_event(
    event_type: AuditEventType,
    description: Optional[str] = None,
    severity: AuditSeverity = AuditSeverity.MEDIUM,
    capture_args: bool = False,
    capture_result: bool = False,
    sensitive_params: Optional[List[str]] = None,
    tenant_param: Optional[str] = "tenant_id",
    user_param: Optional[str] = "user_id",
    request_param: Optional[str] = "request"
):
    """
    Decorator to automatically log audit events for function calls

    Args:
        event_type: Type of audit event
        description: Custom description (if None, uses function name)
        severity: Event severity level
        capture_args: Whether to capture function arguments
        capture_result: Whether to capture function result
        sensitive_params: List of parameter names to mask in logs
        tenant_param: Parameter name that contains tenant ID
        user_param: Parameter name that contains user ID
        request_param: Parameter name that contains FastAPI Request object
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await _execute_with_audit(
                func, args, kwargs, event_type, description, severity,
                capture_args, capture_result, sensitive_params,
                tenant_param, user_param, request_param, is_async=True
            )

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(_execute_with_audit(
                func, args, kwargs, event_type, description, severity,
                capture_args, capture_result, sensitive_params,
                tenant_param, user_param, request_param, is_async=False
            ))

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


async def _execute_with_audit(
    func: Callable,
    args: tuple,
    kwargs: dict,
    event_type: AuditEventType,
    description: Optional[str],
    severity: AuditSeverity,
    capture_args: bool,
    capture_result: bool,
    sensitive_params: Optional[List[str]],
    tenant_param: Optional[str],
    user_param: Optional[str],
    request_param: Optional[str],
    is_async: bool
) -> Any:
    """Execute function with audit logging"""

    start_time = datetime.utcnow()
    success = False
    result = None
    error = None

    try:
        # Extract audit context
        audit_context = _extract_audit_context(
            func, args, kwargs, tenant_param, user_param, request_param
        )

        # Execute function
        if is_async:
            result = await func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)

        success = True
        return result

    except Exception as e:
        error = e
        success = False
        raise

    finally:
        try:
            # Log the audit event
            await _log_function_audit(
                func, args, kwargs, result, error, success,
                event_type, description, severity, capture_args, capture_result,
                sensitive_params, audit_context, start_time
            )
        except Exception as audit_error:
            logger.error(f"Failed to log audit event: {audit_error}")


def _extract_audit_context(
    func: Callable,
    args: tuple,
    kwargs: dict,
    tenant_param: Optional[str],
    user_param: Optional[str],
    request_param: Optional[str]
) -> Dict[str, Any]:
    """Extract audit context from function parameters"""
    context = {}

    # Get function signature
    sig = inspect.signature(func)
    param_names = list(sig.parameters.keys())

    # Create args + kwargs dict
    all_params = {}
    for i, arg in enumerate(args):
        if i < len(param_names):
            all_params[param_names[i]] = arg
    all_params.update(kwargs)

    # Extract tenant ID
    if tenant_param and tenant_param in all_params:
        context["tenant_id"] = all_params[tenant_param]

    # Extract user ID
    if user_param and user_param in all_params:
        context["user_id"] = all_params[user_param]

    # Extract request info
    if request_param and request_param in all_params:
        request = all_params[request_param]
        if hasattr(request, 'client'):
            context["ip_address"] = request.client.host
        if hasattr(request, 'headers'):
            context["user_agent"] = request.headers.get("user-agent")
            context["request_id"] = request.headers.get("x-request-id")

    return context


async def _log_function_audit(
    func: Callable,
    args: tuple,
    kwargs: dict,
    result: Any,
    error: Optional[Exception],
    success: bool,
    event_type: AuditEventType,
    description: Optional[str],
    severity: AuditSeverity,
    capture_args: bool,
    capture_result: bool,
    sensitive_params: Optional[List[str]],
    audit_context: Dict[str, Any],
    start_time: datetime
):
    """Log the audit event for function execution"""

    try:
        audit_logger = await get_audit_logger()

        # Build actor information
        actor = {
            "type": "user" if audit_context.get("user_id") else "system",
            "id": audit_context.get("user_id", "system"),
            "tenant_id": audit_context.get("tenant_id")
        }

        # Build target information
        target = {
            "type": "function",
            "id": f"{func.__module__}.{func.__name__}",
            "name": func.__name__
        }

        # Build action information
        action = {
            "type": "function_call",
            "description": description or f"Called function {func.__name__}",
            "function": func.__name__,
            "module": func.__module__
        }

        # Add arguments if requested
        if capture_args:
            sig = inspect.signature(func)
            param_names = list(sig.parameters.keys())

            # Create masked args
            masked_args = []
            for i, arg in enumerate(args):
                param_name = param_names[i] if i < len(param_names) else f"arg_{i}"
                if sensitive_params and param_name in sensitive_params:
                    masked_args.append("***MASKED***")
                else:
                    masked_args.append(str(arg)[:100])  # Limit length

            # Create masked kwargs
            masked_kwargs = {}
            for key, value in kwargs.items():
                if sensitive_params and key in sensitive_params:
                    masked_kwargs[key] = "***MASKED***"
                else:
                    masked_kwargs[key] = str(value)[:100]  # Limit length

            action["arguments"] = {
                "args": masked_args,
                "kwargs": masked_kwargs
            }

        # Build result information
        execution_time = (datetime.utcnow() - start_time).total_seconds()

        result_info = {
            "success": success,
            "execution_time_seconds": execution_time
        }

        if success and capture_result and result is not None:
            result_info["result"] = str(result)[:500]  # Limit length

        if error:
            result_info["error"] = {
                "type": type(error).__name__,
                "message": str(error),
                "traceback": traceback.format_exc() if logger.isEnabledFor(logging.DEBUG) else None
            }
            # Increase severity on errors
            if severity == AuditSeverity.LOW:
                severity = AuditSeverity.MEDIUM

        # Build context
        context = {
            "function_signature": str(inspect.signature(func)),
            "execution_context": "async" if asyncio.iscoroutinefunction(func) else "sync"
        }

        # Log the event
        await audit_logger.log_event(
            event_type=event_type,
            actor=actor,
            target=target,
            action=action,
            result=result_info,
            context=context,
            severity=severity,
            tenant_id=audit_context.get("tenant_id"),
            ip_address=audit_context.get("ip_address"),
            user_agent=audit_context.get("user_agent"),
            request_id=audit_context.get("request_id")
        )

    except Exception as e:
        logger.error(f"Error logging audit event for {func.__name__}: {e}")


def audit_data_access(
    operation: str,
    resource_type: str,
    sensitive: bool = False,
    tenant_param: Optional[str] = "tenant_id",
    user_param: Optional[str] = "user_id",
    request_param: Optional[str] = "request"
):
    """Decorator for data access operations (CRUD)"""

    # Map operations to audit event types
    operation_mapping = {
        "create": AuditEventType.CREATE,
        "read": AuditEventType.READ,
        "update": AuditEventType.UPDATE,
        "delete": AuditEventType.DELETE,
        "export": AuditEventType.EXPORT,
        "import": AuditEventType.IMPORT
    }

    event_type = operation_mapping.get(operation.lower(), AuditEventType.READ)
    severity = AuditSeverity.HIGH if sensitive else AuditSeverity.LOW

    return audit_event(
        event_type=event_type,
        description=f"{operation.title()} operation on {resource_type}",
        severity=severity,
        capture_args=True,
        capture_result=operation.lower() in ["create", "update"],
        sensitive_params=["password", "token", "key", "secret"] if sensitive else None,
        tenant_param=tenant_param,
        user_param=user_param,
        request_param=request_param
    )


def audit_auth_operation(
    operation_type: str = "authentication",
    capture_failure_details: bool = True
):
    """Decorator for authentication operations"""

    operation_mapping = {
        "login": AuditEventType.LOGIN_SUCCESS,
        "logout": AuditEventType.LOGOUT,
        "password_change": AuditEventType.PASSWORD_CHANGE,
        "token_refresh": AuditEventType.TOKEN_REFRESH
    }

    event_type = operation_mapping.get(operation_type.lower(), AuditEventType.LOGIN_SUCCESS)

    return audit_event(
        event_type=event_type,
        description=f"{operation_type.title()} operation",
        severity=AuditSeverity.MEDIUM,
        capture_args=capture_failure_details,
        capture_result=False,
        sensitive_params=["password", "token", "credentials"],
        tenant_param="tenant_id",
        user_param="user_id",
        request_param="request"
    )


def audit_admin_operation(
    description: Optional[str] = None,
    high_priority: bool = False
):
    """Decorator for administrative operations"""

    return audit_event(
        event_type=AuditEventType.CONFIGURATION_CHANGE,
        description=description,
        severity=AuditSeverity.HIGH if high_priority else AuditSeverity.MEDIUM,
        capture_args=True,
        capture_result=True,
        sensitive_params=["password", "token", "key", "secret"],
        tenant_param="tenant_id",
        user_param="user_id",
        request_param="request"
    )


class AuditContext:
    """Context manager for audit logging within a block of code"""

    def __init__(
        self,
        event_type: AuditEventType,
        description: str,
        actor: Dict[str, Any],
        target: Dict[str, Any],
        severity: AuditSeverity = AuditSeverity.MEDIUM,
        tenant_id: Optional[str] = None
    ):
        self.event_type = event_type
        self.description = description
        self.actor = actor
        self.target = target
        self.severity = severity
        self.tenant_id = tenant_id
        self.start_time = None
        self.success = False
        self.error = None

    async def __aenter__(self):
        self.start_time = datetime.utcnow()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.success = exc_type is None
        if exc_val:
            self.error = exc_val

        await self._log_event()

    async def _log_event(self):
        """Log the audit event"""
        try:
            audit_logger = await get_audit_logger()

            execution_time = (datetime.utcnow() - self.start_time).total_seconds()

            action = {
                "type": "code_block",
                "description": self.description
            }

            result = {
                "success": self.success,
                "execution_time_seconds": execution_time
            }

            if self.error:
                result["error"] = {
                    "type": type(self.error).__name__,
                    "message": str(self.error)
                }

            await audit_logger.log_event(
                event_type=self.event_type,
                actor=self.actor,
                target=self.target,
                action=action,
                result=result,
                severity=self.severity,
                tenant_id=self.tenant_id
            )

        except Exception as e:
            logger.error(f"Error logging audit context: {e}")


# Convenience functions for common audit patterns

async def audit_login_attempt(
    username: str,
    success: bool,
    ip_address: str,
    user_agent: str,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    error_message: Optional[str] = None
):
    """Log login attempt"""
    audit_logger = await get_audit_logger()
    event_type = AuditEventType.LOGIN_SUCCESS if success else AuditEventType.LOGIN_FAILED

    await audit_logger.log_authentication_event(
        event_type=event_type,
        user_id=user_id,
        username=username,
        success=success,
        ip_address=ip_address,
        user_agent=user_agent,
        tenant_id=tenant_id,
        error_message=error_message
    )


async def audit_permission_check(
    user_id: str,
    resource_type: str,
    resource_id: Optional[str],
    action: str,
    granted: bool,
    ip_address: str,
    tenant_id: Optional[str] = None,
    policy_decisions: Optional[List[Dict[str, Any]]] = None
):
    """Log permission check result"""
    audit_logger = await get_audit_logger()

    await audit_logger.log_authorization_event(
        user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        action_type=action,
        granted=granted,
        policy_decisions=policy_decisions or [],
        ip_address=ip_address,
        tenant_id=tenant_id
    )


async def audit_security_incident(
    incident_type: str,
    description: str,
    user_id: Optional[str],
    ip_address: str,
    severity: AuditSeverity = AuditSeverity.HIGH,
    tenant_id: Optional[str] = None,
    additional_context: Optional[Dict[str, Any]] = None
):
    """Log security incident"""
    audit_logger = await get_audit_logger()

    event_type_mapping = {
        "brute_force": AuditEventType.SUSPICIOUS_ACTIVITY,
        "data_breach": AuditEventType.DATA_BREACH_ATTEMPT,
        "rate_limit": AuditEventType.RATE_LIMIT_EXCEEDED,
        "security_violation": AuditEventType.SECURITY_VIOLATION
    }

    event_type = event_type_mapping.get(incident_type, AuditEventType.SECURITY_VIOLATION)

    await audit_logger.log_security_event(
        event_type=event_type,
        description=description,
        user_id=user_id,
        ip_address=ip_address,
        severity=severity,
        tenant_id=tenant_id,
        context=additional_context
    )