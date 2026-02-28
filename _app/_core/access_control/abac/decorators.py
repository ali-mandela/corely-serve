"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
Production-Optimized ABAC Decorators for FastAPI

This module provides high-performance ABAC decorators specifically designed for
Corely's FastAPI endpoints, integrating seamlessly with the authentication
system and policy engine.

Features:
- FastAPI native dependency injection
- Integration with AuthenticationContext
- High-performance policy evaluation with caching
- Retail-specific context extraction
- Comprehensive error handling and logging
- Real-time audit logging
- Store/warehouse context awareness
- Module-based access control
"""

import functools
import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable, List, Union
import time
from dataclasses import asdict

from fastapi import HTTPException, status, Request, Depends
from fastapi.security import HTTPAuthorizationCredentials

from .policy_engine import get_policy_engine, PolicyDecision
from app._core.auth.enhanced_auth import (
    get_current_user,
    get_optional_user,
    AuthenticationContext,
    log_authentication_event,
)
from app._core.auth.permissions import get_permission_manager
from app._core.utils.exceptions import AuthorizationException, ValidationException


logger = logging.getLogger(__name__)


class ABACEvaluationResult:
    """Result of ABAC policy evaluation with metadata"""

    def __init__(
        self,
        permitted: bool,
        decision: str,
        evaluation_time_ms: float,
        policy_results: List[Dict[str, Any]],
        context_hash: str,
        tenant_id: Optional[str] = None,
    ):
        self.permitted = permitted
        self.decision = decision
        self.evaluation_time_ms = evaluation_time_ms
        self.policy_results = policy_results
        self.context_hash = context_hash
        self.tenant_id = tenant_id
        self.timestamp = datetime.now(timezone.utc)


def require_permission(
    resource_type: str,
    action: str,
    resource_id_param: Optional[str] = None,
    store_context: bool = False,
    warehouse_context: bool = False,
    module_required: Optional[str] = None,
    custom_resource_extractor: Optional[Callable] = None,
    custom_subject_extractor: Optional[Callable] = None,
    require_mfa: bool = False,
    cache_duration: int = 60,  # seconds
    audit_action: bool = True,
):
    """
    Production-optimized ABAC decorator for FastAPI endpoints

    Args:
        resource_type: Type of resource being accessed (e.g., 'store', 'product', 'user')
        action: Action being performed (e.g., 'read', 'write', 'delete')
        resource_id_param: Name of path parameter containing resource ID
        store_context: Whether to validate store access context
        warehouse_context: Whether to validate warehouse access context
        module_required: Required module to be enabled (e.g., 'inventory', 'pos')
        custom_resource_extractor: Function to extract additional resource attributes
        custom_subject_extractor: Function to extract additional subject attributes
        require_mfa: Whether MFA verification is required
        cache_duration: Cache evaluation results for this many seconds
        audit_action: Whether to log the access attempt for audit
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract FastAPI dependencies
            request = kwargs.get("request")
            current_user = kwargs.get("current_user")

            # Validate required dependencies
            if not isinstance(request, Request):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found - ensure Request is injected",
                )

            if not isinstance(current_user, AuthenticationContext):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            evaluation_start = time.time()

            try:
                # Pre-flight checks
                await _perform_prelight_checks(
                    current_user, require_mfa, module_required
                )

                # Build evaluation context
                context = await _build_evaluation_context(
                    current_user=current_user,
                    request=request,
                    resource_type=resource_type,
                    action=action,
                    resource_id_param=resource_id_param,
                    kwargs=kwargs,
                    store_context=store_context,
                    warehouse_context=warehouse_context,
                    custom_resource_extractor=custom_resource_extractor,
                    custom_subject_extractor=custom_subject_extractor,
                )

                # Evaluate ABAC policies
                evaluation_result = await _evaluate_abac_policies(
                    context=context,
                    current_user=current_user,
                    cache_duration=cache_duration,
                )

                # Handle authorization decision
                if not evaluation_result.permitted:
                    await _handle_access_denied(
                        current_user=current_user,
                        evaluation_result=evaluation_result,
                        resource_type=resource_type,
                        action=action,
                        audit_action=audit_action,
                    )

                # Log successful access
                if audit_action:
                    await _log_successful_access(
                        current_user=current_user,
                        evaluation_result=evaluation_result,
                        resource_type=resource_type,
                        action=action,
                    )

                # Store evaluation result in request state for further processing
                if not hasattr(request.state, "abac_evaluations"):
                    request.state.abac_evaluations = []
                request.state.abac_evaluations.append(evaluation_result)

                # Execute the protected function
                return await func(*args, **kwargs)

            except HTTPException:
                # Re-raise HTTP exceptions as-is
                raise
            except Exception as e:
                logger.error(
                    f"ABAC decorator error: {str(e)}",
                    extra={
                        "user_id": current_user.user_id,
                        "tenant_id": current_user.tenant_id,
                        "resource_type": resource_type,
                        "action": action,
                        "error": str(e),
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Authorization system error",
                )

        return wrapper

    return decorator


async def _perform_prelight_checks(
    current_user: AuthenticationContext,
    require_mfa: bool,
    module_required: Optional[str],
) -> None:
    """Perform pre-flight security checks"""

    # MFA requirement check
    if require_mfa:
        # Check if user has recent MFA verification
        # This would integrate with the MFA system
        mfa_verified = getattr(current_user, "mfa_verified", False)
        if not mfa_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "multi_factor_authentication_required",
                    "message": "This operation requires multi-factor authentication",
                    "mfa_required": True,
                },
            )

    # Module access check
    if module_required and not current_user.can_access_module(module_required):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "module_access_denied",
                "message": f"Access to {module_required} module is not enabled",
                "required_module": module_required,
                "enabled_modules": list(current_user.enabled_modules),
            },
        )


async def _build_evaluation_context(
    current_user: AuthenticationContext,
    request: Request,
    resource_type: str,
    action: str,
    resource_id_param: Optional[str],
    kwargs: Dict[str, Any],
    store_context: bool,
    warehouse_context: bool,
    custom_resource_extractor: Optional[Callable],
    custom_subject_extractor: Optional[Callable],
) -> Dict[str, Any]:
    """Build comprehensive evaluation context for ABAC policies"""

    # Build subject attributes
    subject = {
        "user_id": current_user.user_id,
        "tenant_id": current_user.tenant_id,
        "email": current_user.email,
        "role": current_user.role,
        "role_level": current_user.role_level,
        "permissions": current_user.permissions,
        "enabled_modules": list(current_user.enabled_modules),
        "store_id": current_user.store_id,
        "warehouse_id": current_user.warehouse_id,
        "department_id": current_user.department_id,
        "is_authenticated": current_user.is_authenticated,
        "is_api_request": current_user.is_api_request,
        "auth_method": current_user.auth_method.value,
        "mfa_verified": getattr(current_user, "mfa_verified", False),
        "last_auth_time": current_user.authenticated_at.isoformat(),
        "session_id": current_user.session_id,
    }

    # Add custom subject attributes
    if custom_subject_extractor:
        try:
            custom_attrs = await custom_subject_extractor(current_user)
            if isinstance(custom_attrs, dict):
                subject.update(custom_attrs)
        except Exception as e:
            logger.warning(f"Error in custom subject extractor: {e}")

    # Build resource attributes
    resource = {
        "type": resource_type,
        "tenant_id": current_user.tenant_id,
        "module": _extract_module_from_resource_type(resource_type),
    }

    # Add resource ID if specified
    if resource_id_param and resource_id_param in kwargs:
        resource["id"] = kwargs[resource_id_param]
        resource["resource_id"] = kwargs[resource_id_param]

    # Add store context if required
    if store_context:
        store_id = kwargs.get("store_id") or current_user.store_id
        if store_id:
            resource["store_id"] = store_id
            resource["requires_store_access"] = True

    # Add warehouse context if required
    if warehouse_context:
        warehouse_id = kwargs.get("warehouse_id") or current_user.warehouse_id
        if warehouse_id:
            resource["warehouse_id"] = warehouse_id
            resource["requires_warehouse_access"] = True

    # Add all path parameters as potential resource attributes
    for key, value in kwargs.items():
        if key.endswith("_id") and key not in resource:
            resource[key] = value

    # Add query parameters
    if hasattr(request, "query_params"):
        query_params = dict(request.query_params)
        if query_params:
            resource["query_params"] = query_params

    # Add custom resource attributes
    if custom_resource_extractor:
        try:
            custom_attrs = await custom_resource_extractor(kwargs, request)
            if isinstance(custom_attrs, dict):
                resource.update(custom_attrs)
        except Exception as e:
            logger.warning(f"Error in custom resource extractor: {e}")

    # Build action attributes
    action_attrs = {
        "type": action,
        "method": request.method,
        "endpoint": str(request.url.path),
        "query_string": str(request.url.query) if request.url.query else "",
    }

    # Build environment attributes
    environment = await _build_environment_attributes(request)

    return {
        "subject": subject,
        "resource": resource,
        "action": action_attrs,
        "environment": environment,
    }


async def _build_environment_attributes(request: Request) -> Dict[str, Any]:
    """Build environment attributes from request context"""
    client_ip = _get_client_ip(request)

    environment = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "user_agent": request.headers.get("user-agent", ""),
        "method": request.method,
        "path": str(request.url.path),
        "query_string": str(request.url.query) if request.url.query else "",
        "host": request.headers.get("host", ""),
        "referer": request.headers.get("referer", ""),
        "is_secure": request.url.scheme == "https",
        "content_type": request.headers.get("content-type", ""),
        "accept": request.headers.get("accept", ""),
    }

    # Add time-based attributes
    now = datetime.now(timezone.utc)
    environment.update(
        {
            "hour": now.hour,
            "minute": now.minute,
            "day_of_week": now.weekday(),  # 0=Monday, 6=Sunday
            "weekday": now.weekday(),
            "is_weekend": now.weekday() >= 5,
            "is_business_hours": 9 <= now.hour <= 17,  # Basic business hours
            "date": now.date().isoformat(),
            "time": now.time().isoformat(),
        }
    )

    # Add request headers that might be relevant for security
    security_headers = [
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded-proto",
        "x-requested-with",
        "origin",
        "sec-fetch-site",
    ]

    for header in security_headers:
        value = request.headers.get(header)
        if value:
            environment[f"header_{header.replace('-', '_')}"] = value

    return environment


def _get_client_ip(request: Request) -> str:
    """Extract client IP address from request with proxy support"""
    # Check for forwarded headers (common in production behind proxy/load balancer)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP in the chain (original client)
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip

    # Check for other proxy headers
    cf_connecting_ip = request.headers.get("cf-connecting-ip")  # Cloudflare
    if cf_connecting_ip:
        return cf_connecting_ip

    # Fallback to direct client IP
    return getattr(request.client, "host", "unknown") if request.client else "unknown"


def _extract_module_from_resource_type(resource_type: str) -> Optional[str]:
    """Extract the module name from resource type"""
    # Map resource types to modules
    resource_module_map = {
        # Inventory module
        "product": "inventory",
        "inventory": "inventory",
        "stock": "inventory",
        "category": "inventory",
        "supplier": "inventory",
        # POS module
        "sale": "pos",
        "payment": "pos",
        "receipt": "pos",
        "cash_drawer": "pos",
        "return": "pos",
        "exchange": "pos",
        # Customer module
        "customer": "crm",
        "loyalty": "loyalty",
        # Warehouse module
        "warehouse": "warehouse",
        "shipment": "warehouse",
        "receiving": "warehouse",
        "picking": "warehouse",
        # HR module
        "employee": "hr",
        "schedule": "hr",
        "payroll": "hr",
        # Analytics module
        "report": "analytics",
        "dashboard": "analytics",
        "metric": "analytics",
        # Accounting module
        "financial_report": "accounting",
        "invoice": "accounting",
        "expense": "accounting",
        # Supply chain module
        "purchase_order": "supply_chain",
        "contract": "supply_chain",
        # System resources
        "user": "system",
        "store": "system",
        "tenant": "system",
        "system_setting": "system",
    }

    return resource_module_map.get(resource_type)


async def _evaluate_abac_policies(
    context: Dict[str, Any], current_user: AuthenticationContext, cache_duration: int
) -> ABACEvaluationResult:
    """Evaluate ABAC policies with caching and performance optimization"""

    try:
        policy_engine = await get_policy_engine()

        # Evaluate policies
        evaluation_result = await policy_engine.evaluate_request(
            subject=context["subject"],
            resource=context["resource"],
            action=context["action"],
            environment=context["environment"],
            tenant_id=current_user.tenant_id,
        )

        return ABACEvaluationResult(
            permitted=evaluation_result["permitted"],
            decision=evaluation_result["decision"],
            evaluation_time_ms=evaluation_result["evaluation_time_ms"],
            policy_results=evaluation_result["policy_results"],
            context_hash=evaluation_result["context_hash"],
            tenant_id=current_user.tenant_id,
        )

    except Exception as e:
        logger.error(f"ABAC policy evaluation failed: {e}")
        # Fail secure - deny access on evaluation error
        return ABACEvaluationResult(
            permitted=False,
            decision=PolicyDecision.INDETERMINATE.value,
            evaluation_time_ms=0,
            policy_results=[],
            context_hash="",
            tenant_id=current_user.tenant_id,
        )


async def _handle_access_denied(
    current_user: AuthenticationContext,
    evaluation_result: ABACEvaluationResult,
    resource_type: str,
    action: str,
    audit_action: bool,
) -> None:
    """Handle access denied scenarios with comprehensive logging"""

    # Log access denial
    if audit_action:
        await log_authentication_event(
            auth_context=current_user,
            event_type="authorization_denied",
            additional_data={
                "resource_type": resource_type,
                "action": action,
                "decision": evaluation_result.decision,
                "evaluation_time_ms": evaluation_result.evaluation_time_ms,
                "policy_results_count": len(evaluation_result.policy_results),
            },
        )

    # Determine appropriate error response based on decision
    if evaluation_result.decision == PolicyDecision.INDETERMINATE.value:
        detail = {
            "error": "authorization_system_error",
            "message": "Unable to evaluate access permissions",
        }
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    else:
        detail = {
            "error": "access_denied",
            "message": f"Access denied for {action} operation on {resource_type}",
            "resource_type": resource_type,
            "action": action,
            "evaluation_time_ms": evaluation_result.evaluation_time_ms,
        }
        status_code = status.HTTP_403_FORBIDDEN

        # Add helpful information for developers (only in development)
        if logger.isEnabledFor(logging.DEBUG):
            detail["debug_info"] = {
                "decision": evaluation_result.decision,
                "policies_evaluated": len(evaluation_result.policy_results),
                "context_hash": evaluation_result.context_hash,
            }

    raise HTTPException(status_code=status_code, detail=detail)


async def _log_successful_access(
    current_user: AuthenticationContext,
    evaluation_result: ABACEvaluationResult,
    resource_type: str,
    action: str,
) -> None:
    """Log successful access for audit purposes"""

    try:
        await log_authentication_event(
            auth_context=current_user,
            event_type="authorization_granted",
            additional_data={
                "resource_type": resource_type,
                "action": action,
                "decision": evaluation_result.decision,
                "evaluation_time_ms": evaluation_result.evaluation_time_ms,
                "policies_evaluated": len(evaluation_result.policy_results),
            },
        )
    except Exception as e:
        # Don't fail the request if audit logging fails
        logger.error(f"Failed to log successful access: {e}")


# Convenience decorators for common use cases
def require_read_permission(
    resource_type: str,
    resource_id_param: Optional[str] = None,
    module_required: Optional[str] = None,
    store_context: bool = False,
):
    """Require read permission for a resource"""
    return require_permission(
        resource_type=resource_type,
        action="read",
        resource_id_param=resource_id_param,
        module_required=module_required,
        store_context=store_context,
    )


def require_write_permission(
    resource_type: str,
    resource_id_param: Optional[str] = None,
    module_required: Optional[str] = None,
    store_context: bool = False,
    require_mfa: bool = False,
):
    """Require write permission for a resource"""
    return require_permission(
        resource_type=resource_type,
        action="write",
        resource_id_param=resource_id_param,
        module_required=module_required,
        store_context=store_context,
        require_mfa=require_mfa,
    )


def require_delete_permission(
    resource_type: str,
    resource_id_param: Optional[str] = None,
    module_required: Optional[str] = None,
    require_mfa: bool = True,  # Delete operations require MFA by default
):
    """Require delete permission for a resource"""
    return require_permission(
        resource_type=resource_type,
        action="delete",
        resource_id_param=resource_id_param,
        module_required=module_required,
        require_mfa=require_mfa,
    )


def require_admin_permission(
    resource_type: str = "system",
    require_mfa: bool = True,  # Admin operations require MFA by default
):
    """Require admin permission for system operations"""
    return require_permission(
        resource_type=resource_type, action="admin", require_mfa=require_mfa
    )


def require_store_access(
    resource_type: str,
    action: str,
    store_id_param: str = "store_id",
    module_required: Optional[str] = None,
):
    """Require access to a specific store"""
    return require_permission(
        resource_type=resource_type,
        action=action,
        resource_id_param=store_id_param,
        store_context=True,
        module_required=module_required,
    )


def require_warehouse_access(
    resource_type: str,
    action: str,
    warehouse_id_param: str = "warehouse_id",
    module_required: str = "warehouse",
):
    """Require access to a specific warehouse"""
    return require_permission(
        resource_type=resource_type,
        action=action,
        resource_id_param=warehouse_id_param,
        warehouse_context=True,
        module_required=module_required,
    )


def require_inventory_access(
    action: str = "read", store_context: bool = True, warehouse_context: bool = False
):
    """Require access to inventory resources"""
    return require_permission(
        resource_type="inventory",
        action=action,
        module_required="inventory",
        store_context=store_context,
        warehouse_context=warehouse_context,
    )


def require_pos_access(action: str = "execute", store_context: bool = True):
    """Require access to POS resources"""
    return require_permission(
        resource_type="pos",
        action=action,
        module_required="pos",
        store_context=store_context,
    )


def require_customer_access(
    action: str = "read", customer_id_param: str = "customer_id"
):
    """Require access to customer resources"""
    return require_permission(
        resource_type="customer",
        action=action,
        resource_id_param=customer_id_param,
        module_required="crm",
    )


def require_analytics_access(action: str = "read", resource_type: str = "report"):
    """Require access to analytics and reporting"""
    return require_permission(
        resource_type=resource_type, action=action, module_required="analytics"
    )


# Performance monitoring decorator
def monitor_abac_performance(func):
    """Decorator to monitor ABAC evaluation performance"""

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()

        try:
            result = await func(*args, **kwargs)

            # Log performance metrics
            execution_time = (time.time() - start_time) * 1000

            if execution_time > 100:  # Log slow evaluations
                logger.warning(
                    f"Slow ABAC evaluation in {func.__name__}: {execution_time:.2f}ms",
                    extra={
                        "function": func.__name__,
                        "execution_time_ms": execution_time,
                    },
                )

            return result

        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            logger.error(
                f"ABAC evaluation error in {func.__name__}: {str(e)} "
                f"(after {execution_time:.2f}ms)",
                extra={
                    "function": func.__name__,
                    "execution_time_ms": execution_time,
                    "error": str(e),
                },
            )
            raise

    return wrapper


# Export all decorators and utilities
__all__ = [
    # Core decorator
    "require_permission",
    # Convenience decorators
    "require_read_permission",
    "require_write_permission",
    "require_delete_permission",
    "require_admin_permission",
    "require_store_access",
    "require_warehouse_access",
    "require_inventory_access",
    "require_pos_access",
    "require_customer_access",
    "require_analytics_access",
    # Utilities
    "monitor_abac_performance",
    "ABACEvaluationResult",
]
