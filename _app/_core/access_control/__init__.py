"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
Access Control Module

This module provides comprehensive access control for Corely's multi-tenant retail
operations, integrating ABAC policies with tenant isolation to create a complete
security framework.

Components:
- ABAC System: Attribute-based access control with retail-specific policies
- Tenant Isolation: Multi-tenant data isolation with performance optimization
- Integration Layer: Unified access control interface
- Monitoring Tools: Security monitoring and compliance reporting
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
import weakref

# Import ABAC components
from .abac import (
    # Core ABAC system
    ABACModule,
    get_abac_module,
    initialize_abac,
    shutdown_abac,
    get_abac_status,
    PolicyEngine,
    Policy,
    PolicyRule,
    PolicyCondition,
    Effect,
    PolicyDecision,
    AttributeType,
    ConditionOperator,
    get_policy_engine,
    evaluate_access,
    # Default policies
    get_default_policies,
    get_policies_by_module,
    get_policies_by_role,
    validate_policy_consistency,
    load_default_policies_to_engine,
    # FastAPI decorators
    require_permission,
    ABACEvaluationResult,
    require_read_permission,
    require_write_permission,
    require_delete_permission,
    require_admin_permission,
    require_store_access,
    require_warehouse_access,
    require_inventory_access,
    require_pos_access,
    require_customer_access,
    require_analytics_access,
    monitor_abac_performance,
    # Policy management
    add_custom_policy,
    remove_policy,
    evaluate_policy_request,
    get_policies_for_role,
    get_policies_for_module,
    validate_system_policies,
    get_performance_metrics,
    clear_policy_cache,
)

# Import tenant isolation components
from .tenant_isolation import (
    # Core tenant isolation
    TenantContext,
    TenantAwareDatabase,
    TenantAwareService,
    TenantDataFilter,
    get_tenant_context,
    get_tenant_database,
    # Enums and exceptions
    TenantAccessLevel,
    IsolationViolationType,
    TenantIsolationError,
    # Decorators
    require_tenant_isolation,
    # Utilities
    ensure_tenant_isolation_indexes,
    get_tenant_isolation_metrics,
    check_tenant_security_violations,
)


logger = logging.getLogger(__name__)


class AccessControlModule:
    """Unified access control system for Corely"""

    def __init__(self):
        self._initialized = False
        self._abac_module: Optional[ABACModule] = None
        self._tenant_database: Optional[TenantAwareDatabase] = None

        # Component registry
        self._components: weakref.WeakSet = weakref.WeakSet()

        # Performance metrics
        self._initialization_time: Optional[datetime] = None
        self._total_evaluations = 0
        self._security_violations = 0

    async def initialize(self) -> None:
        """Initialize the complete access control system"""
        if self._initialized:
            return

        logger.info("Initializing Corely Access Control Module...")
        start_time = datetime.now(timezone.utc)

        try:
            # Initialize ABAC system
            self._abac_module = await get_abac_module()
            self._components.add(self._abac_module)

            # Initialize tenant isolation system
            self._tenant_database = get_tenant_database()
            self._components.add(self._tenant_database)

            # Ensure database indexes for both systems
            await self._ensure_all_indexes()

            # Validate system integration
            await self._validate_system_integration()

            # Test end-to-end access control
            await self._test_access_control_integration()

            self._initialization_time = start_time
            self._initialized = True

            logger.info("Access Control Module initialized successfully")

        except Exception as e:
            logger.error(f"Access Control Module initialization failed: {str(e)}")
            await self.shutdown()
            raise

    async def shutdown(self) -> None:
        """Shutdown the access control system"""
        if not self._initialized:
            return

        logger.info("Shutting down Access Control Module...")

        try:
            # Shutdown ABAC module
            if self._abac_module:
                await shutdown_abac()

            # Clear component references
            self._components.clear()

            self._initialized = False
            logger.info("Access Control Module shutdown completed")

        except Exception as e:
            logger.error(f"Access Control Module shutdown error: {str(e)}")

    async def _ensure_all_indexes(self) -> None:
        """Ensure all access control related indexes"""
        logger.info("Ensuring access control database indexes...")

        index_tasks = [
            # ABAC indexes
            (
                self._abac_module.policy_engine.ensure_abac_indexes()
                if self._abac_module
                else asyncio.sleep(0)
            ),
            # Tenant isolation indexes
            ensure_tenant_isolation_indexes(),
        ]

        await asyncio.gather(*index_tasks, return_exceptions=True)
        logger.info("Access control indexes ensured")

    async def _validate_system_integration(self) -> None:
        """Validate integration between ABAC and tenant isolation"""
        logger.info("Validating access control system integration...")

        try:
            # Check ABAC system status
            abac_status = await get_abac_status()
            if not abac_status.get("initialized"):
                raise Exception("ABAC system not properly initialized")

            # Check policy consistency
            policy_validation = validate_system_policies()
            if not policy_validation["valid"]:
                logger.warning("Policy consistency issues detected:")
                for issue in policy_validation["issues"]:
                    logger.warning(f"  - {issue}")

            # Test tenant isolation
            tenant_metrics = await get_tenant_isolation_metrics()
            logger.debug(f"Tenant isolation metrics: {tenant_metrics}")

        except Exception as e:
            logger.error(f"System integration validation failed: {str(e)}")
            raise

    async def _test_access_control_integration(self) -> None:
        """Test end-to-end access control functionality"""
        logger.info("Testing access control integration...")

        try:
            # Test ABAC policy evaluation
            test_result = await evaluate_policy_request(
                subject={
                    "user_id": "test_user",
                    "role": "STORE_MANAGER",
                    "role_level": 70,
                    "tenant_id": "test_tenant",
                    "store_id": "test_store",
                },
                resource={
                    "type": "inventory",
                    "tenant_id": "test_tenant",
                    "store_id": "test_store",
                },
                action={"type": "read"},
                environment={
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "is_business_hours": True,
                },
                tenant_id="test_tenant",
            )

            if not test_result["permitted"]:
                logger.warning(
                    "Access control integration test failed - expected permission denied"
                )
            else:
                logger.debug("Access control integration test passed")

        except Exception as e:
            logger.error(f"Access control integration test failed: {str(e)}")
            # Don't raise - this is just a test

    async def evaluate_comprehensive_access(
        self,
        user_context: Dict[str, Any],
        resource_context: Dict[str, Any],
        action_context: Dict[str, Any],
        environment_context: Dict[str, Any],
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Comprehensive access evaluation combining ABAC and tenant isolation

        Args:
            user_context: User attributes and context
            resource_context: Resource attributes and context
            action_context: Action being performed
            environment_context: Environmental context
            tenant_id: Tenant ID for evaluation

        Returns:
            Comprehensive evaluation result
        """
        evaluation_start = datetime.now(timezone.utc)

        try:
            # ABAC policy evaluation
            abac_result = await evaluate_policy_request(
                subject=user_context,
                resource=resource_context,
                action=action_context,
                environment=environment_context,
                tenant_id=tenant_id,
            )

            # Tenant isolation validation
            tenant_validation = self._validate_tenant_access(
                user_context, resource_context, tenant_id
            )

            # Combine results
            final_decision = abac_result["permitted"] and tenant_validation["permitted"]

            evaluation_time = (
                datetime.now(timezone.utc) - evaluation_start
            ).total_seconds() * 1000

            self._total_evaluations += 1

            result = {
                "permitted": final_decision,
                "decision": "PERMIT" if final_decision else "DENY",
                "evaluation_time_ms": round(evaluation_time, 2),
                "abac_result": abac_result,
                "tenant_validation": tenant_validation,
                "timestamp": evaluation_start.isoformat(),
                "evaluation_id": f"eval_{self._total_evaluations}",
            }

            # Log evaluation for audit
            if not final_decision:
                await self._log_access_denial(
                    user_context, resource_context, action_context, result
                )

            return result

        except Exception as e:
            logger.error(f"Comprehensive access evaluation failed: {str(e)}")
            return {
                "permitted": False,
                "decision": "INDETERMINATE",
                "error": str(e),
                "timestamp": evaluation_start.isoformat(),
            }

    def _validate_tenant_access(
        self,
        user_context: Dict[str, Any],
        resource_context: Dict[str, Any],
        tenant_id: Optional[str],
    ) -> Dict[str, Any]:
        """Validate tenant-level access"""

        user_tenant = user_context.get("tenant_id")
        resource_tenant = resource_context.get("tenant_id")
        user_role_level = user_context.get("role_level", 0)

        # Super admin bypass
        if user_role_level >= 100:
            return {
                "permitted": True,
                "reason": "super_admin_access",
                "validation_type": "tenant_isolation",
            }

        # Same tenant access
        if user_tenant == resource_tenant:
            return {
                "permitted": True,
                "reason": "same_tenant_access",
                "validation_type": "tenant_isolation",
            }

        # Cross-tenant access denied
        return {
            "permitted": False,
            "reason": "cross_tenant_access_denied",
            "validation_type": "tenant_isolation",
            "user_tenant": user_tenant,
            "resource_tenant": resource_tenant,
        }

    async def _log_access_denial(
        self,
        user_context: Dict[str, Any],
        resource_context: Dict[str, Any],
        action_context: Dict[str, Any],
        evaluation_result: Dict[str, Any],
    ) -> None:
        """Log access denial for security monitoring"""
        try:
            self._security_violations += 1

            # This would integrate with the audit system
            logger.warning(
                f"Access denied for user {user_context.get('user_id')} "
                f"on {resource_context.get('type')} resource",
                extra={
                    "user_id": user_context.get("user_id"),
                    "tenant_id": user_context.get("tenant_id"),
                    "resource_type": resource_context.get("type"),
                    "action": action_context.get("type"),
                    "evaluation_result": evaluation_result,
                },
            )

        except Exception as e:
            logger.error(f"Failed to log access denial: {str(e)}")

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive access control system status"""
        status = {
            "initialized": self._initialized,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if self._initialized:
            try:
                # Get component statuses
                abac_status = (
                    self._abac_module.get_system_status() if self._abac_module else {}
                )
                tenant_metrics = asyncio.run(get_tenant_isolation_metrics())

                status.update(
                    {
                        "initialization_time": self._initialization_time.isoformat(),
                        "total_evaluations": self._total_evaluations,
                        "security_violations": self._security_violations,
                        "components": {
                            "abac_system": abac_status,
                            "tenant_isolation": tenant_metrics,
                        },
                        "performance": {
                            "violation_rate": (
                                (
                                    self._security_violations
                                    / max(1, self._total_evaluations)
                                )
                                * 100
                            ),
                            "components_active": len(self._components),
                        },
                    }
                )

            except Exception as e:
                status["error"] = f"Failed to get component status: {str(e)}"

        return status

    @property
    def is_initialized(self) -> bool:
        """Check if access control module is initialized"""
        return self._initialized


# Global access control module instance
_access_control_module: Optional[AccessControlModule] = None


async def get_access_control_module() -> AccessControlModule:
    """Get global access control module instance"""
    global _access_control_module
    if _access_control_module is None:
        _access_control_module = AccessControlModule()
        await _access_control_module.initialize()
    return _access_control_module


async def initialize_access_control() -> None:
    """Initialize access control module - convenience function"""
    await get_access_control_module()


async def shutdown_access_control() -> None:
    """Shutdown access control module - convenience function"""
    global _access_control_module
    if _access_control_module:
        await _access_control_module.shutdown()
        _access_control_module = None


async def get_access_control_status() -> Dict[str, Any]:
    """Get access control system status - convenience function"""
    try:
        access_control = await get_access_control_module()
        return access_control.get_system_status()
    except Exception as e:
        return {
            "initialized": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# High-level access control functions
async def evaluate_user_access(
    user_context: Dict[str, Any],
    resource_type: str,
    action: str,
    resource_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    store_id: Optional[str] = None,
    warehouse_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    High-level access evaluation function

    Args:
        user_context: User information and attributes
        resource_type: Type of resource being accessed
        action: Action being performed
        resource_id: Specific resource ID (optional)
        tenant_id: Tenant context
        store_id: Store context (optional)
        warehouse_id: Warehouse context (optional)

    Returns:
        Access evaluation result
    """
    try:
        access_control = await get_access_control_module()

        # Build resource context
        resource_context = {
            "type": resource_type,
            "tenant_id": tenant_id or user_context.get("tenant_id"),
        }

        if resource_id:
            resource_context["id"] = resource_id
        if store_id:
            resource_context["store_id"] = store_id
        if warehouse_id:
            resource_context["warehouse_id"] = warehouse_id

        # Build action context
        action_context = {"type": action}

        # Build environment context
        environment_context = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_business_hours": True,  # This could be calculated
        }

        return await access_control.evaluate_comprehensive_access(
            user_context=user_context,
            resource_context=resource_context,
            action_context=action_context,
            environment_context=environment_context,
            tenant_id=tenant_id,
        )

    except Exception as e:
        logger.error(f"User access evaluation failed: {str(e)}")
        return {"permitted": False, "decision": "INDETERMINATE", "error": str(e)}


# Security monitoring functions
async def get_security_summary(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Get security summary for monitoring dashboard"""
    try:
        access_control = await get_access_control_module()

        # Get overall status
        status = access_control.get_system_status()

        # Get recent violations if tenant specified
        violations = []
        if tenant_id:
            violations = await check_tenant_security_violations(tenant_id, hours=24)

        return {
            "system_status": status,
            "recent_violations": violations,
            "violation_count_24h": len(violations),
            "recommendations": _generate_security_recommendations(status, violations),
        }

    except Exception as e:
        logger.error(f"Failed to get security summary: {str(e)}")
        return {"error": str(e)}


def _generate_security_recommendations(
    status: Dict[str, Any], violations: List[Dict[str, Any]]
) -> List[str]:
    """Generate security recommendations based on system status"""
    recommendations = []

    if len(violations) > 5:
        recommendations.append(
            "High number of security violations detected. Review user permissions and access patterns."
        )

    performance = status.get("performance", {})
    violation_rate = performance.get("violation_rate", 0)

    if violation_rate > 5:
        recommendations.append(
            f"Security violation rate is {violation_rate:.1f}%. Consider reviewing access policies."
        )

    components = status.get("components", {})
    tenant_metrics = components.get("tenant_isolation", {})
    isolation_violations = tenant_metrics.get("isolation_violations", 0)

    if isolation_violations > 0:
        recommendations.append(
            f"Tenant isolation violations detected ({isolation_violations}). "
            "Review tenant access controls and user permissions."
        )

    if not recommendations:
        recommendations.append("Access control system is operating normally.")

    return recommendations


# System maintenance functions
async def perform_access_control_maintenance() -> Dict[str, Any]:
    """Perform comprehensive access control system maintenance"""
    try:
        results = {}

        # Clear policy cache
        cache_cleared = await clear_policy_cache()
        results["policy_cache_cleared"] = cache_cleared

        # Get performance metrics
        abac_metrics = await get_performance_metrics()
        tenant_metrics = await get_tenant_isolation_metrics()

        results["performance_metrics"] = {
            "abac": abac_metrics,
            "tenant_isolation": tenant_metrics,
        }

        # Validate policies
        policy_validation = await validate_system_policies()
        results["policy_validation"] = policy_validation

        results["maintenance_completed_at"] = datetime.now(timezone.utc).isoformat()

        return results

    except Exception as e:
        logger.error(f"Access control maintenance failed: {str(e)}")
        return {
            "error": str(e),
            "maintenance_completed_at": datetime.now(timezone.utc).isoformat(),
        }


# Export all access control functionality
__all__ = [
    # Core Module
    "AccessControlModule",
    "get_access_control_module",
    "initialize_access_control",
    "shutdown_access_control",
    "get_access_control_status",
    # ABAC System
    "ABACModule",
    "get_abac_module",
    "initialize_abac",
    "shutdown_abac",
    "get_abac_status",
    "PolicyEngine",
    "Policy",
    "PolicyRule",
    "PolicyCondition",
    "Effect",
    "PolicyDecision",
    "AttributeType",
    "ConditionOperator",
    "get_policy_engine",
    "evaluate_access",
    # ABAC Policies
    "get_default_policies",
    "get_policies_by_module",
    "get_policies_by_role",
    "validate_policy_consistency",
    "load_default_policies_to_engine",
    # ABAC Decorators
    "require_permission",
    "ABACEvaluationResult",
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
    "monitor_abac_performance",
    # ABAC Management
    "add_custom_policy",
    "remove_policy",
    "evaluate_policy_request",
    "get_policies_for_role",
    "get_policies_for_module",
    "validate_system_policies",
    "get_performance_metrics",
    "clear_policy_cache",
    # Tenant Isolation
    "TenantContext",
    "TenantAwareDatabase",
    "TenantAwareService",
    "TenantDataFilter",
    "get_tenant_context",
    "get_tenant_database",
    "TenantAccessLevel",
    "IsolationViolationType",
    "TenantIsolationError",
    "require_tenant_isolation",
    "ensure_tenant_isolation_indexes",
    "get_tenant_isolation_metrics",
    "check_tenant_security_violations",
    # High-level Functions
    "evaluate_user_access",
    "get_security_summary",
    "perform_access_control_maintenance",
]
