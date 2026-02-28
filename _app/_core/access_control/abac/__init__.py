"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
ABAC (Attribute-Based Access Control) Module

This module provides a complete ABAC system specifically designed for Corely's
multi-tenant retail chain operations, integrating policy engine, decorators,
and default policies into a unified access control system.

Components:
- Policy Engine: High-performance policy evaluation with caching
- Default Policies: Comprehensive retail-specific access policies
- Decorators: FastAPI integration with performance optimization
- Management Tools: Policy administration and monitoring utilities
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import weakref

# Import all ABAC components
from .policy_engine import (
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
    ensure_abac_indexes,
)

from .default_policies import (
    get_default_policies,
    get_policies_by_module,
    get_policies_by_role,
    validate_policy_consistency,
    load_default_policies_to_engine,
)

from .decorators import (
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
)


logger = logging.getLogger(__name__)


class ABACModule:
    """Centralized ABAC module coordinator for Corely"""

    def __init__(self):
        self._initialized = False
        self._policy_engine: Optional[PolicyEngine] = None

        # Component registry for lifecycle management
        self._components: weakref.WeakSet = weakref.WeakSet()

        # Performance metrics
        self._initialization_time: Optional[datetime] = None
        self._policies_loaded: int = 0

    async def initialize(self) -> None:
        """Initialize the complete ABAC system"""
        if self._initialized:
            return

        logger.info("Initializing Corely ABAC Module...")
        start_time = datetime.now(timezone.utc)

        try:
            # Initialize policy engine
            self._policy_engine = await get_policy_engine()
            self._components.add(self._policy_engine)

            # Ensure database indexes
            await ensure_abac_indexes()

            # Load default policies
            self._policies_loaded = await load_default_policies_to_engine(
                self._policy_engine
            )

            # Validate policy consistency
            validation_result = validate_policy_consistency()
            if not validation_result["valid"]:
                logger.warning("Policy consistency issues found:")
                for issue in validation_result["issues"]:
                    logger.warning(f"  - {issue}")

            # Test policy engine with a basic evaluation
            await self._test_policy_engine()

            self._initialization_time = start_time
            self._initialized = True

            logger.info(
                f"ABAC Module initialized successfully - "
                f"{self._policies_loaded} policies loaded, "
                f"validation: {'✓' if validation_result['valid'] else '✗ with issues'}"
            )

        except Exception as e:
            logger.error(f"ABAC Module initialization failed: {str(e)}")
            await self.shutdown()
            raise

    async def shutdown(self) -> None:
        """Shutdown the ABAC system"""
        if not self._initialized:
            return

        logger.info("Shutting down ABAC Module...")

        try:
            # Shutdown policy engine
            if self._policy_engine:
                await self._policy_engine.shutdown()

            # Clear component references
            self._components.clear()

            self._initialized = False
            logger.info("ABAC Module shutdown completed")

        except Exception as e:
            logger.error(f"ABAC Module shutdown error: {str(e)}")

    async def _test_policy_engine(self) -> None:
        """Test policy engine with basic evaluation"""
        try:
            # Test with a simple super admin scenario
            test_context = {
                "subject": {
                    "user_id": "test_user",
                    "role": "SUPER_ADMIN",
                    "role_level": 100,
                    "tenant_id": "test_tenant",
                },
                "resource": {"type": "test_resource", "tenant_id": "test_tenant"},
                "action": {"type": "read"},
                "environment": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "is_business_hours": True,
                },
            }

            result = await evaluate_access(
                subject=test_context["subject"],
                resource=test_context["resource"],
                action=test_context["action"],
                environment=test_context["environment"],
                tenant_id="test_tenant",
            )

            if not result["permitted"]:
                logger.warning("Policy engine test failed - super admin denied access")
            else:
                logger.debug(
                    f"Policy engine test passed ({result['evaluation_time_ms']:.2f}ms)"
                )

        except Exception as e:
            logger.error(f"Policy engine test failed: {str(e)}")
            raise

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive ABAC system status"""
        status = {
            "initialized": self._initialized,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if self._initialized:
            status.update(
                {
                    "initialization_time": self._initialization_time.isoformat(),
                    "policies_loaded": self._policies_loaded,
                    "policy_engine_metrics": (
                        self._policy_engine.get_metrics() if self._policy_engine else {}
                    ),
                    "components": {
                        "policy_engine": self._policy_engine is not None,
                        "default_policies": self._policies_loaded > 0,
                    },
                }
            )

        return status

    @property
    def is_initialized(self) -> bool:
        """Check if ABAC module is initialized"""
        return self._initialized

    @property
    def policy_engine(self) -> Optional[PolicyEngine]:
        """Get the policy engine instance"""
        return self._policy_engine


# Global ABAC module instance
_abac_module: Optional[ABACModule] = None


async def get_abac_module() -> ABACModule:
    """Get global ABAC module instance"""
    global _abac_module
    if _abac_module is None:
        _abac_module = ABACModule()
        await _abac_module.initialize()
    return _abac_module


async def initialize_abac() -> None:
    """Initialize ABAC module - convenience function"""
    await get_abac_module()


async def shutdown_abac() -> None:
    """Shutdown ABAC module - convenience function"""
    global _abac_module
    if _abac_module:
        await _abac_module.shutdown()
        _abac_module = None


async def get_abac_status() -> Dict[str, Any]:
    """Get ABAC system status - convenience function"""
    try:
        abac_module = await get_abac_module()
        return abac_module.get_system_status()
    except Exception as e:
        return {
            "initialized": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Policy management utilities
async def add_custom_policy(policy: Policy) -> bool:
    """Add a custom policy to the system"""
    try:
        abac_module = await get_abac_module()
        if abac_module.policy_engine:
            await abac_module.policy_engine.add_policy(policy)
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to add custom policy: {str(e)}")
        return False


async def remove_policy(policy_id: str) -> bool:
    """Remove a policy from the system"""
    try:
        abac_module = await get_abac_module()
        if abac_module.policy_engine:
            return await abac_module.policy_engine.remove_policy(policy_id)
        return False
    except Exception as e:
        logger.error(f"Failed to remove policy: {str(e)}")
        return False


async def evaluate_policy_request(
    subject: Dict[str, Any],
    resource: Dict[str, Any],
    action: Dict[str, Any],
    environment: Dict[str, Any],
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate a policy request - convenience function"""
    return await evaluate_access(
        subject=subject,
        resource=resource,
        action=action,
        environment=environment,
        tenant_id=tenant_id,
    )


async def get_policies_for_role(role: str) -> List[Policy]:
    """Get all policies that apply to a specific role"""
    try:
        return get_policies_by_role(role)
    except Exception as e:
        logger.error(f"Failed to get policies for role {role}: {str(e)}")
        return []


async def get_policies_for_module(module: str) -> List[Policy]:
    """Get all policies for a specific module"""
    try:
        return get_policies_by_module(module)
    except Exception as e:
        logger.error(f"Failed to get policies for module {module}: {str(e)}")
        return []


async def validate_system_policies() -> Dict[str, Any]:
    """Validate all system policies for consistency"""
    try:
        return validate_policy_consistency()
    except Exception as e:
        logger.error(f"Policy validation failed: {str(e)}")
        return {
            "valid": False,
            "issues": [f"Validation error: {str(e)}"],
            "total_policies": 0,
        }


# Performance and monitoring utilities
async def get_performance_metrics() -> Dict[str, Any]:
    """Get ABAC system performance metrics"""
    try:
        abac_module = await get_abac_module()
        if abac_module.policy_engine:
            return abac_module.policy_engine.get_metrics()
        return {}
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {str(e)}")
        return {"error": str(e)}


async def clear_policy_cache() -> bool:
    """Clear policy evaluation cache"""
    try:
        abac_module = await get_abac_module()
        if abac_module.policy_engine:
            await abac_module.policy_engine._invalidate_policy_cache()
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to clear policy cache: {str(e)}")
        return False


# Development and testing utilities
async def test_policy_scenario(
    policy: Policy, test_scenarios: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Test a policy against predefined scenarios"""
    try:
        abac_module = await get_abac_module()
        if abac_module.policy_engine:
            return await abac_module.policy_engine.test_policy_against_scenarios(
                policy, test_scenarios
            )
        return {"error": "Policy engine not available"}
    except Exception as e:
        logger.error(f"Policy scenario testing failed: {str(e)}")
        return {"error": str(e)}


async def validate_policy_structure(policy: Policy) -> Dict[str, Any]:
    """Validate policy structure and syntax"""
    try:
        abac_module = await get_abac_module()
        if abac_module.policy_engine:
            return await abac_module.policy_engine.validate_policy(policy)
        return {"valid": False, "issues": ["Policy engine not available"]}
    except Exception as e:
        logger.error(f"Policy validation failed: {str(e)}")
        return {"valid": False, "issues": [str(e)]}


# System administration utilities
async def reload_default_policies() -> Dict[str, Any]:
    """Reload all default policies"""
    try:
        abac_module = await get_abac_module()
        if abac_module.policy_engine:
            # Clear existing policies
            for policy_id in list(abac_module.policy_engine.policies.keys()):
                await abac_module.policy_engine.remove_policy(policy_id)

            # Reload defaults
            policies_loaded = await load_default_policies_to_engine(
                abac_module.policy_engine
            )

            return {
                "success": True,
                "policies_loaded": policies_loaded,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        return {"success": False, "error": "Policy engine not available"}

    except Exception as e:
        logger.error(f"Failed to reload default policies: {str(e)}")
        return {"success": False, "error": str(e)}


async def export_system_policies() -> Dict[str, Any]:
    """Export all system policies for backup"""
    try:
        abac_module = await get_abac_module()
        if abac_module.policy_engine:
            return {
                "success": True,
                "policies": abac_module.policy_engine.export_policies_to_json(),
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "total_policies": len(abac_module.policy_engine.policies),
            }

        return {"success": False, "error": "Policy engine not available"}

    except Exception as e:
        logger.error(f"Failed to export policies: {str(e)}")
        return {"success": False, "error": str(e)}


# Export all ABAC functionality
__all__ = [
    # Core Components
    "ABACModule",
    "get_abac_module",
    "initialize_abac",
    "shutdown_abac",
    "get_abac_status",
    # Policy Engine Components
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
    # Default Policies
    "get_default_policies",
    "get_policies_by_module",
    "get_policies_by_role",
    "validate_policy_consistency",
    "load_default_policies_to_engine",
    # FastAPI Decorators
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
    # Policy Management
    "add_custom_policy",
    "remove_policy",
    "evaluate_policy_request",
    "get_policies_for_role",
    "get_policies_for_module",
    "validate_system_policies",
    # Performance and Monitoring
    "get_performance_metrics",
    "clear_policy_cache",
    # Development and Testing
    "test_policy_scenario",
    "validate_policy_structure",
    # System Administration
    "reload_default_policies",
    "export_system_policies",
]
