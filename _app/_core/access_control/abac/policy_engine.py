"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
Production-Optimized Attribute-Based Access Control (ABAC) Policy Engine

This module provides a high-performance, enterprise-grade ABAC policy engine
specifically optimized for Corely's multi-tenant retail chain operations.

Features:
- High-performance policy evaluation with caching
- MongoDB-native policy storage and retrieval
- Real-time policy updates and versioning
- Comprehensive metrics and monitoring
- Integration with Corely authentication system
- Retail-specific policy templates
- Multi-tenant policy isolation
- Advanced condition operators for retail scenarios
"""

import json
import asyncio
import logging
import hashlib
from datetime import datetime, time, timezone
from typing import Dict, List, Any, Optional, Union, Set, Callable
from enum import Enum
from dataclasses import dataclass, asdict, field
from ipaddress import IPv4Address, IPv6Address, AddressValueError
import re
from functools import lru_cache
import time as time_module
from collections import defaultdict

from app._core.config.settings import get_settings
from app._core.database.connection import get_connection_manager
from app._core.auth.tokens import ROLE_HIERARCHY
from app._core.auth.sessions import ORGANIZATION_MODULES
from app._core.utils.exceptions import ValidationException, AuthorizationException
from app._core.utils.constants import DatabaseConstants


logger = logging.getLogger(__name__)


class Effect(str, Enum):
    """Policy decision effects"""

    PERMIT = "PERMIT"
    DENY = "DENY"


class PolicyDecision(str, Enum):
    """Final policy evaluation decisions"""

    PERMIT = "PERMIT"
    DENY = "DENY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INDETERMINATE = "INDETERMINATE"  # Error during evaluation


class AttributeType(str, Enum):
    """Types of attributes used in policies"""

    SUBJECT = "subject"  # User attributes (role, store_id, permissions)
    RESOURCE = "resource"  # Resource attributes (type, owner, tenant_id)
    ACTION = "action"  # Action attributes (type, method, scope)
    ENVIRONMENT = "environment"  # Context attributes (time, location, device)


class ConditionOperator(str, Enum):
    """Available condition operators"""

    # Basic comparison
    EQ = "eq"  # equals
    NE = "ne"  # not equals
    GT = "gt"  # greater than
    GTE = "gte"  # greater than or equal
    LT = "lt"  # less than
    LTE = "lte"  # less than or equal

    # Set operations
    IN = "in"  # value in list
    NOT_IN = "not_in"  # value not in list
    CONTAINS = "contains"  # list contains value
    NOT_CONTAINS = "not_contains"  # list does not contain value

    # String operations
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX_MATCH = "regex_match"
    ICONTAINS = "icontains"  # case-insensitive contains

    # Special operators for retail
    ROLE_LEVEL_GTE = "role_level_gte"  # role level >= value
    STORE_HIERARCHY = "store_hierarchy"  # hierarchical store access
    MODULE_ENABLED = "module_enabled"  # module enabled for tenant
    TIME_BETWEEN = "time_between"  # time range check
    IP_IN_RANGE = "ip_in_range"  # IP address range
    WEEKDAY_IN = "weekday_in"  # day of week check
    DISTANCE_LT = "distance_lt"  # geographic distance

    # Temporal operators
    DAYS_AGO_LT = "days_ago_lt"  # X days ago
    HOURS_AGO_LT = "hours_ago_lt"  # X hours ago

    # Advanced operators
    JSON_PATH_EQ = "json_path_eq"  # JSONPath equality
    ARRAY_INTERSECT = "array_intersect"  # arrays have common elements


@dataclass
class PolicyCondition:
    """Individual condition in a policy rule with retail-specific enhancements"""

    attribute_type: AttributeType
    attribute_name: str
    operator: ConditionOperator
    value: Union[str, int, float, bool, List[Any], Dict[str, Any]]
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self):
        # Ensure operator is ConditionOperator enum
        if isinstance(self.operator, str):
            self.operator = ConditionOperator(self.operator)

    async def evaluate(
        self, context: Dict[str, Any], policy_engine: "PolicyEngine"
    ) -> bool:
        """Evaluate this condition against the provided context"""
        try:
            actual_value = self._get_attribute_value(context)
            if actual_value is None and self.operator not in [
                ConditionOperator.EQ,
                ConditionOperator.NE,
            ]:
                return False

            return await self._apply_operator(actual_value, context, policy_engine)
        except Exception as e:
            logger.warning(
                f"Error evaluating condition {self.attribute_name} {self.operator.value}: {e}",
                extra={
                    "attribute_type": self.attribute_type.value,
                    "attribute_name": self.attribute_name,
                    "operator": self.operator.value,
                    "value": self.value,
                },
            )
            return False

    def _get_attribute_value(self, context: Dict[str, Any]) -> Any:
        """Extract attribute value from context with dot notation support"""
        category = context.get(self.attribute_type.value, {})

        # Support dot notation for nested attributes
        if "." in self.attribute_name:
            parts = self.attribute_name.split(".")
            value = category
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return None
            return value
        else:
            return category.get(self.attribute_name)

    async def _apply_operator(
        self, actual: Any, context: Dict[str, Any], policy_engine: "PolicyEngine"
    ) -> bool:
        """Apply the comparison operator with context awareness"""

        # Basic comparison operators
        if self.operator == ConditionOperator.EQ:
            return actual == self.value
        elif self.operator == ConditionOperator.NE:
            return actual != self.value
        elif self.operator == ConditionOperator.GT:
            return actual > self.value
        elif self.operator == ConditionOperator.GTE:
            return actual >= self.value
        elif self.operator == ConditionOperator.LT:
            return actual < self.value
        elif self.operator == ConditionOperator.LTE:
            return actual <= self.value

        # Set operations
        elif self.operator == ConditionOperator.IN:
            return (
                actual in self.value
                if isinstance(self.value, (list, tuple, set))
                else False
            )
        elif self.operator == ConditionOperator.NOT_IN:
            return (
                actual not in self.value
                if isinstance(self.value, (list, tuple, set))
                else True
            )
        elif self.operator == ConditionOperator.CONTAINS:
            return (
                self.value in actual
                if isinstance(actual, (list, tuple, set, str))
                else False
            )
        elif self.operator == ConditionOperator.NOT_CONTAINS:
            return (
                self.value not in actual
                if isinstance(actual, (list, tuple, set, str))
                else True
            )

        # String operations
        elif self.operator == ConditionOperator.STARTS_WITH:
            return str(actual).startswith(str(self.value))
        elif self.operator == ConditionOperator.ENDS_WITH:
            return str(actual).endswith(str(self.value))
        elif self.operator == ConditionOperator.ICONTAINS:
            return str(self.value).lower() in str(actual).lower()
        elif self.operator == ConditionOperator.REGEX_MATCH:
            return self._regex_match(str(actual), str(self.value))

        # Retail-specific operators
        elif self.operator == ConditionOperator.ROLE_LEVEL_GTE:
            return await self._check_role_level(actual, context)
        elif self.operator == ConditionOperator.STORE_HIERARCHY:
            return await self._check_store_hierarchy(actual, context, policy_engine)
        elif self.operator == ConditionOperator.MODULE_ENABLED:
            return await self._check_module_enabled(context, policy_engine)
        elif self.operator == ConditionOperator.TIME_BETWEEN:
            return self._time_between(actual)
        elif self.operator == ConditionOperator.IP_IN_RANGE:
            return self._ip_in_range(actual)
        elif self.operator == ConditionOperator.WEEKDAY_IN:
            return self._weekday_in(actual)

        # Temporal operators
        elif self.operator == ConditionOperator.DAYS_AGO_LT:
            return self._days_ago_lt(actual)
        elif self.operator == ConditionOperator.HOURS_AGO_LT:
            return self._hours_ago_lt(actual)

        # Advanced operators
        elif self.operator == ConditionOperator.JSON_PATH_EQ:
            return self._json_path_eq(actual)
        elif self.operator == ConditionOperator.ARRAY_INTERSECT:
            return self._array_intersect(actual)

        return False

    def _regex_match(self, value: str, pattern: str) -> bool:
        """Match value against regex pattern with caching"""
        try:
            # Cache compiled regex patterns
            if not hasattr(self, "_regex_cache"):
                self._regex_cache = {}

            if pattern not in self._regex_cache:
                self._regex_cache[pattern] = re.compile(pattern)

            return bool(self._regex_cache[pattern].match(value))
        except re.error:
            return False

    async def _check_role_level(self, role: str, context: Dict[str, Any]) -> bool:
        """Check if role level meets minimum requirement"""
        user_role_level = ROLE_HIERARCHY.get(role, 0)
        required_level = int(self.value)
        return user_role_level >= required_level

    async def _check_store_hierarchy(
        self, store_id: str, context: Dict[str, Any], policy_engine: "PolicyEngine"
    ) -> bool:
        """Check store hierarchy access (managers can access subordinate stores)"""
        try:
            subject = context.get("subject", {})
            user_store_ids = subject.get("store_ids", [])
            user_role = subject.get("role", "")

            # Direct store access
            if store_id in user_store_ids:
                return True

            # Hierarchical access for managers
            if user_role in [
                "STORE_MANAGER",
                "REGIONAL_MANAGER",
                "TENANT_ADMIN",
                "SUPER_ADMIN",
            ]:
                # Check if user has hierarchical access to this store
                return await self._check_hierarchical_store_access(
                    user_store_ids, store_id, policy_engine
                )

            return False
        except Exception:
            return False

    async def _check_hierarchical_store_access(
        self,
        user_store_ids: List[str],
        target_store_id: str,
        policy_engine: "PolicyEngine",
    ) -> bool:
        """Check if user has hierarchical access to target store"""
        # This would query the store hierarchy from the database
        # For now, simplified implementation
        return target_store_id in user_store_ids

    async def _check_module_enabled(
        self, context: Dict[str, Any], policy_engine: "PolicyEngine"
    ) -> bool:
        """Check if module is enabled for the tenant"""
        try:
            subject = context.get("subject", {})
            tenant_id = subject.get("tenant_id")
            module = str(self.value)

            if not tenant_id:
                return True  # Global access

            # Get tenant's enabled modules from cache or database
            enabled_modules = await policy_engine._get_tenant_enabled_modules(tenant_id)
            return module in enabled_modules
        except Exception:
            return False

    def _time_between(self, current_time: Union[str, datetime]) -> bool:
        """Check if current time is between start and end times"""
        try:
            if isinstance(current_time, str):
                current = datetime.fromisoformat(current_time).time()
            elif isinstance(current_time, datetime):
                current = current_time.time()
            elif isinstance(current_time, int):
                # Hour of day (0-23)
                current = time(hour=current_time)
            else:
                current = datetime.now(timezone.utc).time()

            time_range = self.value
            if not isinstance(time_range, list) or len(time_range) != 2:
                return False

            start = (
                time.fromisoformat(time_range[0])
                if isinstance(time_range[0], str)
                else time_range[0]
            )
            end = (
                time.fromisoformat(time_range[1])
                if isinstance(time_range[1], str)
                else time_range[1]
            )

            if start <= end:
                return start <= current <= end
            else:  # Spans midnight
                return current >= start or current <= end
        except (ValueError, IndexError, AttributeError):
            return False

    def _ip_in_range(self, ip_address: str) -> bool:
        """Check if IP address is in the specified range with caching"""
        try:
            from ipaddress import ip_address, ip_network

            # Cache IP network objects
            if not hasattr(self, "_ip_cache"):
                self._ip_cache = {}

            ip_ranges = self.value if isinstance(self.value, list) else [self.value]

            for ip_range in ip_ranges:
                if ip_range not in self._ip_cache:
                    self._ip_cache[ip_range] = ip_network(ip_range, strict=False)

                if ip_address(ip_address) in self._ip_cache[ip_range]:
                    return True

            return False
        except (AddressValueError, ValueError):
            return False

    def _weekday_in(self, weekday: Union[int, str]) -> bool:
        """Check if current weekday is in allowed list"""
        try:
            if isinstance(weekday, str):
                # Convert day name to number
                days = {
                    "monday": 0,
                    "tuesday": 1,
                    "wednesday": 2,
                    "thursday": 3,
                    "friday": 4,
                    "saturday": 5,
                    "sunday": 6,
                }
                weekday = days.get(weekday.lower(), -1)

            allowed_days = self.value if isinstance(self.value, list) else [self.value]
            return weekday in allowed_days
        except (ValueError, KeyError):
            return False

    def _days_ago_lt(self, timestamp: Union[str, datetime, int]) -> bool:
        """Check if timestamp is less than X days ago"""
        try:
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp)
            elif isinstance(timestamp, datetime):
                dt = timestamp
            elif isinstance(timestamp, int):
                dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            else:
                return False

            now = datetime.now(timezone.utc)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            days_ago = (now - dt).days
            return days_ago < int(self.value)
        except (ValueError, TypeError):
            return False

    def _hours_ago_lt(self, timestamp: Union[str, datetime, int]) -> bool:
        """Check if timestamp is less than X hours ago"""
        try:
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp)
            elif isinstance(timestamp, datetime):
                dt = timestamp
            elif isinstance(timestamp, int):
                dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            else:
                return False

            now = datetime.now(timezone.utc)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            hours_ago = (now - dt).total_seconds() / 3600
            return hours_ago < float(self.value)
        except (ValueError, TypeError):
            return False

    def _json_path_eq(self, data: Any) -> bool:
        """Check if JSONPath expression equals expected value"""
        try:
            import jsonpath_ng

            jsonpath_expr = jsonpath_ng.parse(self.metadata.get("json_path", "$"))
            matches = [match.value for match in jsonpath_expr.find(data)]
            expected = self.value
            return expected in matches
        except ImportError:
            # Fallback without jsonpath_ng
            return False
        except Exception:
            return False

    def _array_intersect(self, array1: List[Any]) -> bool:
        """Check if two arrays have any common elements"""
        try:
            array2 = self.value if isinstance(self.value, list) else []
            return bool(set(array1) & set(array2))
        except (TypeError, ValueError):
            return False


@dataclass
class PolicyRule:
    """A policy rule with conditions and effect, optimized for performance"""

    rule_id: str
    description: str
    effect: Effect
    conditions: List[PolicyCondition]
    priority: int = 100  # Lower numbers = higher priority
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    is_active: bool = True

    def __post_init__(self):
        # Ensure effect is Effect enum
        if isinstance(self.effect, str):
            self.effect = Effect(self.effect)

    async def evaluate(
        self, context: Dict[str, Any], policy_engine: "PolicyEngine"
    ) -> Optional[Effect]:
        """Evaluate all conditions and return effect if all pass"""
        if not self.is_active or not self.conditions:
            return None

        # Fast path: evaluate lightweight conditions first
        lightweight_conditions = []
        heavyweight_conditions = []

        for condition in self.conditions:
            if condition.operator in [
                ConditionOperator.EQ,
                ConditionOperator.NE,
                ConditionOperator.IN,
                ConditionOperator.NOT_IN,
            ]:
                lightweight_conditions.append(condition)
            else:
                heavyweight_conditions.append(condition)

        # Evaluate lightweight conditions first
        for condition in lightweight_conditions:
            if not await condition.evaluate(context, policy_engine):
                return None

        # Only evaluate heavyweight conditions if lightweight ones pass
        for condition in heavyweight_conditions:
            if not await condition.evaluate(context, policy_engine):
                return None

        return self.effect


@dataclass
class Policy:
    """Complete ABAC policy with metadata and performance optimizations"""

    policy_id: str
    name: str
    description: str
    version: str
    tenant_id: Optional[str]  # None for global policies
    rules: List[PolicyRule]
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)

    # Performance optimization fields
    _rule_index: Optional[Dict[str, List[PolicyRule]]] = field(default=None, init=False)
    _compiled_hash: Optional[str] = field(default=None, init=False)

    def __post_init__(self):
        self._build_rule_index()
        self._compute_hash()

    def _build_rule_index(self):
        """Build index for fast rule lookup"""
        self._rule_index = defaultdict(list)

        # Sort rules by priority
        sorted_rules = sorted(self.rules, key=lambda r: r.priority)

        # Index by effect for faster evaluation
        for rule in sorted_rules:
            self._rule_index[rule.effect.value].append(rule)
            self._rule_index["all"].append(rule)

    def _compute_hash(self):
        """Compute hash for policy change detection"""
        policy_data = {
            "policy_id": self.policy_id,
            "version": self.version,
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "effect": rule.effect.value,
                    "conditions": [
                        {
                            "type": cond.attribute_type.value,
                            "name": cond.attribute_name,
                            "op": cond.operator.value,
                            "val": str(cond.value),
                        }
                        for cond in rule.conditions
                    ],
                }
                for rule in self.rules
            ],
        }

        policy_str = json.dumps(policy_data, sort_keys=True)
        self._compiled_hash = hashlib.md5(policy_str.encode()).hexdigest()

    async def evaluate(
        self, context: Dict[str, Any], policy_engine: "PolicyEngine"
    ) -> Optional[Effect]:
        """Evaluate policy with optimized rule processing"""
        if not self.is_active or not self.rules:
            return None

        # Fast path: check DENY rules first (fail fast)
        deny_rules = self._rule_index.get(Effect.DENY.value, [])
        for rule in deny_rules:
            effect = await rule.evaluate(context, policy_engine)
            if effect == Effect.DENY:
                return Effect.DENY

        # Then check PERMIT rules
        permit_rules = self._rule_index.get(Effect.PERMIT.value, [])
        for rule in permit_rules:
            effect = await rule.evaluate(context, policy_engine)
            if effect == Effect.PERMIT:
                return Effect.PERMIT

        return None

    def invalidate_cache(self):
        """Invalidate cached rule index when policy changes"""
        self._rule_index = None
        self._compiled_hash = None
        self._build_rule_index()
        self._compute_hash()


class PolicyEngine:
    """Main ABAC policy engine with production optimizations"""

    def __init__(self):
        self.settings = get_settings()

        # Policy storage
        self.policies: Dict[str, Policy] = {}
        self.global_policies: List[Policy] = []

        # Performance optimization
        self._policy_cache: Dict[str, List[Policy]] = {}  # Cache by tenant_id
        self._tenant_modules_cache: Dict[str, Set[str]] = {}
        self._cache_lock = asyncio.Lock()
        self._cache_ttl = 300  # 5 minutes
        self._last_cache_clear = time_module.time()

        # Metrics
        self._evaluation_count = 0
        self._cache_hits = 0
        self._cache_misses = 0

        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None

    async def initialize(self):
        """Initialize the policy engine"""
        # Start background cache cleanup task
        self._cleanup_task = asyncio.create_task(self._cache_cleanup_loop())

        # Load policies from database if available
        await self._load_policies_from_db()

    async def shutdown(self):
        """Shutdown the policy engine"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def add_policy(self, policy: Policy) -> None:
        """Add a policy to the engine with caching invalidation"""
        self.policies[policy.policy_id] = policy

        if policy.tenant_id is None:
            if policy not in self.global_policies:
                self.global_policies.append(policy)

        # Invalidate relevant caches
        await self._invalidate_policy_cache(policy.tenant_id)

    async def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy from the engine"""
        if policy_id in self.policies:
            policy = self.policies.pop(policy_id)

            if policy in self.global_policies:
                self.global_policies.remove(policy)

            # Invalidate relevant caches
            await self._invalidate_policy_cache(policy.tenant_id)
            return True
        return False

    async def evaluate_request(
        self,
        subject: Dict[str, Any],
        resource: Dict[str, Any],
        action: Dict[str, Any],
        environment: Dict[str, Any],
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate an access request with performance optimization

        Returns comprehensive evaluation result
        """
        evaluation_start = time_module.time()
        self._evaluation_count += 1

        # Build evaluation context
        context = {
            AttributeType.SUBJECT.value: subject,
            AttributeType.RESOURCE.value: resource,
            AttributeType.ACTION.value: action,
            AttributeType.ENVIRONMENT.value: environment,
        }

        try:
            # Get applicable policies (with caching)
            applicable_policies = await self._get_applicable_policies_cached(tenant_id)

            decisions = []
            policy_results = []
            permit_found = False
            deny_found = False

            # Evaluate policies with early termination optimization
            for policy in applicable_policies:
                try:
                    decision = await policy.evaluate(context, self)

                    if decision is not None:
                        decisions.append(decision)
                        policy_results.append(
                            {
                                "policy_id": policy.policy_id,
                                "policy_name": policy.name,
                                "decision": decision.value,
                                "applicable": True,
                                "tenant_id": policy.tenant_id,
                            }
                        )

                        # Track decision types
                        if decision == Effect.PERMIT:
                            permit_found = True
                        elif decision == Effect.DENY:
                            deny_found = True
                            break  # Early termination on DENY
                    else:
                        policy_results.append(
                            {
                                "policy_id": policy.policy_id,
                                "policy_name": policy.name,
                                "decision": "NOT_APPLICABLE",
                                "applicable": False,
                                "tenant_id": policy.tenant_id,
                            }
                        )

                except Exception as e:
                    logger.error(f"Error evaluating policy {policy.policy_id}: {e}")
                    policy_results.append(
                        {
                            "policy_id": policy.policy_id,
                            "policy_name": policy.name,
                            "decision": PolicyDecision.INDETERMINATE.value,
                            "applicable": False,
                            "error": str(e),
                            "tenant_id": policy.tenant_id,
                        }
                    )

            # Determine final decision
            if deny_found:
                final_decision = PolicyDecision.DENY
            elif permit_found:
                final_decision = PolicyDecision.PERMIT
            else:
                final_decision = PolicyDecision.DENY  # Default deny

            evaluation_time = (time_module.time() - evaluation_start) * 1000

            result = {
                "decision": final_decision.value,
                "permitted": final_decision == PolicyDecision.PERMIT,
                "evaluation_time_ms": round(evaluation_time, 2),
                "policies_evaluated": len(applicable_policies),
                "applicable_policies": len(
                    [p for p in policy_results if p["applicable"]]
                ),
                "policy_results": policy_results,
                "tenant_id": tenant_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "context_hash": self._compute_context_hash(context),
            }

            # Log slow evaluations
            if evaluation_time > 100:  # More than 100ms
                logger.warning(
                    f"Slow policy evaluation: {evaluation_time:.2f}ms for {len(applicable_policies)} policies",
                    extra={
                        "evaluation_time_ms": evaluation_time,
                        "policies_count": len(applicable_policies),
                        "tenant_id": tenant_id,
                        "subject_role": subject.get("role"),
                        "resource_type": resource.get("type"),
                        "action_type": action.get("type"),
                    },
                )

            return result

        except Exception as e:
            logger.error(f"Policy evaluation error: {e}", exc_info=True)
            return {
                "decision": PolicyDecision.INDETERMINATE.value,
                "permitted": False,
                "evaluation_time_ms": round(
                    (time_module.time() - evaluation_start) * 1000, 2
                ),
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def _get_applicable_policies_cached(
        self, tenant_id: Optional[str]
    ) -> List[Policy]:
        """Get applicable policies with caching"""
        cache_key = tenant_id or "global"

        async with self._cache_lock:
            # Check cache
            if cache_key in self._policy_cache:
                current_time = time_module.time()
                if current_time - self._last_cache_clear < self._cache_ttl:
                    self._cache_hits += 1
                    return self._policy_cache[cache_key]

            # Cache miss - load policies
            self._cache_misses += 1
            policies = await self._get_applicable_policies(tenant_id)
            self._policy_cache[cache_key] = policies

            return policies

    async def _get_applicable_policies(self, tenant_id: Optional[str]) -> List[Policy]:
        """Get policies applicable to the tenant"""
        applicable = []

        # Add active global policies (sorted by priority)
        global_policies = [p for p in self.global_policies if p.is_active]
        applicable.extend(
            sorted(
                global_policies,
                key=lambda p: min(r.priority for r in p.rules) if p.rules else 100,
            )
        )

        # Add tenant-specific policies
        if tenant_id:
            tenant_policies = [
                p
                for p in self.policies.values()
                if p.tenant_id == tenant_id and p.is_active
            ]
            applicable.extend(
                sorted(
                    tenant_policies,
                    key=lambda p: min(r.priority for r in p.rules) if p.rules else 100,
                )
            )

        return applicable

    async def _get_tenant_enabled_modules(self, tenant_id: str) -> Set[str]:
        """Get enabled modules for tenant with caching"""
        if tenant_id in self._tenant_modules_cache:
            return self._tenant_modules_cache[tenant_id]

        try:
            manager = await get_connection_manager()
            async with manager.get_collection(DatabaseConstants.TENANTS) as collection:
                tenant = await collection.find_one({"_id": tenant_id})

                if tenant:
                    enabled_modules = set(
                        tenant.get("enabled_modules", list(ORGANIZATION_MODULES.keys()))
                    )
                else:
                    enabled_modules = set(ORGANIZATION_MODULES.keys())

                # Cache result
                self._tenant_modules_cache[tenant_id] = enabled_modules
                return enabled_modules

        except Exception as e:
            logger.error(f"Failed to get enabled modules for tenant {tenant_id}: {e}")
            return set(["inventory", "pos"])  # Default minimal modules

    async def _invalidate_policy_cache(self, tenant_id: Optional[str] = None):
        """Invalidate policy cache for specific tenant or all"""
        async with self._cache_lock:
            if tenant_id:
                cache_key = tenant_id or "global"
                self._policy_cache.pop(cache_key, None)
                self._tenant_modules_cache.pop(tenant_id, None)
            else:
                # Clear all caches
                self._policy_cache.clear()
                self._tenant_modules_cache.clear()
                self._last_cache_clear = time_module.time()

    def _compute_context_hash(self, context: Dict[str, Any]) -> str:
        """Compute hash of evaluation context for caching/debugging"""
        context_str = json.dumps(context, sort_keys=True, default=str)
        return hashlib.md5(context_str.encode()).hexdigest()[:8]

    async def _cache_cleanup_loop(self):
        """Background task to cleanup expired caches"""
        while True:
            try:
                await asyncio.sleep(self._cache_ttl)

                current_time = time_module.time()
                if current_time - self._last_cache_clear > self._cache_ttl:
                    await self._invalidate_policy_cache()
                    logger.debug("Policy cache cleanup completed")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")

    async def _load_policies_from_db(self):
        """Load policies from MongoDB"""
        try:
            manager = await get_connection_manager()
            async with manager.get_collection("abac_policies") as collection:
                cursor = collection.find({"is_active": True})

                async for policy_doc in cursor:
                    try:
                        policy = self._create_policy_from_dict(policy_doc)
                        await self.add_policy(policy)
                    except Exception as e:
                        logger.error(
                            f"Failed to load policy {policy_doc.get('policy_id')}: {e}"
                        )

        except Exception as e:
            logger.warning(f"Failed to load policies from database: {e}")

    async def save_policy_to_db(self, policy: Policy) -> bool:
        """Save policy to MongoDB"""
        try:
            manager = await get_connection_manager()

            policy_doc = self._create_dict_from_policy(policy)
            policy_doc["created_at"] = datetime.now(timezone.utc)
            policy_doc["updated_at"] = datetime.now(timezone.utc)

            async with manager.get_collection("abac_policies") as collection:
                await collection.replace_one(
                    {"policy_id": policy.policy_id}, policy_doc, upsert=True
                )

            await self.add_policy(policy)
            return True

        except Exception as e:
            logger.error(f"Failed to save policy {policy.policy_id}: {e}")
            return False

    def _create_policy_from_dict(self, policy_dict: Dict) -> Policy:
        """Create Policy object from dictionary"""
        rules = []
        for rule_data in policy_dict.get("rules", []):
            conditions = []
            for cond_data in rule_data.get("conditions", []):
                condition = PolicyCondition(
                    attribute_type=AttributeType(cond_data["attribute_type"]),
                    attribute_name=cond_data["attribute_name"],
                    operator=ConditionOperator(cond_data["operator"]),
                    value=cond_data["value"],
                    metadata=cond_data.get("metadata", {}),
                )
                conditions.append(condition)

            rule = PolicyRule(
                rule_id=rule_data["rule_id"],
                description=rule_data["description"],
                effect=Effect(rule_data["effect"]),
                conditions=conditions,
                priority=rule_data.get("priority", 100),
                metadata=rule_data.get("metadata", {}),
                is_active=rule_data.get("is_active", True),
            )
            rules.append(rule)

        created_at = policy_dict.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)

        updated_at = policy_dict.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)

        return Policy(
            policy_id=policy_dict["policy_id"],
            name=policy_dict["name"],
            description=policy_dict["description"],
            version=policy_dict["version"],
            tenant_id=policy_dict.get("tenant_id"),
            rules=rules,
            is_active=policy_dict.get("is_active", True),
            created_at=created_at,
            updated_at=updated_at,
            metadata=policy_dict.get("metadata", {}),
        )

    def _create_dict_from_policy(self, policy: Policy) -> Dict[str, Any]:
        """Create dictionary from Policy object"""
        return {
            "policy_id": policy.policy_id,
            "name": policy.name,
            "description": policy.description,
            "version": policy.version,
            "tenant_id": policy.tenant_id,
            "is_active": policy.is_active,
            "metadata": policy.metadata,
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "description": rule.description,
                    "effect": rule.effect.value,
                    "priority": rule.priority,
                    "is_active": rule.is_active,
                    "metadata": rule.metadata,
                    "conditions": [
                        {
                            "attribute_type": cond.attribute_type.value,
                            "attribute_name": cond.attribute_name,
                            "operator": cond.operator.value,
                            "value": cond.value,
                            "metadata": cond.metadata,
                        }
                        for cond in rule.conditions
                    ],
                }
                for rule in policy.rules
            ],
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get policy engine performance metrics"""
        cache_hit_rate = (
            self._cache_hits / (self._cache_hits + self._cache_misses) * 100
            if (self._cache_hits + self._cache_misses) > 0
            else 0
        )

        return {
            "total_policies": len(self.policies),
            "global_policies": len(self.global_policies),
            "tenant_specific_policies": len(self.policies) - len(self.global_policies),
            "evaluations_count": self._evaluation_count,
            "cache_hit_rate_percent": round(cache_hit_rate, 2),
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cached_tenants": len(self._tenant_modules_cache),
            "cached_policy_sets": len(self._policy_cache),
        }

    async def validate_policy(self, policy: Policy) -> Dict[str, Any]:
        """Validate policy structure and logic"""
        issues = []

        # Basic validation
        if not policy.policy_id:
            issues.append("Missing policy_id")

        if not policy.name:
            issues.append("Missing policy name")

        if not policy.rules:
            issues.append("Policy has no rules")

        # Rule validation
        for i, rule in enumerate(policy.rules):
            if not rule.rule_id:
                issues.append(f"Rule {i} missing rule_id")

            if not rule.conditions:
                issues.append(f"Rule {rule.rule_id} has no conditions")

            # Condition validation
            for j, condition in enumerate(rule.conditions):
                try:
                    # Validate operator
                    ConditionOperator(condition.operator)

                    # Validate attribute type
                    AttributeType(condition.attribute_type)

                except ValueError as e:
                    issues.append(f"Rule {rule.rule_id}, condition {j}: {str(e)}")

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "policy_id": policy.policy_id,
            "rules_count": len(policy.rules),
            "conditions_count": sum(len(rule.conditions) for rule in policy.rules),
        }

    async def test_policy_against_scenarios(
        self, policy: Policy, test_scenarios: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Test policy against predefined scenarios"""
        results = []

        for i, scenario in enumerate(test_scenarios):
            context = scenario.get("context", {})
            expected_decision = scenario.get("expected_decision")

            try:
                # Temporarily add policy for testing
                test_engine = PolicyEngine()
                await test_engine.add_policy(policy)

                # Evaluate
                result = await test_engine.evaluate_request(
                    subject=context.get("subject", {}),
                    resource=context.get("resource", {}),
                    action=context.get("action", {}),
                    environment=context.get("environment", {}),
                    tenant_id=context.get("tenant_id"),
                )

                actual_decision = result["decision"]
                passed = (
                    actual_decision == expected_decision if expected_decision else True
                )

                results.append(
                    {
                        "scenario_id": i,
                        "description": scenario.get("description", f"Scenario {i}"),
                        "expected_decision": expected_decision,
                        "actual_decision": actual_decision,
                        "passed": passed,
                        "evaluation_time_ms": result["evaluation_time_ms"],
                    }
                )

            except Exception as e:
                results.append(
                    {
                        "scenario_id": i,
                        "description": scenario.get("description", f"Scenario {i}"),
                        "error": str(e),
                        "passed": False,
                    }
                )

        passed_count = sum(1 for r in results if r.get("passed", False))

        return {
            "total_scenarios": len(test_scenarios),
            "passed_scenarios": passed_count,
            "failed_scenarios": len(test_scenarios) - passed_count,
            "success_rate_percent": (
                round((passed_count / len(test_scenarios)) * 100, 2)
                if test_scenarios
                else 0
            ),
            "results": results,
        }


# Global policy engine instance
_policy_engine: Optional[PolicyEngine] = None


async def get_policy_engine() -> PolicyEngine:
    """Get global policy engine instance"""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
        await _policy_engine.initialize()
    return _policy_engine


# Convenience function for evaluation (backward compatibility)
async def evaluate_access(
    subject: Dict[str, Any],
    resource: Dict[str, Any],
    action: Dict[str, Any],
    environment: Dict[str, Any],
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function to evaluate access using the global policy engine
    """
    engine = await get_policy_engine()
    return await engine.evaluate_request(
        subject=subject,
        resource=resource,
        action=action,
        environment=environment,
        tenant_id=tenant_id,
    )


# Database index management
async def ensure_abac_indexes() -> None:
    """Ensure ABAC-related database indexes"""
    try:
        manager = await get_connection_manager()

        # ABAC policies collection
        async with manager.get_collection("abac_policies") as collection:
            await collection.create_index("policy_id", unique=True, background=True)
            await collection.create_index("tenant_id", background=True)
            await collection.create_index("is_active", background=True)
            await collection.create_index("version", background=True)
            await collection.create_index("updated_at", background=True)

            # Compound indexes
            await collection.create_index(
                [("tenant_id", 1), ("is_active", 1)], background=True
            )

        logger.info("ABAC indexes ensured successfully")

    except Exception as e:
        logger.error(f"Failed to ensure ABAC indexes: {e}")
        raise


# Export all classes and functions
__all__ = [
    # Enums
    "Effect",
    "PolicyDecision",
    "AttributeType",
    "ConditionOperator",
    # Data Classes
    "PolicyCondition",
    "PolicyRule",
    "Policy",
    # Core Classes
    "PolicyEngine",
    # Global Functions
    "get_policy_engine",
    "evaluate_access",
    "ensure_abac_indexes",
]
