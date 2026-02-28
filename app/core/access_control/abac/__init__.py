"""
ABAC (Attribute-Based Access Control) System for Corely

This package provides a comprehensive ABAC system with:
- Policy engine for evaluating access requests
- Attribute providers for extracting context
- FastAPI middleware for automatic enforcement
- Default policies for common use cases
"""

from .models import (
    Policy, PolicyRule, Condition, PolicyEffect, PolicyDecision,
    ABACContext, ConditionOperator, AttributeType
)
from .engine import policy_engine, PolicyEngine, ConditionEvaluator
from .attributes import AttributeManager
from .middleware import ABACMiddleware, get_abac_context, get_abac_decision, abac_required
from .default_policies import load_default_policies, load_custom_policy

__all__ = [
    # Models
    "Policy", "PolicyRule", "Condition", "PolicyEffect", "PolicyDecision",
    "ABACContext", "ConditionOperator", "AttributeType",

    # Engine
    "policy_engine", "PolicyEngine", "ConditionEvaluator",

    # Attributes
    "AttributeManager",

    # Middleware & Dependencies
    "ABACMiddleware", "get_abac_context", "get_abac_decision", "abac_required",

    # Policy Management
    "load_default_policies", "load_custom_policy"
]