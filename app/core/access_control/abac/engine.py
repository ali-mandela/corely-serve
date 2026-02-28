import re
import time
from typing import Dict, Any, List, Optional, Union
from .models import (
    Policy, PolicyRule, Condition, PolicyEffect, PolicyDecision,
    ABACContext, ConditionOperator
)


class ConditionEvaluator:
    """Evaluates ABAC policy conditions"""

    def evaluate(self, condition: Condition, attributes: Dict[str, Any]) -> bool:
        """Evaluate a condition against provided attributes"""
        try:
            if condition.operator in [ConditionOperator.AND, ConditionOperator.OR, ConditionOperator.NOT]:
                return self._evaluate_logical_condition(condition, attributes)
            else:
                return self._evaluate_simple_condition(condition, attributes)
        except Exception as e:
            # Log error and return False for safety
            print(f"Error evaluating condition: {e}")
            return False

    def _evaluate_logical_condition(self, condition: Condition, attributes: Dict[str, Any]) -> bool:
        """Evaluate logical conditions (AND, OR, NOT)"""
        if not condition.conditions:
            return False

        if condition.operator == ConditionOperator.AND:
            return all(self.evaluate(c, attributes) for c in condition.conditions)
        elif condition.operator == ConditionOperator.OR:
            return any(self.evaluate(c, attributes) for c in condition.conditions)
        elif condition.operator == ConditionOperator.NOT:
            # NOT should only have one condition
            if len(condition.conditions) == 1:
                return not self.evaluate(condition.conditions[0], attributes)
        return False

    def _evaluate_simple_condition(self, condition: Condition, attributes: Dict[str, Any]) -> bool:
        """Evaluate simple comparison conditions"""
        # Get attribute value - supports nested attributes using dot notation
        attr_value = self._get_nested_attribute(attributes, condition.attribute)
        condition_value = condition.value

        if condition.operator == ConditionOperator.EQUALS:
            return attr_value == condition_value
        elif condition.operator == ConditionOperator.NOT_EQUALS:
            return attr_value != condition_value
        elif condition.operator == ConditionOperator.GREATER_THAN:
            return self._safe_compare(attr_value, condition_value, lambda a, b: a > b)
        elif condition.operator == ConditionOperator.GREATER_THAN_OR_EQUAL:
            return self._safe_compare(attr_value, condition_value, lambda a, b: a >= b)
        elif condition.operator == ConditionOperator.LESS_THAN:
            return self._safe_compare(attr_value, condition_value, lambda a, b: a < b)
        elif condition.operator == ConditionOperator.LESS_THAN_OR_EQUAL:
            return self._safe_compare(attr_value, condition_value, lambda a, b: a <= b)
        elif condition.operator == ConditionOperator.IN:
            return attr_value in condition_value if isinstance(condition_value, (list, tuple)) else False
        elif condition.operator == ConditionOperator.NOT_IN:
            return attr_value not in condition_value if isinstance(condition_value, (list, tuple)) else True
        elif condition.operator == ConditionOperator.CONTAINS:
            return self._safe_contains(attr_value, condition_value)
        elif condition.operator == ConditionOperator.NOT_CONTAINS:
            return not self._safe_contains(attr_value, condition_value)
        elif condition.operator == ConditionOperator.STARTS_WITH:
            return str(attr_value).startswith(str(condition_value)) if attr_value is not None else False
        elif condition.operator == ConditionOperator.ENDS_WITH:
            return str(attr_value).endswith(str(condition_value)) if attr_value is not None else False
        elif condition.operator == ConditionOperator.REGEX:
            return bool(re.match(str(condition_value), str(attr_value))) if attr_value is not None else False

        return False

    def _get_nested_attribute(self, attributes: Dict[str, Any], attr_path: str) -> Any:
        """Get nested attribute value using dot notation (e.g., 'user.role')"""
        if '.' not in attr_path:
            return attributes.get(attr_path)

        parts = attr_path.split('.')
        value = attributes
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
            if value is None:
                break
        return value

    def _safe_compare(self, attr_value: Any, condition_value: Any, comparator) -> bool:
        """Safely compare values with type checking"""
        if attr_value is None or condition_value is None:
            return False
        try:
            # Convert both to same type if possible
            if isinstance(attr_value, str) and isinstance(condition_value, (int, float)):
                attr_value = type(condition_value)(attr_value)
            elif isinstance(condition_value, str) and isinstance(attr_value, (int, float)):
                condition_value = type(attr_value)(condition_value)
            return comparator(attr_value, condition_value)
        except (ValueError, TypeError):
            return False

    def _safe_contains(self, attr_value: Any, condition_value: Any) -> bool:
        """Safely check containment"""
        if attr_value is None:
            return False
        try:
            if isinstance(attr_value, (list, tuple)):
                return condition_value in attr_value
            elif isinstance(attr_value, str):
                return str(condition_value) in attr_value
        except TypeError:
            pass
        return False


class PolicyEngine:
    """Core ABAC policy engine for evaluating access requests"""

    def __init__(self):
        self.policies: Dict[str, Policy] = {}
        self.condition_evaluator = ConditionEvaluator()

    def add_policy(self, policy: Policy):
        """Add a policy to the engine"""
        self.policies[policy.id] = policy

    def remove_policy(self, policy_id: str):
        """Remove a policy from the engine"""
        if policy_id in self.policies:
            del self.policies[policy_id]

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get a policy by ID"""
        return self.policies.get(policy_id)

    def list_policies(self) -> List[Policy]:
        """List all policies"""
        return list(self.policies.values())

    async def evaluate(self, context: ABACContext) -> PolicyDecision:
        """Evaluate access request against all policies"""
        start_time = time.time()

        # Convert context to attributes dictionary
        attributes = self._context_to_attributes(context)

        applicable_policies = []
        reasons = []
        final_decision = PolicyEffect.DENY  # Default deny

        # Get all active policies sorted by priority
        active_policies = [p for p in self.policies.values() if p.is_active]

        # Group policies by priority and evaluate
        for policy in sorted(active_policies, key=lambda p: max((rule.priority for rule in p.rules), default=0), reverse=True):
            policy_result = self._evaluate_policy(policy, attributes)

            if policy_result["applicable"]:
                applicable_policies.append(policy.id)
                reasons.extend(policy_result["reasons"])

                # Check if we have a permit decision
                if policy_result["decision"] == PolicyEffect.PERMIT:
                    final_decision = PolicyEffect.PERMIT
                    # Continue evaluating to collect all applicable policies
                elif policy_result["decision"] == PolicyEffect.DENY:
                    # Explicit deny - but continue to see if there's a higher priority permit
                    pass

        # If no applicable policies found, default to deny
        if not applicable_policies:
            reasons.append("No applicable policies found")

        evaluation_time = (time.time() - start_time) * 1000  # Convert to milliseconds

        return PolicyDecision(
            decision=final_decision,
            applicable_policies=applicable_policies,
            reasons=reasons,
            evaluation_time_ms=evaluation_time
        )

    def _evaluate_policy(self, policy: Policy, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single policy"""
        applicable = False
        reasons = []
        decision = PolicyEffect.DENY

        # Sort rules by priority (highest first)
        sorted_rules = sorted(policy.rules, key=lambda r: r.priority, reverse=True)

        for rule in sorted_rules:
            if self.condition_evaluator.evaluate(rule.condition, attributes):
                applicable = True
                decision = rule.effect
                reason = f"Policy '{policy.name}' rule '{rule.id}' matched"
                if rule.description:
                    reason += f": {rule.description}"
                reasons.append(reason)

                # First matching rule wins (highest priority)
                break

        return {
            "applicable": applicable,
            "decision": decision,
            "reasons": reasons
        }

    def _context_to_attributes(self, context: ABACContext) -> Dict[str, Any]:
        """Convert ABACContext to flat attributes dictionary"""
        # Flatten the context into a single attributes dictionary
        attributes = {}

        # Convert context to dict and flatten nested structures
        context_dict = context.model_dump()

        # Add flattened attributes with proper prefixes
        for key, value in context_dict.items():
            if value is not None:
                attributes[key] = value

                # Add convenience mappings
                if key == "roles" and isinstance(value, list):
                    for role in value:
                        attributes[f"role.{role}"] = True
                elif key == "permissions" and isinstance(value, list):
                    for perm in value:
                        attributes[f"permission.{perm}"] = True

        return attributes


# Global policy engine instance
policy_engine = PolicyEngine()