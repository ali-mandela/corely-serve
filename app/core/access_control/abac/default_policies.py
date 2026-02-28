from .models import Policy, PolicyRule, Condition, PolicyEffect, ConditionOperator
from .engine import policy_engine


def create_basic_user_policy() -> Policy:
    """Create basic policy for authenticated users"""
    return Policy(
        id="basic_user_policy",
        name="Basic User Access",
        description="Basic access rights for authenticated users",
        rules=[
            PolicyRule(
                id="authenticated_user_read",
                description="Authenticated users can read public resources",
                effect=PolicyEffect.PERMIT,
                priority=10,
                condition=Condition(
                    operator=ConditionOperator.AND,
                    attribute="",
                    conditions=[
                        Condition(
                            attribute="user_id",
                            operator=ConditionOperator.NOT_EQUALS,
                            value=None
                        ),
                        Condition(
                            attribute="action",
                            operator=ConditionOperator.EQUALS,
                            value="read"
                        ),
                        Condition(
                            attribute="resource_sensitivity",
                            operator=ConditionOperator.IN,
                            value=["public", "internal"]
                        )
                    ]
                )
            )
        ]
    )


def create_admin_policy() -> Policy:
    """Create policy for admin users"""
    return Policy(
        id="admin_policy",
        name="Administrator Access",
        description="Full access for administrators",
        rules=[
            PolicyRule(
                id="admin_full_access",
                description="Admins have full access to all resources",
                effect=PolicyEffect.PERMIT,
                priority=100,
                condition=Condition(
                    operator=ConditionOperator.OR,
                    attribute="",
                    conditions=[
                        Condition(
                            attribute="roles",
                            operator=ConditionOperator.CONTAINS,
                            value="admin"
                        ),
                        Condition(
                            attribute="is_admin",
                            operator=ConditionOperator.EQUALS,
                            value=True
                        )
                    ]
                )
            )
        ]
    )


def create_resource_owner_policy() -> Policy:
    """Create policy for resource ownership"""
    return Policy(
        id="resource_owner_policy",
        name="Resource Owner Access",
        description="Users can manage their own resources",
        rules=[
            PolicyRule(
                id="owner_full_access",
                description="Resource owners have full access to their resources",
                effect=PolicyEffect.PERMIT,
                priority=50,
                condition=Condition(
                    operator=ConditionOperator.AND,
                    attribute="",
                    conditions=[
                        Condition(
                            attribute="user_id",
                            operator=ConditionOperator.NOT_EQUALS,
                            value=None
                        ),
                        Condition(
                            attribute="resource_owner",
                            operator=ConditionOperator.EQUALS,
                            value="{{user_id}}"  # Dynamic value resolved at runtime
                        )
                    ]
                )
            )
        ]
    )


def create_business_hours_policy() -> Policy:
    """Create policy that restricts sensitive operations to business hours"""
    return Policy(
        id="business_hours_policy",
        name="Business Hours Restriction",
        description="Sensitive operations only allowed during business hours",
        rules=[
            PolicyRule(
                id="sensitive_business_hours_only",
                description="Deny sensitive operations outside business hours",
                effect=PolicyEffect.DENY,
                priority=80,
                condition=Condition(
                    operator=ConditionOperator.AND,
                    attribute="",
                    conditions=[
                        Condition(
                            attribute="resource_sensitivity",
                            operator=ConditionOperator.EQUALS,
                            value="confidential"
                        ),
                        Condition(
                            attribute="action",
                            operator=ConditionOperator.IN,
                            value=["create", "update", "delete"]
                        ),
                        Condition(
                            operator=ConditionOperator.OR,
                            attribute="",
                            conditions=[
                                Condition(
                                    attribute="is_business_hours",
                                    operator=ConditionOperator.EQUALS,
                                    value=False
                                ),
                                Condition(
                                    attribute="is_weekend",
                                    operator=ConditionOperator.EQUALS,
                                    value=True
                                )
                            ]
                        )
                    ]
                )
            )
        ]
    )


def create_department_policy() -> Policy:
    """Create policy for department-based access"""
    return Policy(
        id="department_policy",
        name="Department Access Control",
        description="Users can only access resources from their department",
        rules=[
            PolicyRule(
                id="same_department_access",
                description="Users can access resources from their department",
                effect=PolicyEffect.PERMIT,
                priority=30,
                condition=Condition(
                    operator=ConditionOperator.AND,
                    attribute="",
                    conditions=[
                        Condition(
                            attribute="department",
                            operator=ConditionOperator.NOT_EQUALS,
                            value=None
                        ),
                        Condition(
                            attribute="resource_department",
                            operator=ConditionOperator.EQUALS,
                            value="{{department}}"  # Dynamic value
                        )
                    ]
                )
            ),
            PolicyRule(
                id="cross_department_deny",
                description="Deny access to resources from different departments",
                effect=PolicyEffect.DENY,
                priority=25,
                condition=Condition(
                    operator=ConditionOperator.AND,
                    attribute="",
                    conditions=[
                        Condition(
                            attribute="department",
                            operator=ConditionOperator.NOT_EQUALS,
                            value=None
                        ),
                        Condition(
                            attribute="resource_department",
                            operator=ConditionOperator.NOT_EQUALS,
                            value=None
                        ),
                        Condition(
                            attribute="resource_department",
                            operator=ConditionOperator.NOT_EQUALS,
                            value="{{department}}"
                        )
                    ]
                )
            )
        ]
    )


def create_ip_restriction_policy() -> Policy:
    """Create policy for IP-based restrictions"""
    return Policy(
        id="ip_restriction_policy",
        name="IP Address Restrictions",
        description="Restrict admin operations to specific IP ranges",
        rules=[
            PolicyRule(
                id="admin_ip_restriction",
                description="Admin operations only from trusted IPs",
                effect=PolicyEffect.DENY,
                priority=90,
                condition=Condition(
                    operator=ConditionOperator.AND,
                    attribute="",
                    conditions=[
                        Condition(
                            attribute="action",
                            operator=ConditionOperator.IN,
                            value=["delete", "admin"]
                        ),
                        Condition(
                            operator=ConditionOperator.NOT,
                            attribute="",
                            conditions=[
                                Condition(
                                    attribute="ip_address",
                                    operator=ConditionOperator.REGEX,
                                    value=r"^(192\.168\.|10\.|127\.0\.0\.1)"  # Internal IPs
                                )
                            ]
                        )
                    ]
                )
            )
        ]
    )


def load_default_policies() -> int:
    """Load all default policies into the policy engine"""
    policies = [
        create_basic_user_policy(),
        create_admin_policy(),
        create_resource_owner_policy(),
        create_business_hours_policy(),
        create_department_policy(),
        create_ip_restriction_policy(),
    ]

    for policy in policies:
        policy_engine.add_policy(policy)

    return len(policies)


def load_custom_policy(policy_dict: dict) -> Policy:
    """Load a custom policy from dictionary"""
    policy = Policy(**policy_dict)
    policy_engine.add_policy(policy)
    return policy