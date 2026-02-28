from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class PolicyEffect(str, Enum):
    PERMIT = "permit"
    DENY = "deny"


class AttributeType(str, Enum):
    SUBJECT = "subject"
    RESOURCE = "resource"
    ACTION = "action"
    ENVIRONMENT = "environment"


class ConditionOperator(str, Enum):
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    AND = "and"
    OR = "or"
    NOT = "not"


class AttributeValue(BaseModel):
    """Represents an attribute with its type and value"""
    name: str
    type: AttributeType
    value: Union[str, int, float, bool, List[Any], Dict[str, Any]]


class Condition(BaseModel):
    """Represents a condition in a policy rule"""
    attribute: str
    operator: ConditionOperator
    value: Union[str, int, float, bool, List[Any], None] = None
    conditions: Optional[List["Condition"]] = None  # For nested conditions (AND, OR, NOT)


class PolicyRule(BaseModel):
    """Represents a single policy rule"""
    id: str = Field(..., description="Unique identifier for the rule")
    description: Optional[str] = None
    effect: PolicyEffect
    condition: Condition
    priority: int = Field(default=0, description="Higher priority rules are evaluated first")


class Policy(BaseModel):
    """Represents a complete ABAC policy"""
    id: str = Field(..., description="Unique identifier for the policy")
    name: str
    description: Optional[str] = None
    version: str = "1.0"
    rules: List[PolicyRule]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


class AccessRequest(BaseModel):
    """Represents an access request to be evaluated"""
    subject_attributes: Dict[str, Any] = Field(..., description="Subject (user) attributes")
    resource_attributes: Dict[str, Any] = Field(..., description="Resource attributes")
    action_attributes: Dict[str, Any] = Field(..., description="Action attributes")
    environment_attributes: Dict[str, Any] = Field(default_factory=dict, description="Environment attributes")


class PolicyDecision(BaseModel):
    """Represents the result of policy evaluation"""
    decision: PolicyEffect
    applicable_policies: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    evaluation_time_ms: float = 0.0


class ABACContext(BaseModel):
    """Context for ABAC evaluation including all attributes"""
    subject_id: Optional[str] = None
    user_id: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    department: Optional[str] = None
    organization_id: Optional[str] = None

    # Resource attributes
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_owner: Optional[str] = None
    resource_sensitivity: Optional[str] = None

    # Action attributes
    action: Optional[str] = None
    method: Optional[str] = None

    # Environment attributes
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    time_of_day: Optional[str] = None
    day_of_week: Optional[str] = None
    location: Optional[str] = None
    is_weekend: bool = False
    is_business_hours: bool = True


# Update forward references
Condition.model_rebuild()