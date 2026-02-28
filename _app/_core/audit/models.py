"""
Audit logging models and schemas
"""
from datetime import datetime
from typing import Dict, Any, Optional, List
from bson import ObjectId
from pydantic import BaseModel, Field
from enum import Enum

from app._models.user import PyObjectId


class AuditEventType(str, Enum):
    """Types of audit events"""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"

    # Authorization events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PERMISSION_CHANGED = "permission_changed"
    ROLE_CHANGED = "role_changed"

    # Data events
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXPORT = "export"
    IMPORT = "import"

    # Administrative events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_INVITED = "user_invited"
    ORGANIZATION_CREATED = "organization_created"
    ORGANIZATION_UPDATED = "organization_updated"
    STORE_CREATED = "store_created"
    STORE_UPDATED = "store_updated"

    # Security events
    SECURITY_VIOLATION = "security_violation"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    DATA_BREACH_ATTEMPT = "data_breach_attempt"

    # System events
    SYSTEM_ERROR = "system_error"
    CONFIGURATION_CHANGE = "configuration_change"
    BACKUP_CREATED = "backup_created"
    MAINTENANCE_START = "maintenance_start"
    MAINTENANCE_END = "maintenance_end"


class AuditSeverity(str, Enum):
    """Severity levels for audit events"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEvent(BaseModel):
    """Audit event model"""
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")

    # Event identification
    event_type: AuditEventType
    event_id: str = Field(..., description="Unique identifier for this event")
    correlation_id: Optional[str] = Field(None, description="Correlation ID for related events")

    # Temporal information
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Actor information (who performed the action)
    actor: Dict[str, Any] = Field(..., description="Information about who performed the action")

    # Target information (what was acted upon)
    target: Dict[str, Any] = Field(..., description="Information about what was acted upon")

    # Action information
    action: Dict[str, Any] = Field(..., description="Information about the action performed")

    # Context information
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context information")

    # Result information
    result: Dict[str, Any] = Field(..., description="Result of the action")

    # Metadata
    severity: AuditSeverity = AuditSeverity.MEDIUM
    tags: List[str] = Field(default_factory=list)

    # Multi-tenancy
    tenant_id: Optional[str] = Field(None, description="Organization/tenant ID")

    # Technical details
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    # Data protection
    contains_pii: bool = False
    data_classification: str = "internal"  # public, internal, confidential, restricted

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class AuditQuery(BaseModel):
    """Query parameters for audit log searches"""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    event_types: Optional[List[AuditEventType]] = None
    severity: Optional[List[AuditSeverity]] = None
    actor_id: Optional[str] = None
    tenant_id: Optional[str] = None
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    ip_address: Optional[str] = None
    tags: Optional[List[str]] = None
    correlation_id: Optional[str] = None
    limit: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)


class AuditSummary(BaseModel):
    """Summary statistics for audit events"""
    total_events: int
    events_by_type: Dict[str, int]
    events_by_severity: Dict[str, int]
    events_by_actor: Dict[str, int]
    unique_actors: int
    unique_targets: int
    date_range: Dict[str, datetime]
    top_ip_addresses: List[Dict[str, Any]]
    security_events: int
    failed_access_attempts: int