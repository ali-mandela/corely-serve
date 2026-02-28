"""
Production-grade audit system for enterprise applications

This module provides comprehensive audit logging capabilities including:
- Event logging with structured data
- Event processing and routing
- Decorators for automatic auditing
- Security and compliance monitoring
"""

from .models import (
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    AuditQuery,
    AuditSummary
)

from .logger import (
    AuditLogger,
    get_audit_logger,
    log_auth_event,
    log_access_event,
    log_data_event,
    log_security_event
)

from .events import (
    AuditEventManager,
    EventProcessor,
    EventProcessorStatus,
    get_event_manager,
    shutdown_event_manager,
    create_default_event_manager,
    security_alert_processor,
    compliance_processor,
    anomaly_detector_processor
)

from .decorators import (
    audit_event,
    audit_data_access,
    audit_auth_operation,
    audit_admin_operation,
    AuditContext,
    audit_login_attempt,
    audit_permission_check,
    audit_security_incident
)

__all__ = [
    # Models
    "AuditEvent",
    "AuditEventType",
    "AuditSeverity",
    "AuditQuery",
    "AuditSummary",

    # Logger
    "AuditLogger",
    "get_audit_logger",
    "log_auth_event",
    "log_access_event",
    "log_data_event",
    "log_security_event",

    # Event Management
    "AuditEventManager",
    "EventProcessor",
    "EventProcessorStatus",
    "get_event_manager",
    "shutdown_event_manager",
    "create_default_event_manager",
    "security_alert_processor",
    "compliance_processor",
    "anomaly_detector_processor",

    # Decorators
    "audit_event",
    "audit_data_access",
    "audit_auth_operation",
    "audit_admin_operation",
    "AuditContext",
    "audit_login_attempt",
    "audit_permission_check",
    "audit_security_incident",
]

# Version info
__version__ = "1.0.0"
__author__ = "Enterprise Development Team"