"""
Enterprise audit logging system
"""
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from .models import AuditEvent, AuditEventType, AuditSeverity, AuditQuery, AuditSummary
from ..database import get_database

logger = logging.getLogger(__name__)


class AuditLogger:
    """Enterprise audit logging system"""

    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database
        self.collection = database.audit_logs
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Ensure proper indexes for audit log queries"""
        # Note: In production, create these indexes manually for better control
        # This is just for convenience during development
        pass

    async def log_event(
        self,
        event_type: AuditEventType,
        actor: Dict[str, Any],
        target: Dict[str, Any],
        action: Dict[str, Any],
        result: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.MEDIUM,
        tenant_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        contains_pii: bool = False,
        data_classification: str = "internal"
    ) -> str:
        """
        Log an audit event

        Returns:
            str: The event ID of the logged event
        """
        event_id = str(uuid.uuid4())

        audit_event = AuditEvent(
            event_type=event_type,
            event_id=event_id,
            correlation_id=correlation_id,
            actor=actor,
            target=target,
            action=action,
            result=result,
            context=context or {},
            severity=severity,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            session_id=session_id,
            tags=tags or [],
            contains_pii=contains_pii,
            data_classification=data_classification
        )

        try:
            await self.collection.insert_one(
                audit_event.model_dump(by_alias=True, exclude={"id"})
            )
            logger.debug(f"Audit event logged: {event_id}")
            return event_id
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            # In production, you might want to have a fallback logging mechanism
            return event_id

    async def log_authentication_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str],
        username: str,
        success: bool,
        ip_address: str,
        user_agent: str,
        tenant_id: Optional[str] = None,
        error_message: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log authentication-related events"""
        actor = {
            "type": "user",
            "id": user_id,
            "username": username,
            "tenant_id": tenant_id
        }

        target = {
            "type": "authentication_system",
            "id": "auth"
        }

        action = {
            "type": event_type.value,
            "description": f"User {username} attempted authentication"
        }

        result = {
            "success": success,
            "status_code": 200 if success else 401,
            "message": "Authentication successful" if success else error_message or "Authentication failed"
        }

        severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM

        return await self.log_event(
            event_type=event_type,
            actor=actor,
            target=target,
            action=action,
            result=result,
            context=context,
            severity=severity,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            tags=["authentication"]
        )

    async def log_authorization_event(
        self,
        user_id: str,
        resource_type: str,
        resource_id: Optional[str],
        action_type: str,
        granted: bool,
        policy_decisions: List[Dict[str, Any]],
        ip_address: str,
        tenant_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log authorization decisions"""
        actor = {
            "type": "user",
            "id": user_id,
            "tenant_id": tenant_id
        }

        target = {
            "type": resource_type,
            "id": resource_id,
            "tenant_id": tenant_id
        }

        action = {
            "type": action_type,
            "description": f"Access attempt to {resource_type}"
        }

        result = {
            "access_granted": granted,
            "policy_decisions": policy_decisions,
            "decision_count": len(policy_decisions)
        }

        event_type = AuditEventType.ACCESS_GRANTED if granted else AuditEventType.ACCESS_DENIED
        severity = AuditSeverity.LOW if granted else AuditSeverity.MEDIUM

        return await self.log_event(
            event_type=event_type,
            actor=actor,
            target=target,
            action=action,
            result=result,
            context=context,
            severity=severity,
            tenant_id=tenant_id,
            ip_address=ip_address,
            tags=["authorization", "abac"]
        )

    async def log_data_access(
        self,
        user_id: str,
        operation: str,
        resource_type: str,
        resource_id: Optional[str],
        success: bool,
        tenant_id: Optional[str] = None,
        data_count: Optional[int] = None,
        sensitive_data: bool = False,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log data access operations"""
        actor = {
            "type": "user",
            "id": user_id,
            "tenant_id": tenant_id
        }

        target = {
            "type": resource_type,
            "id": resource_id,
            "tenant_id": tenant_id,
            "data_count": data_count,
            "sensitive": sensitive_data
        }

        action = {
            "type": operation.lower(),
            "description": f"{operation} operation on {resource_type}"
        }

        result = {
            "success": success,
            "records_affected": data_count
        }

        # Map operation to audit event type
        operation_mapping = {
            "create": AuditEventType.CREATE,
            "read": AuditEventType.READ,
            "update": AuditEventType.UPDATE,
            "delete": AuditEventType.DELETE,
            "export": AuditEventType.EXPORT,
            "import": AuditEventType.IMPORT
        }

        event_type = operation_mapping.get(operation.lower(), AuditEventType.READ)
        severity = AuditSeverity.HIGH if sensitive_data else AuditSeverity.LOW

        return await self.log_event(
            event_type=event_type,
            actor=actor,
            target=target,
            action=action,
            result=result,
            context=context,
            severity=severity,
            tenant_id=tenant_id,
            contains_pii=sensitive_data,
            tags=["data_access", operation.lower()]
        )

    async def log_security_event(
        self,
        event_type: AuditEventType,
        description: str,
        user_id: Optional[str],
        ip_address: str,
        severity: AuditSeverity = AuditSeverity.HIGH,
        tenant_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log security-related events"""
        actor = {
            "type": "user" if user_id else "system",
            "id": user_id or "system",
            "tenant_id": tenant_id
        }

        target = {
            "type": "security_system",
            "id": "security"
        }

        action = {
            "type": event_type.value,
            "description": description
        }

        result = {
            "security_event": True,
            "requires_investigation": severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]
        }

        return await self.log_event(
            event_type=event_type,
            actor=actor,
            target=target,
            action=action,
            result=result,
            context=context,
            severity=severity,
            tenant_id=tenant_id,
            ip_address=ip_address,
            tags=["security", "alert"]
        )

    async def search_events(self, query: AuditQuery) -> List[AuditEvent]:
        """Search audit events based on query parameters"""
        filter_dict = {}

        # Date range filter
        if query.start_date or query.end_date:
            date_filter = {}
            if query.start_date:
                date_filter["$gte"] = query.start_date
            if query.end_date:
                date_filter["$lte"] = query.end_date
            filter_dict["timestamp"] = date_filter

        # Event type filter
        if query.event_types:
            filter_dict["event_type"] = {"$in": [et.value for et in query.event_types]}

        # Severity filter
        if query.severity:
            filter_dict["severity"] = {"$in": [s.value for s in query.severity]}

        # Actor filter
        if query.actor_id:
            filter_dict["actor.id"] = query.actor_id

        # Tenant filter
        if query.tenant_id:
            filter_dict["tenant_id"] = query.tenant_id

        # Target filters
        if query.target_type:
            filter_dict["target.type"] = query.target_type
        if query.target_id:
            filter_dict["target.id"] = query.target_id

        # IP address filter
        if query.ip_address:
            filter_dict["ip_address"] = query.ip_address

        # Tags filter
        if query.tags:
            filter_dict["tags"] = {"$in": query.tags}

        # Correlation ID filter
        if query.correlation_id:
            filter_dict["correlation_id"] = query.correlation_id

        try:
            cursor = self.collection.find(filter_dict)
            cursor = cursor.sort("timestamp", -1)  # Most recent first
            cursor = cursor.skip(query.offset).limit(query.limit)

            events = []
            async for doc in cursor:
                events.append(AuditEvent(**doc))

            return events
        except Exception as e:
            logger.error(f"Error searching audit events: {e}")
            return []

    async def get_audit_summary(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        tenant_id: Optional[str] = None
    ) -> AuditSummary:
        """Get audit summary statistics"""
        # Default to last 30 days if no dates provided
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        match_filter = {
            "timestamp": {"$gte": start_date, "$lte": end_date}
        }
        if tenant_id:
            match_filter["tenant_id"] = tenant_id

        try:
            # Aggregation pipeline for summary statistics
            pipeline = [
                {"$match": match_filter},
                {
                    "$group": {
                        "_id": None,
                        "total_events": {"$sum": 1},
                        "events_by_type": {
                            "$push": "$event_type"
                        },
                        "events_by_severity": {
                            "$push": "$severity"
                        },
                        "unique_actors": {
                            "$addToSet": "$actor.id"
                        },
                        "unique_targets": {
                            "$addToSet": "$target.id"
                        },
                        "ip_addresses": {
                            "$push": "$ip_address"
                        },
                        "security_events": {
                            "$sum": {
                                "$cond": [
                                    {"$in": ["security", "$tags"]},
                                    1,
                                    0
                                ]
                            }
                        },
                        "failed_access": {
                            "$sum": {
                                "$cond": [
                                    {"$eq": ["$event_type", "access_denied"]},
                                    1,
                                    0
                                ]
                            }
                        }
                    }
                }
            ]

            result = await self.collection.aggregate(pipeline).to_list(1)

            if not result:
                return AuditSummary(
                    total_events=0,
                    events_by_type={},
                    events_by_severity={},
                    events_by_actor={},
                    unique_actors=0,
                    unique_targets=0,
                    date_range={"start": start_date, "end": end_date},
                    top_ip_addresses=[],
                    security_events=0,
                    failed_access_attempts=0
                )

            data = result[0]

            # Process aggregated data
            events_by_type = {}
            for event_type in data.get("events_by_type", []):
                events_by_type[event_type] = events_by_type.get(event_type, 0) + 1

            events_by_severity = {}
            for severity in data.get("events_by_severity", []):
                events_by_severity[severity] = events_by_severity.get(severity, 0) + 1

            # Count IP addresses
            ip_counts = {}
            for ip in data.get("ip_addresses", []):
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

            top_ips = [
                {"ip": ip, "count": count}
                for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ]

            return AuditSummary(
                total_events=data.get("total_events", 0),
                events_by_type=events_by_type,
                events_by_severity=events_by_severity,
                events_by_actor={},  # Would need additional aggregation
                unique_actors=len(data.get("unique_actors", [])),
                unique_targets=len(data.get("unique_targets", [])),
                date_range={"start": start_date, "end": end_date},
                top_ip_addresses=top_ips,
                security_events=data.get("security_events", 0),
                failed_access_attempts=data.get("failed_access", 0)
            )

        except Exception as e:
            logger.error(f"Error generating audit summary: {e}")
            return AuditSummary(
                total_events=0,
                events_by_type={},
                events_by_severity={},
                events_by_actor={},
                unique_actors=0,
                unique_targets=0,
                date_range={"start": start_date, "end": end_date},
                top_ip_addresses=[],
                security_events=0,
                failed_access_attempts=0
            )

    async def cleanup_old_events(self, retention_days: int = 365) -> int:
        """Clean up audit events older than retention period"""
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        try:
            result = await self.collection.delete_many(
                {"timestamp": {"$lt": cutoff_date}}
            )
            logger.info(f"Cleaned up {result.deleted_count} old audit events")
            return result.deleted_count
        except Exception as e:
            logger.error(f"Error cleaning up old audit events: {e}")
            return 0


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


async def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        db = await get_database()
        _audit_logger = AuditLogger(db)
    return _audit_logger


# Convenience functions
async def log_auth_event(event_type: AuditEventType, user_id: str, username: str, success: bool, **kwargs):
    """Log authentication event"""
    audit_logger = await get_audit_logger()
    return await audit_logger.log_authentication_event(
        event_type=event_type,
        user_id=user_id,
        username=username,
        success=success,
        **kwargs
    )


async def log_access_event(user_id: str, resource_type: str, action: str, granted: bool, **kwargs):
    """Log access control event"""
    audit_logger = await get_audit_logger()
    return await audit_logger.log_authorization_event(
        user_id=user_id,
        resource_type=resource_type,
        resource_id=kwargs.get("resource_id"),
        action_type=action,
        granted=granted,
        policy_decisions=kwargs.get("policy_decisions", []),
        ip_address=kwargs.get("ip_address", "unknown"),
        tenant_id=kwargs.get("tenant_id"),
        context=kwargs.get("context")
    )


async def log_data_event(user_id: str, operation: str, resource_type: str, success: bool, **kwargs):
    """Log data access event"""
    audit_logger = await get_audit_logger()

    # Extract resource_id from kwargs to avoid duplicate parameter
    resource_id = kwargs.pop("resource_id", None)

    return await audit_logger.log_data_access(
        user_id=user_id,
        operation=operation,
        resource_type=resource_type,
        resource_id=resource_id,
        success=success,
        **kwargs
    )


async def log_security_event(event_type: AuditEventType, description: str, **kwargs):
    """Log security event"""
    audit_logger = await get_audit_logger()
    return await audit_logger.log_security_event(
        event_type=event_type,
        description=description,
        **kwargs
    )