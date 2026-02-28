"""
Audit event handlers and processors
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from .models import AuditEvent, AuditEventType, AuditSeverity
from .logger import AuditLogger

logger = logging.getLogger(__name__)


class EventProcessorStatus(str, Enum):
    """Status of event processor"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


@dataclass
class EventProcessor:
    """Event processor configuration"""
    name: str
    handler: Callable[[AuditEvent], None]
    event_types: List[AuditEventType] = None
    severity_threshold: AuditSeverity = AuditSeverity.LOW
    active: bool = True
    retry_count: int = 3
    retry_delay: float = 1.0


class AuditEventManager:
    """Manages audit event processing and routing"""

    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.processors: Dict[str, EventProcessor] = {}
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.processing_task: Optional[asyncio.Task] = None
        self.is_running = False

    async def start(self):
        """Start the event processing loop"""
        if self.is_running:
            return

        self.is_running = True
        self.processing_task = asyncio.create_task(self._process_events())
        logger.info("Audit event manager started")

    async def stop(self):
        """Stop the event processing loop"""
        if not self.is_running:
            return

        self.is_running = False
        if self.processing_task:
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:
                pass
        logger.info("Audit event manager stopped")

    def register_processor(self, processor: EventProcessor):
        """Register an event processor"""
        self.processors[processor.name] = processor
        logger.info(f"Registered audit event processor: {processor.name}")

    def unregister_processor(self, name: str):
        """Unregister an event processor"""
        if name in self.processors:
            del self.processors[name]
            logger.info(f"Unregistered audit event processor: {name}")

    async def queue_event(self, event: AuditEvent):
        """Queue an event for processing"""
        await self.event_queue.put(event)

    async def _process_events(self):
        """Process events from the queue"""
        while self.is_running:
            try:
                # Wait for an event with timeout
                try:
                    event = await asyncio.wait_for(
                        self.event_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                # Process the event
                await self._handle_event(event)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in event processing loop: {e}")
                await asyncio.sleep(1)

    async def _handle_event(self, event: AuditEvent):
        """Handle a single audit event"""
        for processor_name, processor in self.processors.items():
            if not processor.active:
                continue

            # Check if processor should handle this event
            if not self._should_process_event(processor, event):
                continue

            # Process the event with retry logic
            for attempt in range(processor.retry_count):
                try:
                    await self._execute_processor(processor, event)
                    break
                except Exception as e:
                    logger.error(
                        f"Processor {processor_name} failed (attempt {attempt + 1}): {e}"
                    )
                    if attempt < processor.retry_count - 1:
                        await asyncio.sleep(processor.retry_delay)
                    else:
                        logger.error(
                            f"Processor {processor_name} failed after {processor.retry_count} attempts"
                        )

    def _should_process_event(self, processor: EventProcessor, event: AuditEvent) -> bool:
        """Check if processor should handle the event"""
        # Check event types filter
        if processor.event_types and event.event_type not in processor.event_types:
            return False

        # Check severity threshold
        severity_order = {
            AuditSeverity.LOW: 0,
            AuditSeverity.MEDIUM: 1,
            AuditSeverity.HIGH: 2,
            AuditSeverity.CRITICAL: 3
        }

        if severity_order.get(event.severity, 0) < severity_order.get(processor.severity_threshold, 0):
            return False

        return True

    async def _execute_processor(self, processor: EventProcessor, event: AuditEvent):
        """Execute a processor with the event"""
        if asyncio.iscoroutinefunction(processor.handler):
            await processor.handler(event)
        else:
            processor.handler(event)


# Built-in event processors

async def security_alert_processor(event: AuditEvent):
    """Process security-related events and send alerts"""
    if event.severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]:
        # Send immediate alert
        logger.critical(
            f"SECURITY ALERT: {event.event_type.value} - {event.action.get('description', 'Unknown action')}"
        )

        # In production, you might want to:
        # - Send to SIEM system
        # - Trigger incident response
        # - Send notifications to security team
        # - Block suspicious IPs

    if event.event_type in [
        AuditEventType.LOGIN_FAILED,
        AuditEventType.ACCESS_DENIED,
        AuditEventType.RATE_LIMIT_EXCEEDED
    ]:
        # Track failed attempts for potential brute force detection
        await _track_failed_attempts(event)


async def compliance_processor(event: AuditEvent):
    """Process events for compliance requirements"""
    # Mark events that need special compliance handling
    compliance_events = [
        AuditEventType.EXPORT,
        AuditEventType.DELETE,
        AuditEventType.USER_DELETED,
        AuditEventType.DATA_BREACH_ATTEMPT
    ]

    if event.event_type in compliance_events:
        logger.info(f"Compliance event logged: {event.event_id}")

        # In production, you might want to:
        # - Forward to compliance system
        # - Generate compliance reports
        # - Ensure immutable storage
        # - Apply retention policies


async def anomaly_detector_processor(event: AuditEvent):
    """Detect anomalous patterns in audit events"""
    # Simple anomaly detection based on event patterns

    # Check for unusual login times
    if event.event_type == AuditEventType.LOGIN_SUCCESS:
        current_hour = event.timestamp.hour
        if current_hour < 6 or current_hour > 22:  # Outside business hours
            logger.warning(f"Off-hours login detected: {event.actor.get('username', 'unknown')}")

    # Check for rapid successive events from same actor
    # This would require maintaining state or querying recent events

    # Check for geographic anomalies (if IP geolocation is available)
    # This would require external geolocation service


async def _track_failed_attempts(event: AuditEvent):
    """Track failed authentication/authorization attempts"""
    # This is a simplified implementation
    # In production, you'd want to use Redis or similar for tracking

    actor_id = event.actor.get('id')
    ip_address = event.ip_address

    if not actor_id and not ip_address:
        return

    # Log the failed attempt for monitoring
    logger.warning(
        f"Failed attempt tracked - Actor: {actor_id}, IP: {ip_address}, Type: {event.event_type.value}"
    )

    # In production, you might:
    # - Increment counters in Redis
    # - Implement sliding window rate limiting
    # - Auto-block after threshold
    # - Send alerts to security team


def create_default_event_manager(audit_logger: AuditLogger) -> AuditEventManager:
    """Create event manager with default processors"""
    manager = AuditEventManager(audit_logger)

    # Register security alert processor for high-severity events
    security_processor = EventProcessor(
        name="security_alerts",
        handler=security_alert_processor,
        event_types=[
            AuditEventType.SECURITY_VIOLATION,
            AuditEventType.SUSPICIOUS_ACTIVITY,
            AuditEventType.DATA_BREACH_ATTEMPT,
            AuditEventType.LOGIN_FAILED,
            AuditEventType.ACCESS_DENIED
        ],
        severity_threshold=AuditSeverity.MEDIUM
    )
    manager.register_processor(security_processor)

    # Register compliance processor
    compliance_proc = EventProcessor(
        name="compliance",
        handler=compliance_processor,
        severity_threshold=AuditSeverity.LOW
    )
    manager.register_processor(compliance_proc)

    # Register anomaly detector
    anomaly_proc = EventProcessor(
        name="anomaly_detector",
        handler=anomaly_detector_processor,
        event_types=[
            AuditEventType.LOGIN_SUCCESS,
            AuditEventType.LOGIN_FAILED,
            AuditEventType.ACCESS_DENIED
        ],
        severity_threshold=AuditSeverity.LOW
    )
    manager.register_processor(anomaly_proc)

    return manager


# Global event manager
_event_manager: Optional[AuditEventManager] = None


async def get_event_manager() -> AuditEventManager:
    """Get the global event manager instance"""
    global _event_manager
    if _event_manager is None:
        from .logger import get_audit_logger
        audit_logger = await get_audit_logger()
        _event_manager = create_default_event_manager(audit_logger)
        await _event_manager.start()
    return _event_manager


async def shutdown_event_manager():
    """Shutdown the global event manager"""
    global _event_manager
    if _event_manager:
        await _event_manager.stop()
        _event_manager = None