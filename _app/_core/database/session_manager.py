"""
Enterprise Multi-Tenant Stores Management System - Session Lifecycle & Transaction Management
This module provides comprehensive session management, transactions, and data consistency.
"""

import asyncio
import logging
import time
import uuid
from typing import Optional, Dict, Any, List, AsyncGenerator, Callable, Union, TypeVar
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import weakref

import motor.motor_asyncio
from motor.motor_asyncio import (
    AsyncIOMotorClientSession,
    AsyncIOMotorDatabase,
    AsyncIOMotorCollection,
)
from pymongo.errors import OperationFailure, DuplicateKeyError, WriteError
from pymongo import WriteConcern, ReadConcern, ReadPreference
from pymongo.client_session import SessionOptions

from app._core.database.connection import get_connection_manager, ConnectionPool
from app._core.config.settings import get_settings
from app._core.config.environment import is_development, is_production
from app._core.utils.constants import DatabaseConstants
from app._core.utils.exceptions import DatabaseException, ValidationException


logger = logging.getLogger(__name__)
T = TypeVar("T")


class TransactionState(Enum):
    """Transaction states"""

    INACTIVE = "inactive"
    ACTIVE = "active"
    COMMITTED = "committed"
    ABORTED = "aborted"
    FAILED = "failed"


class IsolationLevel(Enum):
    """Transaction isolation levels"""

    READ_UNCOMMITTED = "read_uncommitted"
    READ_COMMITTED = "read_committed"
    REPEATABLE_READ = "repeatable_read"
    SNAPSHOT = "snapshot"


@dataclass
class TransactionMetrics:
    """Transaction performance metrics"""

    transaction_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    state: TransactionState = TransactionState.INACTIVE
    operations_count: int = 0
    bytes_read: int = 0
    bytes_written: int = 0
    documents_read: int = 0
    documents_written: int = 0
    retry_count: int = 0
    error_message: Optional[str] = None

    @property
    def duration_ms(self) -> float:
        """Get transaction duration in milliseconds"""
        end = self.end_time or datetime.utcnow()
        return (end - self.start_time).total_seconds() * 1000


class SessionContext:
    """Database session context with transaction support"""

    def __init__(
        self,
        session: AsyncIOMotorClientSession,
        session_id: str,
        tenant_id: Optional[str] = None,
    ):
        self.session = session
        self.session_id = session_id
        self.tenant_id = tenant_id
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.transaction_count = 0
        self.current_transaction: Optional["TransactionContext"] = None
        self.metadata: Dict[str, Any] = {}
        self._operations_count = 0

    def update_activity(self) -> None:
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
        self._operations_count += 1

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to session"""
        self.metadata[key] = value

    def get_info(self) -> Dict[str, Any]:
        """Get session information"""
        return {
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "age_seconds": (datetime.utcnow() - self.created_at).total_seconds(),
            "idle_seconds": (datetime.utcnow() - self.last_activity).total_seconds(),
            "transaction_count": self.transaction_count,
            "operations_count": self._operations_count,
            "has_active_transaction": self.current_transaction is not None,
            "metadata": self.metadata,
        }


class TransactionContext:
    """Transaction context with automatic retry and rollback"""

    def __init__(
        self,
        session_ctx: SessionContext,
        isolation_level: IsolationLevel = IsolationLevel.SNAPSHOT,
        write_concern: Optional[WriteConcern] = None,
        read_concern: Optional[ReadConcern] = None,
        max_retry_attempts: int = 3,
    ):
        self.session_ctx = session_ctx
        self.transaction_id = str(uuid.uuid4())
        self.isolation_level = isolation_level
        self.write_concern = write_concern or WriteConcern(w="majority", wtimeout=5000)
        self.read_concern = read_concern or ReadConcern(level="snapshot")
        self.max_retry_attempts = max_retry_attempts

        self.metrics = TransactionMetrics(
            transaction_id=self.transaction_id, start_time=datetime.utcnow()
        )

        self.state = TransactionState.INACTIVE
        self.operations: List[Dict[str, Any]] = []
        self._savepoints: List[str] = []

    async def __aenter__(self) -> "TransactionContext":
        """Enter transaction context"""
        try:
            await self._start_transaction()
            return self
        except Exception as e:
            logger.error(f"Failed to start transaction {self.transaction_id}: {str(e)}")
            raise DatabaseException(f"Transaction start failed: {str(e)}")

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit transaction context"""
        if exc_type is not None:
            # Exception occurred, abort transaction
            await self._abort_transaction(str(exc_val))
        else:
            # No exception, commit transaction
            await self._commit_transaction()

    async def _start_transaction(self) -> None:
        """Start the transaction"""
        try:
            # Configure session options
            session_options = SessionOptions(
                read_concern=self.read_concern,
                write_concern=self.write_concern,
                read_preference=ReadPreference.PRIMARY,
            )

            # Start transaction
            await self.session_ctx.session.start_transaction()

            self.state = TransactionState.ACTIVE
            self.session_ctx.current_transaction = self
            self.session_ctx.transaction_count += 1

            logger.debug(f"Transaction {self.transaction_id} started")

        except Exception as e:
            self.state = TransactionState.FAILED
            self.metrics.error_message = str(e)
            raise

    async def _commit_transaction(self) -> None:
        """Commit the transaction"""
        if self.state != TransactionState.ACTIVE:
            return

        try:
            await self.session_ctx.session.commit_transaction()
            self.state = TransactionState.COMMITTED
            self.metrics.end_time = datetime.utcnow()

            logger.debug(
                f"Transaction {self.transaction_id} committed "
                f"({self.metrics.operations_count} operations, {self.metrics.duration_ms:.1f}ms)"
            )

        except Exception as e:
            self.state = TransactionState.FAILED
            self.metrics.error_message = str(e)
            self.metrics.end_time = datetime.utcnow()

            logger.error(f"Transaction {self.transaction_id} commit failed: {str(e)}")
            raise DatabaseException(f"Transaction commit failed: {str(e)}")
        finally:
            self.session_ctx.current_transaction = None

    async def _abort_transaction(self, reason: str) -> None:
        """Abort the transaction"""
        if self.state not in [TransactionState.ACTIVE, TransactionState.FAILED]:
            return

        try:
            await self.session_ctx.session.abort_transaction()
            self.state = TransactionState.ABORTED
            self.metrics.end_time = datetime.utcnow()
            self.metrics.error_message = reason

            logger.warning(
                f"Transaction {self.transaction_id} aborted: {reason} "
                f"({self.metrics.operations_count} operations, {self.metrics.duration_ms:.1f}ms)"
            )

        except Exception as e:
            logger.error(f"Transaction {self.transaction_id} abort failed: {str(e)}")
        finally:
            self.session_ctx.current_transaction = None

    def add_operation(
        self, operation_type: str, collection: str, operation_data: Dict[str, Any]
    ) -> None:
        """Add operation to transaction log"""
        self.operations.append(
            {
                "type": operation_type,
                "collection": collection,
                "data": operation_data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        self.metrics.operations_count += 1

    async def create_savepoint(self, name: str) -> str:
        """Create a savepoint (simulated for MongoDB)"""
        savepoint_id = f"{name}_{len(self._savepoints)}"
        self._savepoints.append(savepoint_id)

        logger.debug(
            f"Savepoint {savepoint_id} created in transaction {self.transaction_id}"
        )
        return savepoint_id

    async def rollback_to_savepoint(self, savepoint_id: str) -> None:
        """Rollback to savepoint (simulated for MongoDB)"""
        if savepoint_id not in self._savepoints:
            raise DatabaseException(f"Savepoint {savepoint_id} not found")

        # In MongoDB, we would need to implement custom logic for partial rollback
        # For now, we log the intent
        logger.warning(
            f"Rollback to savepoint {savepoint_id} requested in transaction {self.transaction_id}"
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Get transaction metrics"""
        return {
            "transaction_id": self.transaction_id,
            "state": self.state.value,
            "isolation_level": self.isolation_level.value,
            "start_time": self.metrics.start_time.isoformat(),
            "end_time": (
                self.metrics.end_time.isoformat() if self.metrics.end_time else None
            ),
            "duration_ms": self.metrics.duration_ms,
            "operations_count": self.metrics.operations_count,
            "retry_count": self.metrics.retry_count,
            "error_message": self.metrics.error_message,
            "operations": self.operations[-10:],  # Last 10 operations
        }


class SessionManager:
    """Comprehensive database session manager"""

    def __init__(self):
        self.settings = get_settings()
        self._active_sessions: Dict[str, SessionContext] = {}
        self._session_pool: weakref.WeakSet = weakref.WeakSet()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()

        # Session configuration
        self.max_idle_time = timedelta(minutes=30)
        self.cleanup_interval = 300  # 5 minutes
        self.max_sessions_per_tenant = 50

    async def initialize(self) -> None:
        """Initialize session manager"""
        # Start cleanup task
        if not self._cleanup_task or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info("Session manager initialized")

    async def shutdown(self) -> None:
        """Shutdown session manager"""
        self._shutdown_event.set()

        # Stop cleanup task
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Close all active sessions
        for session_ctx in list(self._active_sessions.values()):
            await self._close_session(session_ctx)

        logger.info("Session manager shutdown complete")

    @asynccontextmanager
    async def create_session(
        self, tenant_id: Optional[str] = None, pool_name: str = "default"
    ) -> AsyncGenerator[SessionContext, None]:
        """Create a new database session"""
        # Check tenant session limits
        if tenant_id:
            tenant_session_count = sum(
                1
                for ctx in self._active_sessions.values()
                if ctx.tenant_id == tenant_id
            )
            if tenant_session_count >= self.max_sessions_per_tenant:
                raise DatabaseException(
                    f"Maximum sessions exceeded for tenant {tenant_id}"
                )

        session_id = str(uuid.uuid4())
        session_ctx = None

        try:
            # Get connection manager and database
            manager = await get_connection_manager()
            pool = await manager.get_pool(pool_name)

            async with pool.get_database() as db:
                # Start client session
                client_session = await db.client.start_session()

                # Create session context
                session_ctx = SessionContext(client_session, session_id, tenant_id)
                self._active_sessions[session_id] = session_ctx
                self._session_pool.add(session_ctx)

                logger.debug(f"Session {session_id} created for tenant {tenant_id}")

                try:
                    yield session_ctx
                finally:
                    # Update activity on session end
                    session_ctx.update_activity()

        except Exception as e:
            logger.error(f"Session {session_id} creation failed: {str(e)}")
            raise DatabaseException(f"Session creation failed: {str(e)}")
        finally:
            # Cleanup session
            if session_ctx:
                await self._close_session(session_ctx)

    @asynccontextmanager
    async def create_transaction(
        self,
        session_ctx: SessionContext,
        isolation_level: IsolationLevel = IsolationLevel.SNAPSHOT,
        write_concern: Optional[WriteConcern] = None,
        read_concern: Optional[ReadConcern] = None,
        max_retry_attempts: int = 3,
    ) -> AsyncGenerator[TransactionContext, None]:
        """Create a transaction within a session"""
        if session_ctx.current_transaction:
            raise DatabaseException("Session already has an active transaction")

        transaction_ctx = TransactionContext(
            session_ctx=session_ctx,
            isolation_level=isolation_level,
            write_concern=write_concern,
            read_concern=read_concern,
            max_retry_attempts=max_retry_attempts,
        )

        async with transaction_ctx:
            yield transaction_ctx

    async def execute_in_transaction(
        self,
        operation: Callable[[TransactionContext], T],
        session_ctx: SessionContext,
        isolation_level: IsolationLevel = IsolationLevel.SNAPSHOT,
        max_retry_attempts: int = 3,
    ) -> T:
        """Execute operation in transaction with automatic retry"""
        last_exception = None

        for attempt in range(max_retry_attempts + 1):
            try:
                async with self.create_transaction(
                    session_ctx=session_ctx,
                    isolation_level=isolation_level,
                    max_retry_attempts=max_retry_attempts,
                ) as transaction_ctx:
                    if attempt > 0:
                        transaction_ctx.metrics.retry_count = attempt
                        logger.debug(f"Retrying transaction (attempt {attempt + 1})")

                    result = await operation(transaction_ctx)
                    return result

            except (OperationFailure, WriteError) as e:
                last_exception = e

                # Check if error is retryable
                if self._is_retryable_error(e) and attempt < max_retry_attempts:
                    retry_delay = min(2**attempt, 10)  # Exponential backoff, max 10s
                    logger.warning(
                        f"Transaction failed (attempt {attempt + 1}), retrying in {retry_delay}s: {str(e)}"
                    )
                    await asyncio.sleep(retry_delay)
                else:
                    logger.error(
                        f"Transaction failed after {attempt + 1} attempts: {str(e)}"
                    )
                    break

        raise DatabaseException(
            f"Transaction failed after retries: {str(last_exception)}"
        )

    def _is_retryable_error(self, error: Exception) -> bool:
        """Check if error is retryable"""
        if isinstance(error, OperationFailure):
            # MongoDB transient transaction errors
            retryable_codes = [112, 117, 11600, 11601, 11602]
            return error.code in retryable_codes

        return False

    async def _close_session(self, session_ctx: SessionContext) -> None:
        """Close a database session"""
        try:
            # Abort any active transaction
            if session_ctx.current_transaction:
                await session_ctx.current_transaction._abort_transaction(
                    "Session closing"
                )

            # End the client session
            await session_ctx.session.end_session()

            # Remove from active sessions
            self._active_sessions.pop(session_ctx.session_id, None)

            logger.debug(f"Session {session_ctx.session_id} closed")

        except Exception as e:
            logger.error(f"Error closing session {session_ctx.session_id}: {str(e)}")

    async def _cleanup_loop(self) -> None:
        """Background cleanup of idle sessions"""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_idle_sessions()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {str(e)}")

    async def _cleanup_idle_sessions(self) -> None:
        """Clean up idle sessions"""
        now = datetime.utcnow()
        idle_sessions = []

        for session_ctx in self._active_sessions.values():
            if now - session_ctx.last_activity > self.max_idle_time:
                idle_sessions.append(session_ctx)

        for session_ctx in idle_sessions:
            logger.info(f"Closing idle session {session_ctx.session_id}")
            await self._close_session(session_ctx)

    def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        now = datetime.utcnow()

        active_count = len(self._active_sessions)
        tenant_counts = {}

        for session_ctx in self._active_sessions.values():
            tenant_id = session_ctx.tenant_id or "system"
            tenant_counts[tenant_id] = tenant_counts.get(tenant_id, 0) + 1

        idle_sessions = sum(
            1
            for ctx in self._active_sessions.values()
            if now - ctx.last_activity > timedelta(minutes=5)
        )

        active_transactions = sum(
            1
            for ctx in self._active_sessions.values()
            if ctx.current_transaction is not None
        )

        return {
            "total_active_sessions": active_count,
            "idle_sessions": idle_sessions,
            "active_transactions": active_transactions,
            "sessions_by_tenant": tenant_counts,
            "max_sessions_per_tenant": self.max_sessions_per_tenant,
            "cleanup_interval_seconds": self.cleanup_interval,
            "max_idle_time_minutes": self.max_idle_time.total_seconds() / 60,
        }


# Global session manager instance
_session_manager: Optional[SessionManager] = None


async def get_session_manager() -> SessionManager:
    """Get global session manager instance"""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
        await _session_manager.initialize()
    return _session_manager


@asynccontextmanager
async def create_session(
    tenant_id: Optional[str] = None, pool_name: str = "default"
) -> AsyncGenerator[SessionContext, None]:
    """Create database session - convenience function"""
    manager = await get_session_manager()
    async with manager.create_session(tenant_id, pool_name) as session:
        yield session


@asynccontextmanager
async def create_transaction(
    session_ctx: SessionContext,
    isolation_level: IsolationLevel = IsolationLevel.SNAPSHOT,
) -> AsyncGenerator[TransactionContext, None]:
    """Create transaction - convenience function"""
    manager = await get_session_manager()
    async with manager.create_transaction(session_ctx, isolation_level) as transaction:
        yield transaction


async def execute_in_transaction(
    operation: Callable[[TransactionContext], T],
    tenant_id: Optional[str] = None,
    isolation_level: IsolationLevel = IsolationLevel.SNAPSHOT,
    max_retry_attempts: int = 3,
) -> T:
    """Execute operation in transaction - convenience function"""
    async with create_session(tenant_id) as session:
        manager = await get_session_manager()
        return await manager.execute_in_transaction(
            operation, session, isolation_level, max_retry_attempts
        )


async def get_session_stats() -> Dict[str, Any]:
    """Get session statistics - convenience function"""
    try:
        manager = await get_session_manager()
        return manager.get_session_stats()
    except Exception as e:
        return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}


async def shutdown_session_manager() -> None:
    """Shutdown session manager - convenience function"""
    global _session_manager
    if _session_manager:
        await _session_manager.shutdown()
        _session_manager = None


# Export all classes and functions
__all__ = [
    # Enums
    "TransactionState",
    "IsolationLevel",
    # Data Classes
    "TransactionMetrics",
    # Core Classes
    "SessionContext",
    "TransactionContext",
    "SessionManager",
    # Convenience Functions
    "get_session_manager",
    "create_session",
    "create_transaction",
    "execute_in_transaction",
    "get_session_stats",
    "shutdown_session_manager",
]
