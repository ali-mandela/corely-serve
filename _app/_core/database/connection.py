"""
Enterprise Multi-Tenant Stores Management System - Enhanced Database Connection Management
This module provides advanced database connection management, pooling, and monitoring.
"""

import asyncio
import logging
import time
from typing import Optional, Dict, Any, List, AsyncGenerator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import weakref

import motor.motor_asyncio
from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorDatabase,
    AsyncIOMotorCollection,
)
from pymongo import ReadPreference, WriteConcern, ReadConcern
from pymongo.errors import (
    ConnectionFailure,
    ServerSelectionTimeoutError,
    OperationFailure,
    NetworkTimeout,
    AutoReconnect,
    ConfigurationError,
)
from pymongo.monitoring import (
    CommandListener,
    ServerListener,
    TopologyListener,
    CommandStartedEvent,
    CommandSucceededEvent,
    CommandFailedEvent,
    ServerOpeningEvent,
    ServerClosedEvent,
    TopologyOpenedEvent,
    TopologyClosedEvent,
)

from app._core.config.settings import get_settings
from app._core.config.environment import is_development, is_production
from app._core.utils.constants import DatabaseConstants
from app._core.utils.exceptions import DatabaseConnectionException, DatabaseException


logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Database connection states"""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"
    CLOSING = "closing"


@dataclass
class ConnectionMetrics:
    """Database connection metrics"""

    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0
    connection_errors: int = 0
    query_count: int = 0
    slow_queries: int = 0
    average_response_time: float = 0.0
    last_error: Optional[str] = None
    last_error_time: Optional[datetime] = None
    uptime_seconds: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)


class DatabaseMonitor(CommandListener, ServerListener, TopologyListener):
    """MongoDB event monitor for performance and health tracking"""

    def __init__(self):
        self.metrics = ConnectionMetrics()
        self.command_times: Dict[int, float] = {}
        self.slow_query_threshold = 2.0  # 2 seconds
        self._lock = asyncio.Lock()

    def started(self, event: CommandStartedEvent) -> None:
        """Command started event"""
        self.command_times[event.request_id] = time.time()

    def succeeded(self, event: CommandSucceededEvent) -> None:
        """Command succeeded event"""
        request_id = event.request_id
        if request_id in self.command_times:
            duration = time.time() - self.command_times.pop(request_id)

            # Update metrics
            self.metrics.query_count += 1

            # Update average response time
            if self.metrics.average_response_time == 0:
                self.metrics.average_response_time = duration
            else:
                self.metrics.average_response_time = (
                    self.metrics.average_response_time * (self.metrics.query_count - 1)
                    + duration
                ) / self.metrics.query_count

            # Track slow queries
            if duration > self.slow_query_threshold:
                self.metrics.slow_queries += 1
                logger.warning(
                    f"Slow query detected: {event.command_name} took {duration:.2f}s",
                    extra={
                        "command": event.command_name,
                        "duration": duration,
                        "database": getattr(event, "database_name", "unknown"),
                    },
                )

    def failed(self, event: CommandFailedEvent) -> None:
        """Command failed event"""
        request_id = event.request_id
        self.command_times.pop(request_id, None)

        self.metrics.connection_errors += 1
        self.metrics.last_error = str(event.failure)
        self.metrics.last_error_time = datetime.utcnow()

        logger.error(
            f"Database command failed: {event.command_name}",
            extra={
                "command": event.command_name,
                "error": str(event.failure),
                "database": getattr(event, "database_name", "unknown"),
            },
        )

    def opened(self, event: ServerOpeningEvent) -> None:
        """Server connection opened"""
        self.metrics.active_connections += 1
        self.metrics.total_connections += 1

        logger.info(f"Database server connection opened: {event.server_address}")

    def closed(self, event: ServerClosedEvent) -> None:
        """Server connection closed"""
        self.metrics.active_connections = max(0, self.metrics.active_connections - 1)

        logger.info(f"Database server connection closed: {event.server_address}")

    def topology_opened(self, event: TopologyOpenedEvent) -> None:
        """Topology opened event"""
        logger.info("Database topology opened")

    def topology_closed(self, event: TopologyClosedEvent) -> None:
        """Topology closed event"""
        logger.info("Database topology closed")

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        uptime = (datetime.utcnow() - self.metrics.created_at).total_seconds()

        return {
            "total_connections": self.metrics.total_connections,
            "active_connections": self.metrics.active_connections,
            "idle_connections": self.metrics.idle_connections,
            "failed_connections": self.metrics.failed_connections,
            "connection_errors": self.metrics.connection_errors,
            "query_count": self.metrics.query_count,
            "slow_queries": self.metrics.slow_queries,
            "slow_query_percentage": (
                (self.metrics.slow_queries / self.metrics.query_count * 100)
                if self.metrics.query_count > 0
                else 0
            ),
            "average_response_time_ms": self.metrics.average_response_time * 1000,
            "uptime_seconds": uptime,
            "last_error": self.metrics.last_error,
            "last_error_time": (
                self.metrics.last_error_time.isoformat()
                if self.metrics.last_error_time
                else None
            ),
        }


class ConnectionPool:
    """Advanced connection pool with health monitoring and auto-recovery"""

    def __init__(self, connection_string: str, database_name: str, **kwargs):
        self.connection_string = connection_string
        self.database_name = database_name
        self.client: Optional[AsyncIOMotorClient] = None
        self.database: Optional[AsyncIOMotorDatabase] = None
        self.monitor = DatabaseMonitor()
        self.state = ConnectionState.DISCONNECTED
        self.settings = get_settings()

        # Connection pool settings
        self.max_pool_size = kwargs.get(
            "max_pool_size", self.settings.database.max_connections
        )
        self.min_pool_size = kwargs.get(
            "min_pool_size", self.settings.database.min_connections
        )
        self.connect_timeout_ms = kwargs.get(
            "connect_timeout_ms", self.settings.database.connection_timeout * 1000
        )
        self.server_selection_timeout_ms = kwargs.get(
            "server_selection_timeout_ms", 30000
        )

        # Health check settings
        self.health_check_interval = 30  # seconds
        self.max_reconnect_attempts = 5
        self.reconnect_delay = 5  # seconds

        # Background tasks
        self._health_check_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()

        # Connection tracking
        self._active_operations = weakref.WeakSet()
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        """Establish connection to MongoDB"""
        async with self._lock:
            if self.state in [ConnectionState.CONNECTED, ConnectionState.CONNECTING]:
                return

            self.state = ConnectionState.CONNECTING

            try:
                logger.info("Establishing database connection...")

                # Create client with monitoring
                self.client = AsyncIOMotorClient(
                    self.connection_string,
                    maxPoolSize=self.max_pool_size,
                    minPoolSize=self.min_pool_size,
                    connectTimeoutMS=self.connect_timeout_ms,
                    serverSelectionTimeoutMS=self.server_selection_timeout_ms,
                    socketTimeoutMS=self.settings.database.query_timeout * 1000,
                    retryWrites=True,
                    retryReads=True,
                    maxIdleTimeMS=300000,  # 5 minutes
                    waitQueueTimeoutMS=10000,  # 10 seconds
                    # Monitoring
                    event_listeners=[self.monitor],
                    # Atlas/Production settings
                    ssl=self.settings.database.enable_ssl,
                    authSource="admin",
                    appName="StoresManagement",
                    # Read/Write concerns
                    readPreference=ReadPreference.SECONDARY_PREFERRED,
                    readConcern=ReadConcern(level="majority"),
                    writeConcern=WriteConcern(w="majority", wtimeout=5000),
                )

                # Get database instance
                self.database = self.client[self.database_name]

                # Test connection
                await self._test_connection()

                self.state = ConnectionState.CONNECTED
                logger.info("✅ Database connection established successfully")

                # Start background tasks
                await self._start_background_tasks()

            except Exception as e:
                self.state = ConnectionState.FAILED
                logger.error(f"❌ Failed to establish database connection: {str(e)}")
                await self.disconnect()
                raise DatabaseConnectionException(self.database_name) from e

    async def disconnect(self) -> None:
        """Close database connection"""
        async with self._lock:
            if self.state == ConnectionState.DISCONNECTED:
                return

            self.state = ConnectionState.CLOSING
            logger.info("Closing database connection...")

            # Signal shutdown
            self._shutdown_event.set()

            # Stop background tasks
            await self._stop_background_tasks()

            # Wait for active operations to complete
            await self._wait_for_operations()

            # Close client
            if self.client:
                self.client.close()
                self.client = None
                self.database = None

            self.state = ConnectionState.DISCONNECTED
            logger.info("✅ Database connection closed")

    async def _test_connection(self) -> None:
        """Test database connection"""
        try:
            # Ping the database
            await self.client.admin.command("ping")
            await self.database.command("ping")

            # Get server info
            server_info = await self.client.server_info()
            logger.info(f"Connected to MongoDB {server_info.get('version', 'unknown')}")

        except Exception as e:
            logger.error(f"Database connection test failed: {str(e)}")
            raise

    async def _start_background_tasks(self) -> None:
        """Start background monitoring tasks"""
        if not self._health_check_task or self._health_check_task.done():
            self._health_check_task = asyncio.create_task(self._health_check_loop())

    async def _stop_background_tasks(self) -> None:
        """Stop background tasks"""
        tasks = [self._health_check_task, self._reconnect_task]

        for task in tasks:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    async def _health_check_loop(self) -> None:
        """Background health check loop"""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(self.health_check_interval)

                if self.state == ConnectionState.CONNECTED:
                    await self._perform_health_check()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {str(e)}")
                if self.state == ConnectionState.CONNECTED:
                    await self._handle_connection_loss()

    async def _perform_health_check(self) -> None:
        """Perform database health check"""
        try:
            start_time = time.time()
            await self.client.admin.command("ping")
            response_time = time.time() - start_time

            # Log slow health checks
            if response_time > 1.0:
                logger.warning(f"Slow health check: {response_time:.2f}s")

        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            await self._handle_connection_loss()

    async def _handle_connection_loss(self) -> None:
        """Handle connection loss and attempt reconnection"""
        if self.state == ConnectionState.RECONNECTING:
            return

        self.state = ConnectionState.RECONNECTING
        logger.warning("Database connection lost, attempting reconnection...")

        # Start reconnection task
        if not self._reconnect_task or self._reconnect_task.done():
            self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        """Reconnection loop with exponential backoff"""
        attempt = 1

        while (
            attempt <= self.max_reconnect_attempts and not self._shutdown_event.is_set()
        ):
            try:
                logger.info(
                    f"Reconnection attempt {attempt}/{self.max_reconnect_attempts}"
                )

                # Close existing connection
                if self.client:
                    self.client.close()
                    self.client = None
                    self.database = None

                # Wait before reconnecting (exponential backoff)
                delay = min(self.reconnect_delay * (2 ** (attempt - 1)), 60)
                await asyncio.sleep(delay)

                # Attempt reconnection
                await self.connect()

                logger.info("✅ Database reconnection successful")
                return

            except Exception as e:
                logger.error(f"Reconnection attempt {attempt} failed: {str(e)}")
                attempt += 1

        # All reconnection attempts failed
        self.state = ConnectionState.FAILED
        logger.error("❌ All reconnection attempts failed")

    async def _wait_for_operations(self, timeout: float = 30.0) -> None:
        """Wait for active operations to complete"""
        start_time = time.time()

        while self._active_operations and (time.time() - start_time) < timeout:
            await asyncio.sleep(0.1)

        if self._active_operations:
            logger.warning(
                f"Timeout waiting for {len(self._active_operations)} operations to complete"
            )

    @asynccontextmanager
    async def get_database(self) -> AsyncGenerator[AsyncIOMotorDatabase, None]:
        """Get database instance with connection management"""
        if self.state != ConnectionState.CONNECTED:
            await self.connect()

        if not self.database:
            raise DatabaseException("Database not available")

        # Track operation
        operation_id = id(asyncio.current_task())
        self._active_operations.add(operation_id)

        try:
            yield self.database
        finally:
            self._active_operations.discard(operation_id)

    @asynccontextmanager
    async def get_collection(
        self, collection_name: str
    ) -> AsyncGenerator[AsyncIOMotorCollection, None]:
        """Get collection instance with connection management"""
        async with self.get_database() as db:
            yield db[collection_name]

    async def execute_with_retry(
        self, operation: Callable, *args, max_retries: int = 3, **kwargs
    ) -> Any:
        """Execute operation with automatic retry on connection errors"""
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                return await operation(*args, **kwargs)

            except (
                ConnectionFailure,
                ServerSelectionTimeoutError,
                NetworkTimeout,
                AutoReconnect,
            ) as e:
                last_exception = e

                if attempt < max_retries:
                    logger.warning(
                        f"Database operation failed (attempt {attempt + 1}), retrying: {str(e)}"
                    )
                    await asyncio.sleep(min(2**attempt, 10))  # Exponential backoff

                    # Try to reconnect if needed
                    if self.state != ConnectionState.CONNECTED:
                        await self._handle_connection_loss()
                else:
                    logger.error(
                        f"Database operation failed after {max_retries + 1} attempts: {str(e)}"
                    )

        raise DatabaseException(
            f"Operation failed after retries: {str(last_exception)}"
        )

    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status"""
        metrics = self.monitor.get_metrics()

        return {
            "state": self.state.value,
            "is_healthy": self.state == ConnectionState.CONNECTED,
            "database_name": self.database_name,
            "connection_pool": {
                "max_size": self.max_pool_size,
                "min_size": self.min_pool_size,
                "active_operations": len(self._active_operations),
            },
            "metrics": metrics,
            "uptime": (
                datetime.utcnow() - self.monitor.metrics.created_at
            ).total_seconds(),
        }


class DatabaseConnectionManager:
    """Centralized database connection management"""

    def __init__(self):
        self.settings = get_settings()
        self._pools: Dict[str, ConnectionPool] = {}
        self._default_pool: Optional[ConnectionPool] = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize database connections"""
        async with self._lock:
            if self._default_pool:
                return

            # Create default connection pool
            connection_string = self.settings.database.connection_url
            database_name = self.settings.database.database

            self._default_pool = ConnectionPool(
                connection_string=connection_string,
                database_name=database_name,
                max_pool_size=self.settings.database.max_connections,
                min_pool_size=self.settings.database.min_connections,
            )

            await self._default_pool.connect()

            # Register as default
            self._pools["default"] = self._default_pool

    async def shutdown(self) -> None:
        """Shutdown all database connections"""
        async with self._lock:
            for pool in self._pools.values():
                await pool.disconnect()

            self._pools.clear()
            self._default_pool = None

    async def get_pool(self, pool_name: str = "default") -> ConnectionPool:
        """Get connection pool by name"""
        if pool_name not in self._pools:
            if pool_name == "default":
                await self.initialize()
            else:
                raise DatabaseException(f"Connection pool '{pool_name}' not found")

        return self._pools[pool_name]

    async def create_pool(
        self, pool_name: str, connection_string: str, database_name: str, **kwargs
    ) -> ConnectionPool:
        """Create a new connection pool"""
        async with self._lock:
            if pool_name in self._pools:
                raise DatabaseException(f"Connection pool '{pool_name}' already exists")

            pool = ConnectionPool(connection_string, database_name, **kwargs)
            await pool.connect()

            self._pools[pool_name] = pool
            return pool

    async def remove_pool(self, pool_name: str) -> None:
        """Remove and disconnect a connection pool"""
        async with self._lock:
            if pool_name in self._pools:
                await self._pools[pool_name].disconnect()
                del self._pools[pool_name]

    async def get_database(
        self, pool_name: str = "default"
    ) -> AsyncGenerator[AsyncIOMotorDatabase, None]:
        """Get database instance from pool"""
        pool = await self.get_pool(pool_name)
        async with pool.get_database() as db:
            yield db

    async def get_collection(
        self, collection_name: str, pool_name: str = "default"
    ) -> AsyncGenerator[AsyncIOMotorCollection, None]:
        """Get collection instance from pool"""
        pool = await self.get_pool(pool_name)
        async with pool.get_collection(collection_name) as collection:
            yield collection

    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of all connection pools"""
        return {
            pool_name: pool.get_health_status()
            for pool_name, pool in self._pools.items()
        }


# Global connection manager instance
_connection_manager: Optional[DatabaseConnectionManager] = None


async def get_connection_manager() -> DatabaseConnectionManager:
    """Get global connection manager instance"""
    global _connection_manager
    if _connection_manager is None:
        _connection_manager = DatabaseConnectionManager()
        await _connection_manager.initialize()
    return _connection_manager


async def get_database(
    pool_name: str = "default",
) -> AsyncGenerator[AsyncIOMotorDatabase, None]:
    """Get database instance - convenience function"""
    manager = await get_connection_manager()
    async with manager.get_database(pool_name) as db:
        yield db


async def get_collection(
    collection_name: str, pool_name: str = "default"
) -> AsyncGenerator[AsyncIOMotorCollection, None]:
    """Get collection instance - convenience function"""
    manager = await get_connection_manager()
    async with manager.get_collection(collection_name, pool_name) as collection:
        yield collection


async def execute_with_retry(operation: Callable, *args, **kwargs) -> Any:
    """Execute database operation with retry - convenience function"""
    manager = await get_connection_manager()
    pool = await manager.get_pool("default")
    return await pool.execute_with_retry(operation, *args, **kwargs)


async def get_database_health() -> Dict[str, Any]:
    """Get database health status - convenience function"""
    try:
        manager = await get_connection_manager()
        return manager.get_health_status()
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


async def close_all_connections() -> None:
    """Close all database connections - convenience function"""
    global _connection_manager
    if _connection_manager:
        await _connection_manager.shutdown()
        _connection_manager = None


# Export all classes and functions
__all__ = [
    # Enums
    "ConnectionState",
    # Data Classes
    "ConnectionMetrics",
    # Core Classes
    "DatabaseMonitor",
    "ConnectionPool",
    "DatabaseConnectionManager",
    # Convenience Functions
    "get_connection_manager",
    "get_database",
    "get_collection",
    "execute_with_retry",
    "get_database_health",
    "close_all_connections",
]
