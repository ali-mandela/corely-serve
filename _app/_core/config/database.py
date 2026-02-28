"""
Enterprise Multi-Tenant Stores Management System - Database Configuration
This module handles MongoDB Atlas connection management and database operations.
"""

import asyncio
import logging
from typing import Optional, Dict, Any, AsyncGenerator
from contextlib import asynccontextmanager
from urllib.parse import quote_plus

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
)

from app._core.config.settings import get_settings
from app._core.utils.constants import DatabaseConstants
from app._core.utils.exceptions import DatabaseConnectionException, DatabaseException


logger = logging.getLogger(__name__)


class DatabaseManager:
    """Database connection and management for MongoDB Atlas"""

    def __init__(self):
        self.settings = get_settings()
        self.client: Optional[AsyncIOMotorClient] = None
        self.database: Optional[AsyncIOMotorDatabase] = None
        self._connection_lock = asyncio.Lock()
        self._is_connected = False

    async def connect(self) -> None:
        """Establish connection to MongoDB Atlas"""
        async with self._connection_lock:
            if self._is_connected and self.client:
                return

            try:
                logger.info("Connecting to MongoDB Atlas...")

                # Build connection URL
                connection_url = self._build_connection_url()

                # Create client with Atlas-optimized settings
                self.client = AsyncIOMotorClient(
                    connection_url,
                    maxPoolSize=self.settings.database.max_connections,
                    minPoolSize=self.settings.database.min_connections,
                    connectTimeoutMS=self.settings.database.connection_timeout * 1000,
                    serverSelectionTimeoutMS=30000,  # 30 seconds for Atlas
                    socketTimeoutMS=self.settings.database.query_timeout * 1000,
                    retryWrites=True,
                    retryReads=True,
                    maxIdleTimeMS=300000,  # 5 minutes
                    waitQueueTimeoutMS=10000,  # 10 seconds
                    # Atlas specific settings
                    ssl=True,
                    ssl_cert_reqs="CERT_NONE",  # Atlas handles SSL certificates
                    authSource="admin",
                    appName="StoresManagement",
                )

                # Get database instance
                self.database = self.client[self.settings.database.database]

                # Test connection
                await self._test_connection()

                self._is_connected = True
                logger.info("✅ Successfully connected to MongoDB Atlas")

            except Exception as e:
                logger.error(f"❌ Failed to connect to MongoDB Atlas: {str(e)}")
                await self.disconnect()
                raise DatabaseConnectionException(
                    self.settings.database.database
                ) from e

    def _build_connection_url(self) -> str:
        """Build MongoDB connection URL for Atlas"""
        db_settings = self.settings.database

        # Use Atlas connection string if provided
        if db_settings.atlas_connection_string:
            logger.info("Using MongoDB Atlas connection string")
            return db_settings.atlas_connection_string

        # Build connection URL manually (for local development)
        if not db_settings.username or not db_settings.password:
            raise ValueError(
                "Database username and password are required for Atlas connection"
            )

        # URL encode credentials
        username = quote_plus(db_settings.username)
        password = quote_plus(db_settings.password)

        # Build Atlas URL
        if db_settings.replica_set:
            # Atlas cluster format
            connection_url = (
                f"mongodb+srv://{username}:{password}@{db_settings.host}/"
                f"{db_settings.database}?retryWrites=true&w=majority"
            )
        else:
            # Standard MongoDB format
            connection_url = (
                f"mongodb://{username}:{password}@{db_settings.host}:"
                f"{db_settings.port}/{db_settings.database}?authSource=admin"
            )

        return connection_url

    async def _test_connection(self) -> None:
        """Test the database connection"""
        try:
            # Ping the database
            await self.client.admin.command("ping")

            # Test database access
            await self.database.command("ping")

            # Get server info for logging
            server_info = await self.client.server_info()
            logger.info(f"Connected to MongoDB {server_info.get('version', 'unknown')}")

        except Exception as e:
            logger.error(f"Database connection test failed: {str(e)}")
            raise

    async def disconnect(self) -> None:
        """Close database connection"""
        async with self._connection_lock:
            if self.client:
                logger.info("Disconnecting from MongoDB Atlas...")
                self.client.close()
                self.client = None
                self.database = None
                self._is_connected = False
                logger.info("✅ Disconnected from MongoDB Atlas")

    async def get_database(self) -> AsyncIOMotorDatabase:
        """Get database instance, connecting if necessary"""
        if not self._is_connected:
            await self.connect()
        return self.database

    async def get_collection(self, collection_name: str) -> AsyncIOMotorCollection:
        """Get collection instance"""
        database = await self.get_database()
        return database[collection_name]

    async def health_check(self) -> Dict[str, Any]:
        """Perform database health check"""
        try:
            if not self._is_connected or not self.client:
                return {"status": "disconnected", "error": "No database connection"}

            # Ping database
            start_time = asyncio.get_event_loop().time()
            await self.client.admin.command("ping")
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000

            # Get server status
            server_status = await self.client.admin.command("serverStatus")

            # Get database stats
            db_stats = await self.database.command("dbStats")

            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "server_version": server_status.get("version"),
                "database_size_mb": round(
                    db_stats.get("dataSize", 0) / (1024 * 1024), 2
                ),
                "collections_count": db_stats.get("collections", 0),
                "objects_count": db_stats.get("objects", 0),
                "uptime_seconds": server_status.get("uptime", 0),
                "connections": {
                    "current": server_status.get("connections", {}).get("current", 0),
                    "available": server_status.get("connections", {}).get(
                        "available", 0
                    ),
                },
            }

        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
            return {"status": "unhealthy", "error": str(e)}

    @property
    def is_connected(self) -> bool:
        """Check if database is connected"""
        return self._is_connected and self.client is not None


class TenantDatabaseManager:
    """Tenant-specific database operations"""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    async def get_tenant_collection(
        self, tenant_id: str, collection_name: str
    ) -> AsyncIOMotorCollection:
        """Get tenant-specific collection"""
        # For MongoDB, we use a single database with tenant_id prefixed collections
        # This is cost-effective for Atlas free tier
        prefixed_collection_name = f"{tenant_id}_{collection_name}"
        return await self.db_manager.get_collection(prefixed_collection_name)

    async def create_tenant_indexes(self, tenant_id: str) -> None:
        """Create necessary indexes for a new tenant"""
        try:
            logger.info(f"Creating indexes for tenant: {tenant_id}")

            # Core collections and their indexes
            collections_indexes = {
                "stores": [
                    ("tenant_id", 1),
                    ("store_code", 1),
                    ("status", 1),
                    [("tenant_id", 1), ("store_code", 1)],  # Compound index
                ],
                "employees": [
                    ("tenant_id", 1),
                    ("employee_id", 1),
                    ("email", 1),
                    ("mobile", 1),
                    ("status", 1),
                    [("tenant_id", 1), ("employee_id", 1)],  # Compound index
                ],
                "products": [
                    ("tenant_id", 1),
                    ("sku", 1),
                    ("barcode", 1),
                    ("category", 1),
                    ("status", 1),
                    [("tenant_id", 1), ("sku", 1)],  # Compound index
                ],
                "inventory": [
                    ("tenant_id", 1),
                    ("product_id", 1),
                    ("store_id", 1),
                    ("quantity", 1),
                    [
                        ("tenant_id", 1),
                        ("product_id", 1),
                        ("store_id", 1),
                    ],  # Compound index
                ],
                "customers": [
                    ("tenant_id", 1),
                    ("email", 1),
                    ("mobile", 1),
                    ("status", 1),
                    [("tenant_id", 1), ("email", 1)],  # Compound index
                ],
                "transactions": [
                    ("tenant_id", 1),
                    ("transaction_id", 1),
                    ("store_id", 1),
                    ("customer_id", 1),
                    ("created_at", -1),  # Descending for recent transactions
                    [
                        ("tenant_id", 1),
                        ("store_id", 1),
                        ("created_at", -1),
                    ],  # Compound index
                ],
            }

            # Create indexes for each collection
            for collection_name, indexes in collections_indexes.items():
                collection = await self.get_tenant_collection(
                    tenant_id, collection_name
                )

                for index in indexes:
                    try:
                        if isinstance(index, list):
                            # Compound index
                            await collection.create_index(index, background=True)
                        else:
                            # Single field index
                            await collection.create_index(index, background=True)
                    except OperationFailure as e:
                        # Index might already exist, log and continue
                        logger.warning(
                            f"Index creation failed for {collection_name}: {str(e)}"
                        )

            logger.info(f"✅ Indexes created for tenant: {tenant_id}")

        except Exception as e:
            logger.error(
                f"❌ Failed to create indexes for tenant {tenant_id}: {str(e)}"
            )
            raise DatabaseException(f"Failed to create tenant indexes: {str(e)}")

    async def drop_tenant_data(self, tenant_id: str) -> None:
        """Drop all data for a tenant (use with caution!)"""
        try:
            logger.warning(f"Dropping all data for tenant: {tenant_id}")

            # Get all collections for this tenant
            database = await self.db_manager.get_database()
            collection_names = await database.list_collection_names()

            tenant_collections = [
                name for name in collection_names if name.startswith(f"{tenant_id}_")
            ]

            # Drop each tenant collection
            for collection_name in tenant_collections:
                await database.drop_collection(collection_name)
                logger.info(f"Dropped collection: {collection_name}")

            logger.warning(f"✅ All data dropped for tenant: {tenant_id}")

        except Exception as e:
            logger.error(f"❌ Failed to drop tenant data for {tenant_id}: {str(e)}")
            raise DatabaseException(f"Failed to drop tenant data: {str(e)}")


class ConnectionPool:
    """Database connection pool management"""

    def __init__(self):
        self.db_manager = DatabaseManager()
        self.tenant_manager = TenantDatabaseManager(self.db_manager)

    async def startup(self) -> None:
        """Initialize database connections on startup"""
        try:
            await self.db_manager.connect()
            logger.info("🚀 Database connection pool initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize database: {str(e)}")
            raise

    async def shutdown(self) -> None:
        """Close database connections on shutdown"""
        try:
            await self.db_manager.disconnect()
            logger.info("🛑 Database connection pool closed")
        except Exception as e:
            logger.error(f"❌ Error during database shutdown: {str(e)}")

    @asynccontextmanager
    async def get_database(self) -> AsyncGenerator[AsyncIOMotorDatabase, None]:
        """Get database instance with automatic connection management"""
        try:
            database = await self.db_manager.get_database()
            yield database
        except Exception as e:
            logger.error(f"Database operation failed: {str(e)}")
            raise DatabaseException(f"Database operation failed: {str(e)}")

    @asynccontextmanager
    async def get_collection(
        self, collection_name: str
    ) -> AsyncGenerator[AsyncIOMotorCollection, None]:
        """Get collection instance with automatic connection management"""
        try:
            collection = await self.db_manager.get_collection(collection_name)
            yield collection
        except Exception as e:
            logger.error(f"Collection operation failed: {str(e)}")
            raise DatabaseException(f"Collection operation failed: {str(e)}")

    @asynccontextmanager
    async def get_tenant_collection(
        self, tenant_id: str, collection_name: str
    ) -> AsyncGenerator[AsyncIOMotorCollection, None]:
        """Get tenant-specific collection with automatic connection management"""
        try:
            collection = await self.tenant_manager.get_tenant_collection(
                tenant_id, collection_name
            )
            yield collection
        except Exception as e:
            logger.error(f"Tenant collection operation failed: {str(e)}")
            raise DatabaseException(f"Tenant collection operation failed: {str(e)}")


# Global connection pool instance
_connection_pool: Optional[ConnectionPool] = None


async def get_connection_pool() -> ConnectionPool:
    """Get the global connection pool instance"""
    global _connection_pool
    if _connection_pool is None:
        _connection_pool = ConnectionPool()
        await _connection_pool.startup()
    return _connection_pool


async def get_database() -> AsyncIOMotorDatabase:
    """Get database instance - convenience function"""
    pool = await get_connection_pool()
    return await pool.db_manager.get_database()


async def get_collection(collection_name: str) -> AsyncIOMotorCollection:
    """Get collection instance - convenience function"""
    pool = await get_connection_pool()
    return await pool.db_manager.get_collection(collection_name)


async def get_tenant_collection(
    tenant_id: str, collection_name: str
) -> AsyncIOMotorCollection:
    """Get tenant-specific collection - convenience function"""
    pool = await get_connection_pool()
    return await pool.tenant_manager.get_tenant_collection(tenant_id, collection_name)


async def create_tenant_indexes(tenant_id: str) -> None:
    """Create indexes for a new tenant - convenience function"""
    pool = await get_connection_pool()
    await pool.tenant_manager.create_tenant_indexes(tenant_id)


async def database_health_check() -> Dict[str, Any]:
    """Perform database health check - convenience function"""
    try:
        pool = await get_connection_pool()
        return await pool.db_manager.health_check()
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def close_database_connections() -> None:
    """Close all database connections - convenience function"""
    global _connection_pool
    if _connection_pool:
        await _connection_pool.shutdown()
        _connection_pool = None


# Database utility functions
async def ensure_indexes() -> None:
    """Ensure all necessary indexes are created"""
    try:
        logger.info("Ensuring database indexes...")

        # Core system collections (non-tenant specific)
        database = await get_database()

        # Tenants collection
        tenants_collection = database[DatabaseConstants.TENANTS]
        await tenants_collection.create_index("subdomain", unique=True, background=True)
        await tenants_collection.create_index("status", background=True)
        await tenants_collection.create_index("created_at", background=True)

        # Users collection
        users_collection = database[DatabaseConstants.USERS]
        await users_collection.create_index("email", unique=True, background=True)
        await users_collection.create_index(
            [("tenant_id", 1), ("email", 1)], background=True
        )
        await users_collection.create_index("tenant_id", background=True)
        await users_collection.create_index("role", background=True)
        await users_collection.create_index("status", background=True)

        # User sessions collection
        sessions_collection = database[DatabaseConstants.USER_SESSIONS]
        await sessions_collection.create_index("user_id", background=True)
        await sessions_collection.create_index(
            "session_token", unique=True, background=True
        )
        await sessions_collection.create_index(
            "expires_at", expireAfterSeconds=0, background=True
        )  # TTL index

        # Audit logs collection
        audit_collection = database[DatabaseConstants.AUDIT_LOGS]
        await audit_collection.create_index(
            [("tenant_id", 1), ("created_at", -1)], background=True
        )
        await audit_collection.create_index("user_id", background=True)
        await audit_collection.create_index("action", background=True)
        await audit_collection.create_index(
            "created_at", expireAfterSeconds=7776000, background=True
        )  # 90 days TTL

        logger.info("✅ Database indexes ensured")

    except Exception as e:
        logger.error(f"❌ Failed to ensure indexes: {str(e)}")
        raise DatabaseException(f"Failed to ensure indexes: {str(e)}")


# Export all functions and classes
__all__ = [
    "DatabaseManager",
    "TenantDatabaseManager",
    "ConnectionPool",
    "get_connection_pool",
    "get_database",
    "get_collection",
    "get_tenant_collection",
    "create_tenant_indexes",
    "database_health_check",
    "close_database_connections",
    "ensure_indexes",
]
